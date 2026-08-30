package resolver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSResolver is a Resolver backed by a real UDP/TCP DNS server, using
// github.com/miekg/dns. We use miekg/dns rather than the stdlib net package
// because dnsdrift's core feature -- distinguishing propagation lag from
// genuine misconfiguration -- depends on the raw TTL and SOA serial of each
// answer. The stdlib net package's LookupXxx helpers hide both: they return
// only resolved values with no TTL/serial access and go through the OS
// resolver rather than a chosen upstream server. miekg/dns lets dnsdrift
// query a specific resolver directly and read the wire-level TTL and SOA
// fields it needs.
type DNSResolver struct {
	name    string
	addr    string
	client  *dns.Client
	timeout time.Duration
}

// NewDNSResolver builds a resolver that queries addr (host:port, e.g.
// "8.8.8.8:53") over UDP with automatic TCP retry on truncation.
func NewDNSResolver(name, addr string, timeout time.Duration) *DNSResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &DNSResolver{
		name: name,
		addr: addr,
		client: &dns.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

func (r *DNSResolver) Name() string    { return r.name }
func (r *DNSResolver) Address() string { return r.addr }

var qtypeOf = map[RecordType]uint16{
	TypeA:     dns.TypeA,
	TypeAAAA:  dns.TypeAAAA,
	TypeCNAME: dns.TypeCNAME,
	TypeMX:    dns.TypeMX,
	TypeTXT:   dns.TypeTXT,
	TypeNS:    dns.TypeNS,
	TypeSOA:   dns.TypeSOA,
}

// Query implements Resolver.
func (r *DNSResolver) Query(ctx context.Context, name string, rtype RecordType) (Answer, error) {
	qtype, ok := qtypeOf[rtype]
	if !ok {
		return Answer{RecordType: rtype, Err: fmt.Sprintf("unsupported record type %q", rtype)}, nil
	}

	fqdn := dns.Fqdn(name)
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true

	resp, _, err := r.exchangeWithContext(ctx, msg)
	if err != nil {
		return Answer{RecordType: rtype, Err: err.Error()}, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return Answer{RecordType: rtype, Err: fmt.Sprintf("rcode %s", dns.RcodeToString[resp.Rcode])}, nil
	}

	answer := Answer{RecordType: rtype}
	var minTTL uint32
	first := true
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		val := recordValue(rr)
		if val == "" {
			continue
		}
		answer.Records = append(answer.Records, val)
		ttl := rr.Header().Ttl
		if first || ttl < minTTL {
			minTTL = ttl
			first = false
		}
		if rtype == TypeSOA {
			if soaRR, ok := rr.(*dns.SOA); ok {
				answer.SOA = &SOA{
					Zone:    strings.TrimSuffix(soaRR.Header().Name, "."),
					MName:   soaRR.Ns,
					RName:   soaRR.Mbox,
					Serial:  soaRR.Serial,
					Refresh: soaRR.Refresh,
					Retry:   soaRR.Retry,
					Expire:  soaRR.Expire,
					Minimum: soaRR.Minttl,
				}
			}
		}
	}
	answer.TTL = minTTL
	answer.Records = NormalizeRecords(answer.Records)
	return answer, nil
}

func (r *DNSResolver) exchangeWithContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	type result struct {
		resp *dns.Msg
		rtt  time.Duration
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, rtt, err := r.client.Exchange(msg, r.addr)
		if err == nil && resp != nil && resp.Truncated {
			tcpClient := &dns.Client{Net: "tcp", Timeout: r.timeout}
			resp, rtt, err = tcpClient.Exchange(msg, r.addr)
		}
		ch <- result{resp, rtt, err}
	}()
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case res := <-ch:
		return res.resp, res.rtt, res.err
	}
}

// recordValue renders an RR's data (not its owner/TTL/class) as a normalized
// comparable string.
func recordValue(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."), v.Serial)
	default:
		return ""
	}
}
