// Package dnstest runs a tiny authoritative-style DNS server on the
// loopback interface for tests. It lets the real miekg/dns-backed resolver
// and the CLI be exercised end to end without touching public DNS.
package dnstest

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// Server answers from a fixed set of records for a single zone.
type Server struct {
	// Addr is the "127.0.0.1:port" address, serving both UDP and TCP.
	Addr        string
	truncateUDP atomic.Bool

	mu      sync.Mutex
	records []dns.RR
	soa     *dns.SOA
	queries []string // "udp A example.test." etc.
}

// Start parses zone-file style records ("example.test. 300 IN A 192.0.2.1")
// and serves them until the test ends. Exactly one SOA record must be given;
// its owner is the zone apex.
func Start(t testing.TB, records ...string) *Server {
	t.Helper()
	s := &Server{}
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil {
			t.Fatalf("dnstest: bad record %q: %v", r, err)
		}
		if soa, ok := rr.(*dns.SOA); ok {
			s.soa = soa
		}
		s.records = append(s.records, rr)
	}
	if s.soa == nil {
		t.Fatal("dnstest: a SOA record is required")
	}

	var pc net.PacketConn
	var ln net.Listener
	for attempt := 0; attempt < 20; attempt++ {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("dnstest: %v", err)
		}
		l, err := net.Listen("tcp", p.LocalAddr().String())
		if err != nil {
			p.Close() // TCP port taken; try another
			continue
		}
		pc, ln = p, l
		break
	}
	if pc == nil {
		t.Fatal("dnstest: could not bind matching UDP and TCP ports")
	}
	s.Addr = pc.LocalAddr().String()

	udp := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.handle)}
	tcp := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(s.handle)}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() {
		udp.Shutdown()
		tcp.Shutdown()
	})
	return s
}

// SetRecords replaces the served records (keeping the same SOA unless a new
// one is supplied), to simulate a DNS change between two queries.
func (s *Server) SetRecords(t testing.TB, records ...string) {
	t.Helper()
	var rrs []dns.RR
	soa := s.soa
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil {
			t.Fatalf("dnstest: bad record %q: %v", r, err)
		}
		if x, ok := rr.(*dns.SOA); ok {
			soa = x
		}
		rrs = append(rrs, rr)
	}
	s.mu.Lock()
	s.records, s.soa = rrs, soa
	s.mu.Unlock()
}

// SetTruncateUDP makes every UDP reply empty with the TC bit set, so a
// client must retry over TCP to get the answer.
func (s *Server) SetTruncateUDP(on bool) { s.truncateUDP.Store(on) }

// Queries returns the queries seen so far, as "proto TYPE name".
func (s *Server) Queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	proto := "tcp"
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		proto = "udp"
	}

	s.mu.Lock()
	s.queries = append(s.queries, proto+" "+dns.TypeToString[q.Qtype]+" "+q.Name)
	records, soa := s.records, s.soa
	s.mu.Unlock()

	if proto == "udp" && s.truncateUDP.Load() {
		m.Truncated = true
		w.WriteMsg(m)
		return
	}

	name := strings.ToLower(q.Name)
	ownerExists := false
	for _, rr := range records {
		if strings.ToLower(rr.Header().Name) != name {
			continue
		}
		ownerExists = true
		if rr.Header().Rrtype == q.Qtype {
			m.Answer = append(m.Answer, dns.Copy(rr))
		}
	}
	// Follow one CNAME, as a recursive resolver would.
	if len(m.Answer) == 0 && q.Qtype != dns.TypeCNAME {
		for _, rr := range records {
			if c, ok := rr.(*dns.CNAME); ok && strings.ToLower(c.Hdr.Name) == name {
				m.Answer = append(m.Answer, dns.Copy(c))
				for _, t := range records {
					if strings.EqualFold(t.Header().Name, c.Target) && t.Header().Rrtype == q.Qtype {
						m.Answer = append(m.Answer, dns.Copy(t))
					}
				}
			}
		}
	}
	if len(m.Answer) == 0 {
		if !ownerExists && !dns.IsSubDomain(soa.Hdr.Name, name) {
			m.Rcode = dns.RcodeRefused
		} else if !ownerExists {
			m.Rcode = dns.RcodeNameError
		}
		m.Ns = append(m.Ns, dns.Copy(soa))
	}
	w.WriteMsg(m)
}
