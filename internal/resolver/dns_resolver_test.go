package resolver_test

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hellpuffyt/dnsdrift/internal/dnstest"
	"github.com/hellpuffyt/dnsdrift/internal/resolver"
)

// These tests run the real miekg/dns-backed DNSResolver against a DNS
// server on 127.0.0.1 (internal/dnstest). No public DNS is involved.

var zone = []string{
	"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2024010101 7200 900 1209600 300",
	"example.test. 3600 IN NS ns1.example.test.",
	"example.test. 3600 IN NS ns2.example.test.",
	"example.test. 300 IN A 192.0.2.10",
	"example.test. 120 IN A 192.0.2.11",
	"example.test. 300 IN AAAA 2001:db8::10",
	"example.test. 300 IN MX 10 mail.example.test.",
	"example.test. 300 IN TXT \"v=spf1 -all\"",
	"www.example.test. 600 IN CNAME example.test.",
	"api.example.test. 300 IN A 192.0.2.20",
}

func TestDNSResolverParsesEveryRecordType(t *testing.T) {
	srv := dnstest.Start(t, zone...)
	r := resolver.NewDNSResolver("Local", srv.Addr, 2*time.Second)
	cases := map[resolver.RecordType][]string{
		resolver.TypeA:     {"192.0.2.10", "192.0.2.11"},
		resolver.TypeAAAA:  {"2001:db8::10"},
		resolver.TypeMX:    {"10 mail.example.test"},
		resolver.TypeTXT:   {"v=spf1 -all"},
		resolver.TypeNS:    {"ns1.example.test", "ns2.example.test"},
		resolver.TypeSOA:   {"ns1.example.test hostmaster.example.test 2024010101"},
		resolver.TypeCNAME: nil,
	}
	for rt, want := range cases {
		ans, err := r.Query(context.Background(), "example.test", rt)
		if err != nil || ans.Err != "" {
			t.Fatalf("%s: %v %q", rt, err, ans.Err)
		}
		if !reflect.DeepEqual(ans.Records, want) {
			t.Errorf("%s: records %q, want %q", rt, ans.Records, want)
		}
	}
	a, _ := r.Query(context.Background(), "example.test", resolver.TypeA)
	if a.TTL != 120 {
		t.Errorf("TTL should be the minimum across the RRset, got %d", a.TTL)
	}
	soa, _ := r.Query(context.Background(), "EXAMPLE.test.", resolver.TypeSOA)
	if soa.SOA == nil || soa.SOA.Serial != 2024010101 || soa.SOA.Zone != "example.test" {
		t.Errorf("SOA: %+v", soa.SOA)
	}
	c, _ := r.Query(context.Background(), "www.example.test", resolver.TypeCNAME)
	if !reflect.DeepEqual(c.Records, []string{"example.test"}) {
		t.Errorf("CNAME: %q", c.Records)
	}
}

// For a name below the apex the SOA comes back in the authority section;
// it still identifies the zone and its serial.
func TestDNSResolverTakesSOAFromAuthoritySection(t *testing.T) {
	srv := dnstest.Start(t, zone...)
	r := resolver.NewDNSResolver("Local", srv.Addr, 2*time.Second)
	ans, err := r.Query(context.Background(), "api.example.test", resolver.TypeSOA)
	if err != nil || ans.Err != "" {
		t.Fatalf("%v %q", err, ans.Err)
	}
	if len(ans.Records) != 0 {
		t.Fatalf("no SOA records exist at api, got %q", ans.Records)
	}
	if ans.SOA == nil || ans.SOA.Zone != "example.test" || ans.SOA.Serial != 2024010101 {
		t.Fatalf("authority SOA not captured: %+v", ans.SOA)
	}
}

func TestDNSResolverReportsRcodeAndRetriesTruncatedOverTCP(t *testing.T) {
	srv := dnstest.Start(t, zone...)
	r := resolver.NewDNSResolver("Local", srv.Addr, 2*time.Second)
	ans, err := r.Query(context.Background(), "missing.example.test", resolver.TypeA)
	if err != nil || ans.Err != "rcode NXDOMAIN" {
		t.Fatalf("NXDOMAIN: %v %+v", err, ans)
	}

	srv.SetTruncateUDP(true)
	ans, err = r.Query(context.Background(), "example.test", resolver.TypeA)
	if err != nil || ans.Err != "" || len(ans.Records) != 2 {
		t.Fatalf("truncated answer not retried over TCP: %v %+v", err, ans)
	}
	q := strings.Join(srv.Queries(), ",")
	if !strings.Contains(q, "udp A example.test.") || !strings.Contains(q, "tcp A example.test.") {
		t.Fatalf("expected a UDP then a TCP query, saw %s", q)
	}
}

func TestDNSResolverTimesOut(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	r := resolver.NewDNSResolver("Silent", pc.LocalAddr().String(), 300*time.Millisecond)
	start := time.Now()
	ans, err := r.Query(context.Background(), "example.test", resolver.TypeA)
	if err != nil || ans.Err == "" {
		t.Fatalf("expected an error answer, got %v %+v", err, ans)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout not enforced: %v", time.Since(start))
	}
}
