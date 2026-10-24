package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/hellpuffyt/dnsdrift/internal/analysis"
	"github.com/hellpuffyt/dnsdrift/internal/query"
	"github.com/hellpuffyt/dnsdrift/internal/resolver"
)

func TestNormalizeName(t *testing.T) {
	cases := map[string]string{
		"Example.com.":  "example.com",
		"  EXAMPLE.COM": "example.com",
		"example.com":   "example.com",
	}
	for in, want := range cases {
		if got := normalizeName(in); got != want {
			t.Errorf("normalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTypesDefault(t *testing.T) {
	got, err := parseTypes("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, resolver.AllTypes) {
		t.Errorf("got %v, want %v", got, resolver.AllTypes)
	}
}

func TestParseTypesExplicit(t *testing.T) {
	got, err := parseTypes("a, mx , TXT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []resolver.RecordType{resolver.TypeA, resolver.TypeMX, resolver.TypeTXT}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTypesInvalid(t *testing.T) {
	if _, err := parseTypes("bogus"); err == nil {
		t.Fatalf("expected error for invalid type")
	}
}

func TestParseExtraResolversEmpty(t *testing.T) {
	got, err := parseExtraResolvers("", time.Second)
	if err != nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestParseExtraResolversValid(t *testing.T) {
	got, err := parseExtraResolvers("Home=192.168.1.1,ISP=10.0.0.1:53", time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 resolvers, got %d", len(got))
	}
	if got[0].Name() != "Home" || got[0].Address() != "192.168.1.1:53" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Address() != "10.0.0.1:53" {
		t.Errorf("got[1] address = %q, want default-port left alone", got[1].Address())
	}
}

func TestParseExtraResolversInvalid(t *testing.T) {
	if _, err := parseExtraResolvers("garbage", time.Second); err == nil {
		t.Fatalf("expected error for malformed resolver entry")
	}
	if _, err := parseExtraResolvers("Name=", time.Second); err == nil {
		t.Fatalf("expected error for missing address")
	}
}

func TestBuildPanelIncludesWellKnownByDefault(t *testing.T) {
	panel := buildPanel(nil, false, time.Second)
	if len(panel) != len(resolver.WellKnown) {
		t.Fatalf("got %d resolvers, want %d", len(panel), len(resolver.WellKnown))
	}
}

func TestBuildPanelOnlyExtra(t *testing.T) {
	extra := []resolver.Resolver{resolver.NewFakeResolver("Custom", "1.2.3.4:53")}
	panel := buildPanel(extra, true, time.Second)
	if len(panel) != 1 || panel[0].Name() != "Custom" {
		t.Fatalf("got %+v", panel)
	}
}

func TestBuildPanelWellKnownPlusExtra(t *testing.T) {
	extra := []resolver.Resolver{resolver.NewFakeResolver("Custom", "1.2.3.4:53")}
	panel := buildPanel(extra, false, time.Second)
	if len(panel) != len(resolver.WellKnown)+1 {
		t.Fatalf("got %d resolvers", len(panel))
	}
}

func TestMajorityRecords(t *testing.T) {
	r := analysis.Report{Groups: []analysis.Group{
		{Records: []string{"1.1.1.1"}, IsMajority: false},
		{Records: []string{"2.2.2.2"}, IsMajority: true},
	}}
	if got := majorityRecords(r); !reflect.DeepEqual(got, []string{"2.2.2.2"}) {
		t.Errorf("got %v", got)
	}
}

func TestMajorityRecordsNoMajority(t *testing.T) {
	r := analysis.Report{}
	if got := majorityRecords(r); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestMajoritySOAZone(t *testing.T) {
	answers := []analysis.ResolverAnswer{
		{Resolver: "Google", Answer: resolver.Answer{SOA: &resolver.SOA{Zone: "example.com"}}},
		{Resolver: "Cloudflare", Answer: resolver.Answer{SOA: &resolver.SOA{Zone: "example.com"}}},
		{Resolver: "Quad9", Answer: resolver.Answer{Err: "timeout"}},
	}
	if got := majoritySOAZone(answers); got != "example.com" {
		t.Errorf("got %q", got)
	}
}

func TestBuildHealthInputDetectsApexAndCNAME(t *testing.T) {
	res := query.Result{
		ByType: map[resolver.RecordType][]analysis.ResolverAnswer{
			resolver.TypeCNAME: {{Resolver: "Google", Answer: resolver.Answer{Records: []string{"target.example.net"}}}},
			resolver.TypeSOA:   {{Resolver: "Google", Answer: resolver.Answer{SOA: &resolver.SOA{Zone: "example.com"}}}},
		},
		SOAByResolver: map[string]uint32{"Google": 100},
	}
	reports := map[resolver.RecordType]analysis.Report{
		resolver.TypeCNAME: {Groups: []analysis.Group{{Records: []string{"target.example.net"}, IsMajority: true}}},
	}
	in := buildHealthInput("example.com", res, reports, true)
	if !in.IsApex {
		t.Errorf("expected apex detection to match SOA zone")
	}
	if !in.HasCNAME || in.CNAMETarget != "target.example.net" || !in.CNAMETargetResolves {
		t.Errorf("got %+v", in)
	}
}

func TestBuildHealthInputNoCNAME(t *testing.T) {
	res := query.Result{ByType: map[resolver.RecordType][]analysis.ResolverAnswer{}}
	reports := map[resolver.RecordType]analysis.Report{}
	in := buildHealthInput("example.com", res, reports, false)
	if in.HasCNAME {
		t.Errorf("expected HasCNAME false, got %+v", in)
	}
}

func TestBuildSnapshotSkipsErroredResolvers(t *testing.T) {
	res := query.Result{
		ByType: map[resolver.RecordType][]analysis.ResolverAnswer{
			resolver.TypeA: {
				{Resolver: "Google", Answer: resolver.Answer{Records: []string{"1.2.3.4"}, TTL: 300}},
				{Resolver: "Quad9", Answer: resolver.Answer{Err: "timeout"}},
			},
		},
	}
	snap := buildSnapshot("example.com", res, time.Now())
	if len(snap.Records) != 1 || snap.Records[0].Resolver != "Google" {
		t.Fatalf("got %+v", snap.Records)
	}
}

// Replaces TestFirstTTLSkipsErrors: the TTL check now uses the largest
// observed TTL (closest to the configured value) instead of whichever
// resolver came first, whose cache may be about to expire.
func TestObservedTTLSkipsErrorsAndTakesMax(t *testing.T) {
	answers := []analysis.ResolverAnswer{
		{Resolver: "Google", Answer: resolver.Answer{Err: "timeout"}},
		{Resolver: "Cloudflare", Answer: resolver.Answer{TTL: 3}},
		{Resolver: "Quad9", Answer: resolver.Answer{TTL: 287}},
	}
	if got := observedTTL(answers); got != 287 {
		t.Errorf("got %d, want 287", got)
	}
}

// Regression: with no SOA zone information the queried name was assumed to
// be the apex, so any CNAME'd subdomain got a "cname-at-apex" error.
func TestBuildHealthInputSubdomainIsNotApex(t *testing.T) {
	cname := map[resolver.RecordType]analysis.Report{
		resolver.TypeCNAME: {Groups: []analysis.Group{{Records: []string{"lb.example.net"}, IsMajority: true}}},
	}
	res := query.Result{
		ByType:            map[resolver.RecordType][]analysis.ResolverAnswer{},
		SOAZoneByResolver: map[string]string{"Google": "example.com", "Quad9": "example.com"},
	}
	if in := buildHealthInput("www.example.com", res, cname, true); in.IsApex {
		t.Fatalf("www.example.com treated as apex of example.com")
	}
	if in := buildHealthInput("example.com", res, cname, true); !in.IsApex {
		t.Fatalf("apex not detected from companion SOA zones")
	}
	res.SOAZoneByResolver = nil
	if in := buildHealthInput("www.example.com", res, cname, true); in.IsApex {
		t.Fatalf("unknown zone must not be treated as apex")
	}
}

func TestParseExtraResolversIPv6AndPorts(t *testing.T) {
	rs, err := parseExtraResolvers("A=::1,B=[2001:db8::53]:5353,C=192.0.2.53,D=dns.example", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"[::1]:53", "[2001:db8::53]:5353", "192.0.2.53:53", "dns.example:53"}
	for i, r := range rs {
		if r.Address() != want[i] {
			t.Errorf("%s: address %q, want %q", r.Name(), r.Address(), want[i])
		}
	}
}

// Regression: "no-ns-records" (an error) was reported whenever NS was not in
// --types, and for every name below the apex.
func TestBuildHealthInputSkipsNSCheckWhenNotApplicable(t *testing.T) {
	ns := analysis.Report{Groups: []analysis.Group{{Records: []string{"ns1.example.com", "ns2.example.com"}, IsMajority: true}}}
	res := query.Result{ByType: map[resolver.RecordType][]analysis.ResolverAnswer{}, SOAZoneByResolver: map[string]string{"G": "example.com"}}
	if in := buildHealthInput("example.com", res, map[resolver.RecordType]analysis.Report{}, false); !in.SkipNS {
		t.Errorf("NS not queried: check must be skipped")
	}
	if in := buildHealthInput("www.example.com", res, map[resolver.RecordType]analysis.Report{resolver.TypeNS: {}}, false); !in.SkipNS {
		t.Errorf("below the apex: check must be skipped")
	}
	if in := buildHealthInput("example.com", res, map[resolver.RecordType]analysis.Report{resolver.TypeNS: ns}, false); in.SkipNS {
		t.Errorf("apex with NS queried: check must run")
	}
}
