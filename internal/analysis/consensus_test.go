package analysis

import (
	"testing"

	"github.com/prabeshsharma/dnsdrift/internal/resolver"
)

func ans(records ...string) resolver.Answer {
	return resolver.Answer{Records: resolver.NormalizeRecords(append([]string(nil), records...))}
}

func ansTTL(ttl uint32, records ...string) resolver.Answer {
	a := ans(records...)
	a.TTL = ttl
	return a
}

func errAns(msg string) resolver.Answer {
	return resolver.Answer{Err: msg}
}

func TestAnalyzeAllResolversAgree(t *testing.T) {
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ans("1.2.3.4")},
		{Resolver: "Cloudflare", Answer: ans("1.2.3.4")},
		{Resolver: "Quad9", Answer: ans("1.2.3.4")},
	}
	r := Analyze("example.com", resolver.TypeA, answers, nil)
	if !r.Agree {
		t.Fatalf("expected agreement, got groups=%v errored=%v", r.Groups, r.Errored)
	}
	if len(r.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(r.Groups))
	}
	if !r.Groups[0].IsMajority {
		t.Errorf("sole group should be majority")
	}
	if len(r.Verdicts) != 0 {
		t.Errorf("expected no verdicts when everyone agrees, got %v", r.Verdicts)
	}
}

func TestAnalyzeGenuineSplitNoSOAData(t *testing.T) {
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ans("1.2.3.4")},
		{Resolver: "Cloudflare", Answer: ans("1.2.3.4")},
		{Resolver: "Quad9", Answer: ans("5.6.7.8")},
	}
	r := Analyze("example.com", resolver.TypeA, answers, nil)
	if r.Agree {
		t.Fatalf("expected disagreement")
	}
	if len(r.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(r.Groups))
	}
	if r.HasSOAData {
		t.Errorf("expected no SOA data")
	}
	if len(r.Verdicts) != 1 || r.Verdicts[0].Resolver != "Quad9" || r.Verdicts[0].Verdict != VerdictUnknown {
		t.Fatalf("expected Quad9 to be VerdictUnknown, got %+v", r.Verdicts)
	}
}

func TestAnalyzePropagationInProgress(t *testing.T) {
	// Quad9 is behind on the SOA serial and its TTL hasn't expired yet:
	// this is ordinary propagation lag.
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Cloudflare", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Quad9", Answer: ansTTL(120, "1.2.3.4")},
	}
	soa := map[string]uint32{"Google": 2024010200, "Cloudflare": 2024010200, "Quad9": 2024010100}
	r := Analyze("example.com", resolver.TypeA, answers, soa)
	if r.Agree {
		t.Fatalf("expected disagreement")
	}
	if r.MaxSOASerial != 2024010200 {
		t.Errorf("MaxSOASerial = %d, want 2024010200", r.MaxSOASerial)
	}
	found := findVerdict(t, r.Verdicts, "Quad9")
	if found.Verdict != VerdictPropagating {
		t.Errorf("Quad9 verdict = %s, want propagating; reason=%q", found.Verdict, found.Reason)
	}
}

func TestAnalyzeTrueMisconfigurationExpiredTTL(t *testing.T) {
	// Quad9 is behind on serial AND its TTL has already expired (0):
	// it should have refreshed by now but hasn't. Genuine fault.
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Cloudflare", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Quad9", Answer: ansTTL(0, "1.2.3.4")},
	}
	soa := map[string]uint32{"Google": 2024010200, "Cloudflare": 2024010200, "Quad9": 2024010100}
	r := Analyze("example.com", resolver.TypeA, answers, soa)
	found := findVerdict(t, r.Verdicts, "Quad9")
	if found.Verdict != VerdictMisconfigured {
		t.Errorf("Quad9 verdict = %s, want misconfigured; reason=%q", found.Verdict, found.Reason)
	}
}

func TestAnalyzeTrueMisconfigurationCurrentSerial(t *testing.T) {
	// Quad9 reports the SAME (current) serial as the majority yet still
	// disagrees -- not explainable by lag at all.
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Cloudflare", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Quad9", Answer: ansTTL(300, "1.2.3.4")},
	}
	soa := map[string]uint32{"Google": 2024010200, "Cloudflare": 2024010200, "Quad9": 2024010200}
	r := Analyze("example.com", resolver.TypeA, answers, soa)
	found := findVerdict(t, r.Verdicts, "Quad9")
	if found.Verdict != VerdictMisconfigured {
		t.Errorf("Quad9 verdict = %s, want misconfigured; reason=%q", found.Verdict, found.Reason)
	}
}

func TestAnalyzeFalsePositiveGuardMajorityNeverGetsVerdict(t *testing.T) {
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Cloudflare", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Quad9", Answer: ansTTL(300, "1.2.3.4")},
	}
	soa := map[string]uint32{"Google": 100, "Cloudflare": 100, "Quad9": 50}
	r := Analyze("example.com", resolver.TypeA, answers, soa)
	for _, v := range r.Verdicts {
		if v.Resolver == "Google" || v.Resolver == "Cloudflare" {
			t.Errorf("majority resolver %s should never receive a verdict, got %+v", v.Resolver, v)
		}
	}
}

func TestAnalyzeAheadResolverIsNotFlaggedAsBehind(t *testing.T) {
	// A resolver reporting a HIGHER serial than the rest is not "behind",
	// so it must not be classified as propagating; it's a disagreement
	// with the current serial, i.e. misconfigured.
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Cloudflare", Answer: ansTTL(300, "5.6.7.8")},
		{Resolver: "Quad9", Answer: ansTTL(300, "1.2.3.4")},
	}
	soa := map[string]uint32{"Google": 100, "Cloudflare": 100, "Quad9": 200}
	r := Analyze("example.com", resolver.TypeA, answers, soa)
	found := findVerdict(t, r.Verdicts, "Quad9")
	if found.Verdict != VerdictMisconfigured {
		t.Errorf("resolver ahead on serial but disagreeing should be misconfigured, got %s", found.Verdict)
	}
}

func TestAnalyzeErroredResolversReportedSeparately(t *testing.T) {
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ans("1.2.3.4")},
		{Resolver: "Cloudflare", Answer: ans("1.2.3.4")},
		{Resolver: "Quad9", Answer: errAns("timeout")},
	}
	r := Analyze("example.com", resolver.TypeA, answers, nil)
	if !r.Agree {
		// Errors alone (with the rest agreeing) still count as
		// disagreement for CI purposes.
	}
	if len(r.Errored) != 1 || r.Errored[0] != "Quad9" {
		t.Fatalf("expected Quad9 in Errored, got %v", r.Errored)
	}
	found := findVerdict(t, r.Verdicts, "Quad9")
	if found.Verdict != VerdictError {
		t.Errorf("errored resolver verdict = %s, want error", found.Verdict)
	}
}

func TestAnalyzeAllErroredIsNotAgreement(t *testing.T) {
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: errAns("timeout")},
		{Resolver: "Cloudflare", Answer: errAns("servfail")},
	}
	r := Analyze("example.com", resolver.TypeA, answers, nil)
	if r.Agree {
		t.Errorf("all resolvers erroring must not be reported as agreement")
	}
	if len(r.Groups) != 0 {
		t.Errorf("expected no answer groups, got %v", r.Groups)
	}
}

func TestAnalyzeThreeWaySplitMajorityIsLargestGroup(t *testing.T) {
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ans("1.1.1.1")},
		{Resolver: "Cloudflare", Answer: ans("1.1.1.1")},
		{Resolver: "Quad9", Answer: ans("1.1.1.1")},
		{Resolver: "OpenDNS", Answer: ans("2.2.2.2")},
		{Resolver: "Extra", Answer: ans("3.3.3.3")},
	}
	r := Analyze("example.com", resolver.TypeA, answers, nil)
	var majority *Group
	for i := range r.Groups {
		if r.Groups[i].IsMajority {
			majority = &r.Groups[i]
		}
	}
	if majority == nil {
		t.Fatalf("no majority group found")
	}
	if len(majority.Resolvers) != 3 {
		t.Errorf("majority group size = %d, want 3", len(majority.Resolvers))
	}
	if majority.Records[0] != "1.1.1.1" {
		t.Errorf("majority records = %v", majority.Records)
	}
}

func TestAnalyzeEmptyInput(t *testing.T) {
	r := Analyze("example.com", resolver.TypeA, nil, nil)
	if r.Agree {
		t.Errorf("empty input should not report agreement")
	}
	if len(r.Groups) != 0 || len(r.Errored) != 0 {
		t.Errorf("expected no groups or errors, got %+v", r)
	}
}

func TestAnalyzeUnknownVerdictWhenSOAMissingForOneResolver(t *testing.T) {
	answers := []ResolverAnswer{
		{Resolver: "Google", Answer: ans("1.2.3.4")},
		{Resolver: "Cloudflare", Answer: ans("1.2.3.4")},
		{Resolver: "Quad9", Answer: ans("5.6.7.8")},
	}
	// SOA data exists for the panel overall, but not for Quad9 specifically
	// (e.g. its SOA query failed independently of the A query).
	soa := map[string]uint32{"Google": 100, "Cloudflare": 100}
	r := Analyze("example.com", resolver.TypeA, answers, soa)
	found := findVerdict(t, r.Verdicts, "Quad9")
	if found.Verdict != VerdictUnknown {
		t.Errorf("Quad9 verdict = %s, want unknown", found.Verdict)
	}
}

func findVerdict(t *testing.T, verdicts []ResolverVerdict, resolverName string) ResolverVerdict {
	t.Helper()
	for _, v := range verdicts {
		if v.Resolver == resolverName {
			return v
		}
	}
	t.Fatalf("no verdict found for resolver %q in %+v", resolverName, verdicts)
	return ResolverVerdict{}
}
