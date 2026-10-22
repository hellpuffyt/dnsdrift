package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hellpuffyt/dnsdrift/internal/dnstest"
	"github.com/hellpuffyt/dnsdrift/internal/output"
)

// End-to-end `dnsdrift query` / `diff` runs against DNS servers on
// 127.0.0.1 (internal/dnstest), using --only-resolvers so the public panel
// is never contacted.

const soaV1 = "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2024010101 7200 900 1209600 300"
const soaV2 = "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2024010102 7200 900 1209600 300"

func baseZone(soa, apexA string) []string {
	return []string{
		soa,
		"example.test. 3600 IN NS ns1.example.test.",
		"example.test. 3600 IN NS ns2.example.test.",
		"example.test. 300 IN A " + apexA,
		"www.example.test. 300 IN CNAME example.test.",
		"v6.example.test. 300 IN CNAME only6.example.test.",
		"only6.example.test. 300 IN AAAA 2001:db8::6",
		"gone.example.test. 300 IN CNAME deleted.example.test.",
	}
}

func queryJSON(t *testing.T, args ...string) (output.QueryOutput, int) {
	t.Helper()
	stdout, code := captureOutput(t, func(w *os.File) int {
		return run(append([]string{"query", "--json", "--only-resolvers", "--timeout", "2s"}, args...), w, devNull(t))
	})
	var out output.QueryOutput
	if code != 3 {
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("bad JSON (exit %d): %v\n%s", code, err, stdout)
		}
	}
	return out, code
}

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func codes(out output.QueryOutput) string {
	var c []string
	for _, f := range out.Findings {
		c = append(c, f.Code)
	}
	return strings.Join(c, ",")
}

func TestE2EAgreementExitsZero(t *testing.T) {
	a := dnstest.Start(t, baseZone(soaV1, "192.0.2.10")...)
	b := dnstest.Start(t, baseZone(soaV1, "192.0.2.10")...)
	out, code := queryJSON(t, "--resolvers", "A="+a.Addr+",B="+b.Addr, "--types", "A,NS,SOA", "example.test")
	if code != 0 || codes(out) != "" {
		t.Fatalf("exit %d findings %q", code, codes(out))
	}
	for _, r := range out.Reports {
		if !r.Agree {
			t.Fatalf("%s: disagreement %+v", r.RecordType, r)
		}
	}
}

// Regression for the false "cname-at-apex" on subdomains, and for a CNAME
// to an IPv6-only target being called dangling.
func TestE2ECNAMEOnSubdomainIsHealthy(t *testing.T) {
	a := dnstest.Start(t, baseZone(soaV1, "192.0.2.10")...)
	for _, name := range []string{"www.example.test", "v6.example.test"} {
		out, code := queryJSON(t, "--resolvers", "A="+a.Addr, "--types", "CNAME", name)
		if code != 0 || codes(out) != "" {
			t.Fatalf("%s: exit %d findings %q", name, code, codes(out))
		}
	}
	// NS not requested for the apex either: no "no-ns-records".
	out, code := queryJSON(t, "--resolvers", "A="+a.Addr, "--types", "A,MX", "example.test")
	if codes(out) != "" {
		t.Fatalf("apex without NS in --types: exit %d findings %q", code, codes(out))
	}
	// A CNAME to a name that does not resolve is still reported.
	out, code = queryJSON(t, "--resolvers", "A="+a.Addr, "--types", "CNAME", "gone.example.test")
	if code != 1 || codes(out) != "dangling-cname" {
		t.Fatalf("dangling: exit %d findings %q", code, codes(out))
	}
}

func TestE2EDisagreementGetsPropagatingVerdict(t *testing.T) {
	stale := dnstest.Start(t, baseZone(soaV1, "192.0.2.10")...)
	fresh1 := dnstest.Start(t, baseZone(soaV2, "192.0.2.99")...)
	fresh2 := dnstest.Start(t, baseZone(soaV2, "192.0.2.99")...)
	out, code := queryJSON(t, "--resolvers", "Stale="+stale.Addr+",F1="+fresh1.Addr+",F2="+fresh2.Addr, "--types", "A", "example.test")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	r := out.Reports[0]
	if r.Agree || len(r.Verdicts) != 1 || r.Verdicts[0].Resolver != "Stale" || r.Verdicts[0].Verdict != "propagating" {
		t.Fatalf("report: %+v", r)
	}
}

// Regression: when no resolver answered anything the exit code was 1
// ("disagreement") instead of the documented 3.
func TestE2ENoResolverAnswersExitsThree(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, code := captureOutput(t, func(w *os.File) int {
		return run([]string{"query", "--only-resolvers", "--timeout", "300ms", "--resolvers", "Dead=" + pc.LocalAddr().String(), "--types", "A", "example.test"}, w, devNull(t))
	})
	if code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
}

// Regression: two snapshots of an unchanged domain taken apart in time
// reported drift because the cached TTL had counted down.
func TestE2ESnapshotDiffIgnoresTTLCountdownButSeesChanges(t *testing.T) {
	srv := dnstest.Start(t, baseZone(soaV1, "192.0.2.10")...)
	dir := t.TempDir()
	s1, s2, s3 := filepath.Join(dir, "1.json"), filepath.Join(dir, "2.json"), filepath.Join(dir, "3.json")
	queryJSON(t, "--resolvers", "L="+srv.Addr, "--types", "A", "--save", s1, "example.test")
	zone := baseZone(soaV1, "192.0.2.10")
	zone[3] = "example.test. 297 IN A 192.0.2.10" // same data, cache TTL counted down
	srv.SetRecords(t, zone...)
	queryJSON(t, "--resolvers", "L="+srv.Addr, "--types", "A", "--save", s2, "example.test")
	if _, code := captureOutput(t, func(w *os.File) int { return run([]string{"diff", s1, s2}, w, w) }); code != 0 {
		t.Fatalf("TTL countdown reported as drift (exit %d)", code)
	}
	srv.SetRecords(t, baseZone(soaV2, "192.0.2.99")...)
	queryJSON(t, "--resolvers", "L="+srv.Addr, "--types", "A", "--save", s3, "example.test")
	diffOut, code := captureOutput(t, func(w *os.File) int { return run([]string{"diff", s1, s3}, w, w) })
	if code != 1 || !strings.Contains(diffOut, "192.0.2.10") || !strings.Contains(diffOut, "192.0.2.99") {
		t.Fatalf("real change not reported (exit %d):\n%s", code, diffOut)
	}
}
