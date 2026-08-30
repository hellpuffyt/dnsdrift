package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prabeshsharma/dnsdrift/internal/analysis"
	"github.com/prabeshsharma/dnsdrift/internal/resolver"
)

func TestAnyDisagreementFalseWhenAllAgreeAndHealthy(t *testing.T) {
	out := QueryOutput{
		Reports: []analysis.Report{{Agree: true}},
	}
	if out.AnyDisagreement() {
		t.Errorf("expected no disagreement")
	}
}

func TestAnyDisagreementTrueOnReportDisagreement(t *testing.T) {
	out := QueryOutput{Reports: []analysis.Report{{Agree: false}}}
	if !out.AnyDisagreement() {
		t.Errorf("expected disagreement")
	}
}

func TestAnyDisagreementTrueOnHealthFinding(t *testing.T) {
	out := QueryOutput{
		Reports:  []analysis.Report{{Agree: true}},
		Findings: []analysis.Finding{{Code: "x", Severity: analysis.SeverityWarning, Message: "m"}},
	}
	if !out.AnyDisagreement() {
		t.Errorf("expected disagreement due to a health finding")
	}
}

func TestRenderJSONProducesValidStructure(t *testing.T) {
	var buf bytes.Buffer
	out := QueryOutput{Domain: "example.com"}
	if err := RenderJSON(&buf, out); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"domain": "example.com"`) {
		t.Errorf("json output missing domain field: %s", buf.String())
	}
}

func TestRenderTableShowsAgreementAndDisagreement(t *testing.T) {
	out := QueryOutput{
		Domain: "example.com",
		Reports: []analysis.Report{
			{
				RecordType: resolver.TypeA,
				Agree:      true,
				Groups:     []analysis.Group{{Records: []string{"1.2.3.4"}, Resolvers: []string{"Google", "Cloudflare"}, IsMajority: true}},
			},
			{
				RecordType: resolver.TypeAAAA,
				Agree:      false,
				Groups: []analysis.Group{
					{Records: []string{"::1"}, Resolvers: []string{"Google"}, IsMajority: true},
					{Records: []string{"::2"}, Resolvers: []string{"Quad9"}, IsMajority: false},
				},
				Verdicts: []analysis.ResolverVerdict{{Resolver: "Quad9", Verdict: analysis.VerdictMisconfigured, Reason: "test reason"}},
			},
		},
	}
	var buf bytes.Buffer
	RenderTable(&buf, out)
	s := buf.String()
	for _, want := range []string{"example.com", "all resolvers agree", "DISAGREEMENT", "misconfigured", "test reason", "Health findings: none"} {
		if !strings.Contains(s, want) {
			t.Errorf("table output missing %q\n--- output ---\n%s", want, s)
		}
	}
}

func TestRenderTableShowsFindings(t *testing.T) {
	out := QueryOutput{
		Domain:   "example.com",
		Findings: []analysis.Finding{{Code: "no-ns-records", Severity: analysis.SeverityError, Message: "no NS records"}},
	}
	var buf bytes.Buffer
	RenderTable(&buf, out)
	s := buf.String()
	if !strings.Contains(s, "no-ns-records") || !strings.Contains(s, "ERROR") {
		t.Errorf("expected finding rendered, got %s", s)
	}
}

func TestRenderTableShowsErroredResolvers(t *testing.T) {
	out := QueryOutput{
		Domain: "example.com",
		Reports: []analysis.Report{
			{RecordType: resolver.TypeA, Agree: false, Errored: []string{"Quad9"}},
		},
	}
	var buf bytes.Buffer
	RenderTable(&buf, out)
	if !strings.Contains(buf.String(), "errored: Quad9") {
		t.Errorf("expected errored resolver listed, got %s", buf.String())
	}
}

func TestRenderDiffTableNoDrift(t *testing.T) {
	var buf bytes.Buffer
	RenderDiffTable(&buf, "old.com", "new.com", nil, nil, nil)
	if !strings.Contains(buf.String(), "no drift detected") {
		t.Errorf("expected 'no drift detected', got %s", buf.String())
	}
}

func TestRenderDiffTableShowsAddedRemovedChanged(t *testing.T) {
	var buf bytes.Buffer
	added := []DiffRecordView{{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300}}
	removed := []DiffRecordView{{Resolver: "Cloudflare", Type: "AAAA", Values: []string{"::1"}, TTL: 300}}
	changed := []DiffChangeView{{Resolver: "Quad9", Type: "A", OldValues: []string{"1.1.1.1"}, NewValues: []string{"2.2.2.2"}, OldTTL: 300, NewTTL: 60}}
	RenderDiffTable(&buf, "old.com", "new.com", added, removed, changed)
	s := buf.String()
	for _, want := range []string{"+ Google A", "- Cloudflare AAAA", "~ Quad9 A", "1.1.1.1", "2.2.2.2"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}
