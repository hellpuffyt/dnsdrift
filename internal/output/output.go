// Package output renders analysis results as a human-readable table or as
// JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/prabeshsharma/dnsdrift/internal/analysis"
)

// QueryOutput is the full result of a `dnsdrift query` run, in the shape
// written out as JSON and rendered as a table.
type QueryOutput struct {
	Domain   string             `json:"domain"`
	Reports  []analysis.Report  `json:"reports"`
	Findings []analysis.Finding `json:"findings,omitempty"`
}

// AnyDisagreement reports whether any record type in the output had
// resolvers that disagreed, or a health finding at warning/error severity
// -- the condition dnsdrift's CLI uses to decide its exit code.
func (o QueryOutput) AnyDisagreement() bool {
	for _, r := range o.Reports {
		if !r.Agree {
			return true
		}
	}
	return len(o.Findings) > 0
}

// RenderJSON writes o to w as indented JSON.
func RenderJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// RenderTable writes a human-readable summary of o to w: one section per
// record type showing the resolver split and, for disagreements, the
// propagation-vs-misconfiguration verdict, followed by health findings.
func RenderTable(w io.Writer, o QueryOutput) {
	fmt.Fprintf(w, "dnsdrift report for %s\n", o.Domain)
	fmt.Fprintln(w, strings.Repeat("=", 40))

	types := make([]string, 0, len(o.Reports))
	byType := map[string]analysis.Report{}
	for _, r := range o.Reports {
		types = append(types, string(r.RecordType))
		byType[string(r.RecordType)] = r
	}
	sort.Strings(types)

	for _, t := range types {
		r := byType[t]
		fmt.Fprintf(w, "\n%s\n", t)
		if r.Agree {
			fmt.Fprintln(w, "  all resolvers agree")
		} else {
			fmt.Fprintln(w, "  DISAGREEMENT")
		}

		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, g := range r.Groups {
			label := "minority"
			if g.IsMajority {
				label = "majority"
			}
			fmt.Fprintf(tw, "  [%s]\t%s\t%s\n", label, strings.Join(g.Resolvers, ", "), formatRecords(g.Records))
		}
		tw.Flush()

		if len(r.Errored) > 0 {
			fmt.Fprintf(w, "  errored: %s\n", strings.Join(r.Errored, ", "))
		}
		for _, v := range r.Verdicts {
			if v.Verdict == analysis.VerdictError {
				continue
			}
			fmt.Fprintf(w, "  %s: %s -- %s\n", v.Resolver, v.Verdict, v.Reason)
		}
	}

	if len(o.Findings) > 0 {
		fmt.Fprintf(w, "\nHealth findings\n")
		for _, f := range o.Findings {
			fmt.Fprintf(w, "  [%s] %s: %s\n", strings.ToUpper(string(f.Severity)), f.Code, f.Message)
		}
	} else {
		fmt.Fprintf(w, "\nHealth findings: none\n")
	}
}

func formatRecords(records []string) string {
	if len(records) == 0 {
		return "(no records)"
	}
	return strings.Join(records, ", ")
}

// RenderDiffTable writes a human-readable summary of a snapshot diff.
func RenderDiffTable(w io.Writer, oldDomain, newDomain string, added, removed []DiffRecordView, changed []DiffChangeView) {
	fmt.Fprintf(w, "dnsdrift snapshot diff: %s -> %s\n", oldDomain, newDomain)
	fmt.Fprintln(w, strings.Repeat("=", 40))
	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		fmt.Fprintln(w, "no drift detected")
		return
	}
	for _, a := range added {
		fmt.Fprintf(w, "+ %s %s: %s (ttl %ds)\n", a.Resolver, a.Type, formatRecords(a.Values), a.TTL)
	}
	for _, r := range removed {
		fmt.Fprintf(w, "- %s %s: %s (ttl %ds)\n", r.Resolver, r.Type, formatRecords(r.Values), r.TTL)
	}
	for _, c := range changed {
		fmt.Fprintf(w, "~ %s %s: %s (ttl %ds) -> %s (ttl %ds)\n", c.Resolver, c.Type, formatRecords(c.OldValues), c.OldTTL, formatRecords(c.NewValues), c.NewTTL)
	}
}

// DiffRecordView and DiffChangeView are thin, package-agnostic mirrors of
// snapshot.Record / snapshot.Change so this package does not need to import
// snapshot (kept separate to avoid a dependency cycle risk and to keep
// output's surface minimal and test-friendly).
type DiffRecordView struct {
	Resolver string
	Type     string
	Values   []string
	TTL      uint32
}

type DiffChangeView struct {
	Resolver  string
	Type      string
	OldValues []string
	NewValues []string
	OldTTL    uint32
	NewTTL    uint32
}
