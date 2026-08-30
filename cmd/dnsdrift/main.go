// Command dnsdrift queries a domain across many public DNS resolvers
// concurrently, reports where they agree and disagree, and explains
// disagreement as either propagation lag or genuine misconfiguration. It
// can also snapshot a query to JSON and diff two snapshots to show drift
// over time.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/prabeshsharma/dnsdrift/internal/analysis"
	"github.com/prabeshsharma/dnsdrift/internal/output"
	"github.com/prabeshsharma/dnsdrift/internal/query"
	"github.com/prabeshsharma/dnsdrift/internal/resolver"
	"github.com/prabeshsharma/dnsdrift/internal/snapshot"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "query":
		return runQuery(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "dnsdrift %s\n", version)
		return 0
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, `dnsdrift - detect DNS record drift across resolvers and over time

Usage:
  dnsdrift query <domain> [flags]
  dnsdrift diff <old-snapshot.json> <new-snapshot.json> [flags]
  dnsdrift version

Query flags:
  --types string       comma-separated record types (A,AAAA,CNAME,MX,TXT,NS,SOA); default: all
  --resolvers string   comma-separated extra resolvers as Name=host[:port]
  --only-resolvers     use only --resolvers, skipping the built-in public panel
  --timeout duration   per-query timeout (default 5s)
  --save string        save this query as a JSON snapshot to the given path
  --json                emit JSON instead of a table

Diff flags:
  --json                emit JSON instead of a table

Exit codes: 0 = full agreement and no health findings; 1 = disagreement or a
health finding was found; 2 = usage error; 3 = a query could not complete.`)
}

func runQuery(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	typesFlag := fs.String("types", "", "comma-separated record types")
	resolversFlag := fs.String("resolvers", "", "comma-separated extra resolvers as Name=host[:port]")
	onlyResolvers := fs.Bool("only-resolvers", false, "use only --resolvers")
	timeoutFlag := fs.Duration("timeout", 5*time.Second, "per-query timeout")
	savePath := fs.String("save", "", "save this query as a JSON snapshot")
	jsonOut := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "expected exactly one domain argument")
		return 2
	}
	domain := normalizeName(fs.Arg(0))

	types, err := parseTypes(*typesFlag)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	extra, err := parseExtraResolvers(*resolversFlag, *timeoutFlag)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	panel := buildPanel(extra, *onlyResolvers, *timeoutFlag)
	if len(panel) == 0 {
		fmt.Fprintln(stderr, "resolver panel is empty (did you set --only-resolvers without --resolvers?)")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag+5*time.Second)
	defer cancel()

	res := query.RunPanel(ctx, panel, domain, types)

	reports := map[resolver.RecordType]analysis.Report{}
	out := output.QueryOutput{Domain: domain}
	for _, t := range types {
		r := analysis.Analyze(domain, t, res.ByType[t], res.SOAByResolver)
		reports[t] = r
		out.Reports = append(out.Reports, r)
	}

	cnameResolves := false
	if cReport, ok := reports[resolver.TypeCNAME]; ok {
		if rec := majorityRecords(cReport); len(rec) > 0 && len(panel) > 0 {
			checkCtx, checkCancel := context.WithTimeout(context.Background(), *timeoutFlag)
			ans, qerr := panel[0].Query(checkCtx, rec[0], resolver.TypeA)
			checkCancel()
			cnameResolves = qerr == nil && ans.Err == "" && len(ans.Records) > 0
		}
	}
	healthInput := buildHealthInput(domain, res, reports, cnameResolves)
	out.Findings = analysis.RunAll(healthInput)

	if *jsonOut {
		if err := output.RenderJSON(stdout, out); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
	} else {
		output.RenderTable(stdout, out)
	}

	if *savePath != "" {
		snap := buildSnapshot(domain, res, time.Now().UTC())
		if err := snapshot.Save(*savePath, snap); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
	}

	if out.AnyDisagreement() {
		return 1
	}
	return 0
}

func runDiff(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "expected exactly two snapshot file arguments: old new")
		return 2
	}

	oldSnap, err := snapshot.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	newSnap, err := snapshot.Load(fs.Arg(1))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}

	d := snapshot.Compare(oldSnap, newSnap)

	if *jsonOut {
		if err := output.RenderJSON(stdout, d); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
	} else {
		added := make([]output.DiffRecordView, len(d.Added))
		for i, r := range d.Added {
			added[i] = output.DiffRecordView{Resolver: r.Resolver, Type: r.Type, Values: r.Values, TTL: r.TTL}
		}
		removed := make([]output.DiffRecordView, len(d.Removed))
		for i, r := range d.Removed {
			removed[i] = output.DiffRecordView{Resolver: r.Resolver, Type: r.Type, Values: r.Values, TTL: r.TTL}
		}
		changed := make([]output.DiffChangeView, len(d.Changed))
		for i, c := range d.Changed {
			changed[i] = output.DiffChangeView{Resolver: c.Resolver, Type: c.Type, OldValues: c.OldValues, NewValues: c.NewValues, OldTTL: c.OldTTL, NewTTL: c.NewTTL}
		}
		output.RenderDiffTable(stdout, d.OldDomain, d.NewDomain, added, removed, changed)
	}

	if d.HasDrift() {
		return 1
	}
	return 0
}
