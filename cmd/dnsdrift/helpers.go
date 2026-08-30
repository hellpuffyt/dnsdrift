package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/prabeshsharma/dnsdrift/internal/analysis"
	"github.com/prabeshsharma/dnsdrift/internal/query"
	"github.com/prabeshsharma/dnsdrift/internal/resolver"
	"github.com/prabeshsharma/dnsdrift/internal/snapshot"
)

// normalizeName lowercases a domain name and strips a trailing root dot, so
// names from user input and from DNS wire responses compare equal.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// parseTypes turns a comma-separated --types flag value into RecordTypes.
// An empty string means "use every supported type".
func parseTypes(raw string) ([]resolver.RecordType, error) {
	if strings.TrimSpace(raw) == "" {
		return resolver.AllTypes, nil
	}
	var out []resolver.RecordType
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		rt, err := resolver.ParseRecordType(part)
		if err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--types was set but no valid record types were parsed from %q", raw)
	}
	return out, nil
}

// parseExtraResolvers parses a comma-separated --resolvers flag value of
// "Name=host[:port]" entries into DNSResolvers. Port defaults to 53.
func parseExtraResolvers(raw string, timeout time.Duration) ([]resolver.Resolver, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []resolver.Resolver
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		nameAddr := strings.SplitN(part, "=", 2)
		if len(nameAddr) != 2 || nameAddr[0] == "" || nameAddr[1] == "" {
			return nil, fmt.Errorf("invalid --resolvers entry %q, expected Name=host[:port]", part)
		}
		addr := nameAddr[1]
		if !strings.Contains(addr, ":") {
			addr = addr + ":53"
		}
		out = append(out, resolver.NewDNSResolver(nameAddr[0], addr, timeout))
	}
	return out, nil
}

// buildPanel assembles the resolver panel: the well-known public resolvers
// plus any user-supplied extras, unless onlyExtra is set, in which case only
// the extras are used.
func buildPanel(extra []resolver.Resolver, onlyExtra bool, timeout time.Duration) []resolver.Resolver {
	var panel []resolver.Resolver
	if !onlyExtra {
		for _, wk := range resolver.WellKnown {
			panel = append(panel, resolver.NewDNSResolver(wk.Name, wk.Addr, timeout))
		}
	}
	panel = append(panel, extra...)
	return panel
}

// majorityRecords returns the records of the report's majority group, or
// nil if there is none (e.g. every resolver errored).
func majorityRecords(r analysis.Report) []string {
	for _, g := range r.Groups {
		if g.IsMajority {
			return g.Records
		}
	}
	return nil
}

// majoritySOAZone returns the Zone (apex) reported by SOA answers, using the
// most common non-empty value across the panel's SOA answers.
func majoritySOAZone(soaAnswers []analysis.ResolverAnswer) string {
	counts := map[string]int{}
	for _, ra := range soaAnswers {
		if ra.Answer.SOA == nil {
			continue
		}
		counts[ra.Answer.SOA.Zone]++
	}
	best := ""
	bestCount := 0
	for zone, c := range counts {
		if c > bestCount {
			best, bestCount = zone, c
		}
	}
	return best
}

// buildHealthInput derives a HealthInput from a completed query.Result and
// its per-type consensus reports, plus an optional resolved-ness check for
// a CNAME target (the caller performs that follow-up query, since it
// requires an extra network round trip).
func buildHealthInput(domain string, res query.Result, reports map[resolver.RecordType]analysis.Report, cnameTargetResolves bool) analysis.HealthInput {
	in := analysis.HealthInput{}

	if nsReport, ok := reports[resolver.TypeNS]; ok {
		in.NSRecords = majorityRecords(nsReport)
	}

	soaSerials := map[string]uint32{}
	for name, serial := range res.SOAByResolver {
		soaSerials[name] = serial
	}
	in.AuthoritativeSerials = soaSerials

	if aReport, ok := reports[resolver.TypeA]; ok {
		if rec := majorityRecords(aReport); rec != nil {
			in.HasTTL = true
			in.TTL = firstTTL(res.ByType[resolver.TypeA])
			in.TTLRecordType = "A"
		}
	}

	soaZone := majoritySOAZone(res.ByType[resolver.TypeSOA])
	if soaZone == "" {
		// SOA may not have been requested explicitly as an output type;
		// fall back to scanning SOAByResolver-derived zone via any A/CNAME
		// answer's implicit apex is not available, so leave apex detection
		// off if we truly have nothing to compare against.
		soaZone = domain
	}
	in.IsApex = normalizeName(domain) == normalizeName(soaZone)

	if cReport, ok := reports[resolver.TypeCNAME]; ok {
		if rec := majorityRecords(cReport); len(rec) > 0 {
			in.HasCNAME = true
			in.CNAMETarget = rec[0]
			in.CNAMETargetResolves = cnameTargetResolves
		}
	}

	return in
}

func firstTTL(answers []analysis.ResolverAnswer) uint32 {
	for _, ra := range answers {
		if ra.Answer.Err == "" {
			return ra.Answer.TTL
		}
	}
	return 0
}

// buildSnapshot flattens a query.Result into a snapshot.Snapshot for saving
// to disk, skipping resolvers that errored (there is nothing meaningful to
// diff against for those).
func buildSnapshot(domain string, res query.Result, now time.Time) snapshot.Snapshot {
	snap := snapshot.Snapshot{Domain: domain, Timestamp: now}
	for rtype, answers := range res.ByType {
		for _, ra := range answers {
			if ra.Answer.Err != "" {
				continue
			}
			snap.Records = append(snap.Records, snapshot.Record{
				Resolver: ra.Resolver,
				Type:     string(rtype),
				Values:   ra.Answer.Records,
				TTL:      ra.Answer.TTL,
			})
		}
	}
	return snap
}
