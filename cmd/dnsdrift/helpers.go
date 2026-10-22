package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hellpuffyt/dnsdrift/internal/analysis"
	"github.com/hellpuffyt/dnsdrift/internal/query"
	"github.com/hellpuffyt/dnsdrift/internal/resolver"
	"github.com/hellpuffyt/dnsdrift/internal/snapshot"
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
		if _, _, err := net.SplitHostPort(addr); err != nil {
			// No port given: "192.0.2.1", "dns.example", "::1" or "[::1]".
			addr = net.JoinHostPort(strings.Trim(addr, "[]"), "53")
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
			in.TTL = observedTTL(res.ByType[resolver.TypeA])
			in.TTLRecordType = "A"
		}
	}

	soaZone := majoritySOAZone(res.ByType[resolver.TypeSOA])
	if soaZone == "" {
		soaZone = majorityZone(res.SOAZoneByResolver)
	}
	// Without any SOA data the apex is unknown: do not guess. (Assuming
	// the queried name was the apex flagged every CNAME'd subdomain as
	// "cname-at-apex".)
	in.IsApex = soaZone != "" && normalizeName(domain) == normalizeName(soaZone)
	_, nsQueried := reports[resolver.TypeNS]
	in.SkipNS = !nsQueried || !in.IsApex

	if cReport, ok := reports[resolver.TypeCNAME]; ok {
		if rec := majorityRecords(cReport); len(rec) > 0 {
			in.HasCNAME = true
			in.CNAMETarget = rec[0]
			in.CNAMETargetResolves = cnameTargetResolves
		}
	}

	return in
}

// majorityZone returns the most common non-empty zone in byResolver (ties
// broken alphabetically for determinism), or "" if there is none.
func majorityZone(byResolver map[string]string) string {
	counts := map[string]int{}
	for _, z := range byResolver {
		if z != "" {
			counts[z]++
		}
	}
	best, bestCount := "", 0
	for z, c := range counts {
		if c > bestCount || (c == bestCount && z < best) {
			best, bestCount = z, c
		}
	}
	return best
}

// observedTTL returns the largest TTL among successful answers. Recursive
// resolvers report the time left in their cache, which counts down; the
// largest value is the closest to the record's configured TTL, so the TTL
// plausibility check does not fire just because one cache is about to
// expire.
func observedTTL(answers []analysis.ResolverAnswer) uint32 {
	var max uint32
	for _, ra := range answers {
		if ra.Answer.Err == "" && ra.Answer.TTL > max {
			max = ra.Answer.TTL
		}
	}
	return max
}

// allFailed reports whether every resolver failed for every queried type,
// i.e. the query produced no data at all.
func allFailed(res query.Result, types []resolver.RecordType) bool {
	for _, t := range types {
		for _, ra := range res.ByType[t] {
			if ra.Answer.Err == "" {
				return false
			}
		}
	}
	return true
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
