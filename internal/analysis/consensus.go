package analysis

import (
	"sort"

	"github.com/prabeshsharma/dnsdrift/internal/resolver"
)

// Verdict classifies why a resolver's answer disagrees with the consensus.
type Verdict string

const (
	// VerdictConsensus means this resolver agrees with the majority; there
	// is nothing to explain.
	VerdictConsensus Verdict = "consensus"
	// VerdictPropagating means the resolver is behind on the zone's SOA
	// serial and its cached answer's TTL has not yet expired -- consistent
	// with ordinary propagation lag that will resolve itself.
	VerdictPropagating Verdict = "propagating"
	// VerdictMisconfigured means the resolver disagrees with the majority
	// despite not being explainable as propagation lag: either it reports
	// the same (current) SOA serial as the majority yet still differs, or
	// it is behind on the serial but its TTL has already expired without
	// the answer changing.
	VerdictMisconfigured Verdict = "misconfigured"
	// VerdictUnknown means there was not enough information (no SOA data
	// available for this resolver) to distinguish propagation from
	// misconfiguration.
	VerdictUnknown Verdict = "unknown"
	// VerdictError means the resolver failed to answer at all.
	VerdictError Verdict = "error"
)

// Group is a set of resolvers that returned identical record data for a
// query.
type Group struct {
	Records    []string `json:"records"`
	Resolvers  []string `json:"resolvers"`
	IsMajority bool     `json:"isMajority"`
}

// ResolverVerdict is the per-resolver explanation attached to a minority
// (disagreeing) group.
type ResolverVerdict struct {
	Resolver string  `json:"resolver"`
	Verdict  Verdict `json:"verdict"`
	Reason   string  `json:"reason"`
}

// Report is the full consensus analysis for one (name, type) query across a
// panel of resolvers.
type Report struct {
	Domain       string              `json:"domain"`
	RecordType   resolver.RecordType `json:"recordType"`
	Groups       []Group             `json:"groups"`
	Agree        bool                `json:"agree"`
	Errored      []string            `json:"errored,omitempty"`
	MaxSOASerial uint32              `json:"maxSoaSerial,omitempty"`
	HasSOAData   bool                `json:"hasSoaData"`
	Verdicts     []ResolverVerdict   `json:"verdicts,omitempty"`
}

// Analyze groups a panel's answers for a single (domain, type) query into
// agreement/disagreement, and for every resolver in a minority group,
// determines whether the disagreement looks like propagation lag or a
// genuine misconfiguration.
//
// soaByResolver supplies, for resolvers where it's known, the SOA serial
// observed at that resolver (typically from a companion SOA query run
// alongside the record being analyzed). Resolvers absent from soaByResolver
// are treated as VerdictUnknown when they land in a minority group.
func Analyze(domain string, rtype resolver.RecordType, answers []ResolverAnswer, soaByResolver map[string]uint32) Report {
	report := Report{Domain: domain, RecordType: rtype}

	groupsByKey := map[string]*Group{}
	var order []string

	for _, ra := range answers {
		if ra.Answer.Err != "" {
			report.Errored = append(report.Errored, ra.Resolver)
			continue
		}
		key := ra.Answer.Key()
		g, ok := groupsByKey[key]
		if !ok {
			records := append([]string(nil), ra.Answer.Records...)
			g = &Group{Records: records}
			groupsByKey[key] = g
			order = append(order, key)
		}
		g.Resolvers = append(g.Resolvers, ra.Resolver)
	}

	sort.Strings(report.Errored)

	// Determine majority group (largest resolver count; ties broken by the
	// first group encountered in input order for determinism).
	var majorityKey string
	majoritySize := -1
	for _, key := range order {
		g := groupsByKey[key]
		if len(g.Resolvers) > majoritySize {
			majoritySize = len(g.Resolvers)
			majorityKey = key
		}
	}

	for _, key := range order {
		g := groupsByKey[key]
		sort.Strings(g.Resolvers)
		if key == majorityKey {
			g.IsMajority = true
		}
		report.Groups = append(report.Groups, *g)
	}

	report.Agree = len(report.Groups) == 1 && len(report.Errored) == 0

	if len(soaByResolver) > 0 {
		report.HasSOAData = true
		var maxSerial uint32
		first := true
		for _, s := range soaByResolver {
			if first || s > maxSerial {
				maxSerial = s
				first = false
			}
		}
		report.MaxSOASerial = maxSerial
	}

	// Build verdicts for every resolver not in the majority group
	// (minority disagreement + errored resolvers).
	for _, g := range report.Groups {
		if g.IsMajority {
			continue
		}
		for _, res := range g.Resolvers {
			v, reason := classify(res, answers, soaByResolver, report.MaxSOASerial, report.HasSOAData)
			report.Verdicts = append(report.Verdicts, ResolverVerdict{Resolver: res, Verdict: v, Reason: reason})
		}
	}
	for _, res := range report.Errored {
		report.Verdicts = append(report.Verdicts, ResolverVerdict{Resolver: res, Verdict: VerdictError, Reason: "resolver failed to answer"})
	}

	sort.Slice(report.Verdicts, func(i, j int) bool { return report.Verdicts[i].Resolver < report.Verdicts[j].Resolver })

	return report
}

// classify implements the propagation-vs-misconfiguration heuristic: a
// resolver that is behind on the zone's SOA serial and still has time left
// on its cached answer's TTL is propagating; a resolver reporting the
// current serial (or one whose TTL has already fully expired) yet still
// disagreeing is misconfigured.
func classify(resolverName string, answers []ResolverAnswer, soaByResolver map[string]uint32, maxSerial uint32, hasSOAData bool) (Verdict, string) {
	var ttl uint32
	for _, ra := range answers {
		if ra.Resolver == resolverName {
			ttl = ra.Answer.TTL
			break
		}
	}

	serial, known := soaByResolver[resolverName]
	if !hasSOAData || !known {
		return VerdictUnknown, "no SOA data available for this resolver to compare serials"
	}

	if serial < maxSerial {
		if ttl > 0 {
			return VerdictPropagating, "resolver holds an older SOA serial and its cached answer's TTL has not expired; expected to converge"
		}
		return VerdictMisconfigured, "resolver holds an older SOA serial but its TTL has already expired without refreshing; it should have picked up the new answer"
	}
	return VerdictMisconfigured, "resolver reports the current SOA serial yet still disagrees with the majority answer"
}
