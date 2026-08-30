// Package query orchestrates concurrent DNS queries across a panel of
// resolvers and hands the results to the analysis package. It is the only
// place that touches the network; everything downstream operates on plain
// data and is unit-tested with fakes.
package query

import (
	"context"
	"sync"

	"github.com/prabeshsharma/dnsdrift/internal/analysis"
	"github.com/prabeshsharma/dnsdrift/internal/resolver"
)

// Result is the outcome of querying a panel of resolvers for a domain
// across one or more record types.
type Result struct {
	Domain string
	// ByType holds, for every requested record type, one ResolverAnswer
	// per resolver in the panel (in panel order).
	ByType map[resolver.RecordType][]analysis.ResolverAnswer
	// SOAByResolver holds the SOA serial each resolver reported, keyed by
	// resolver name, used by analysis.Analyze to distinguish propagation
	// lag from misconfiguration. A resolver whose SOA query failed is
	// absent from this map.
	SOAByResolver map[string]uint32
}

// RunPanel queries every resolver in panel for domain across every type in
// types, plus a companion SOA query per resolver (reused from types if SOA
// was already requested), all concurrently. It returns once every
// resolver/type pair has answered or ctx is done.
func RunPanel(ctx context.Context, panel []resolver.Resolver, domain string, types []resolver.RecordType) Result {
	needSOA := true
	for _, t := range types {
		if t == resolver.TypeSOA {
			needSOA = false
			break
		}
	}
	queryTypes := types
	if needSOA {
		queryTypes = append(append([]resolver.RecordType(nil), types...), resolver.TypeSOA)
	}

	type job struct {
		res   resolver.Resolver
		rtype resolver.RecordType
	}
	type outcome struct {
		res    resolver.Resolver
		rtype  resolver.RecordType
		answer resolver.Answer
	}

	var jobs []job
	for _, r := range panel {
		for _, t := range queryTypes {
			jobs = append(jobs, job{r, t})
		}
	}

	outcomes := make([]outcome, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			ans, err := j.res.Query(ctx, domain, j.rtype)
			if err != nil {
				ans = resolver.Answer{RecordType: j.rtype, Err: err.Error()}
			}
			outcomes[i] = outcome{j.res, j.rtype, ans}
		}(i, j)
	}
	wg.Wait()

	result := Result{
		Domain:        domain,
		ByType:        map[resolver.RecordType][]analysis.ResolverAnswer{},
		SOAByResolver: map[string]uint32{},
	}
	for _, o := range outcomes {
		if o.rtype == resolver.TypeSOA {
			if o.answer.Err == "" && o.answer.SOA != nil {
				result.SOAByResolver[o.res.Name()] = o.answer.SOA.Serial
			}
			if !needSOA {
				// SOA was explicitly requested; also surface it as a
				// regular result type.
				result.ByType[resolver.TypeSOA] = append(result.ByType[resolver.TypeSOA], analysis.ResolverAnswer{Resolver: o.res.Name(), Answer: o.answer})
			}
			continue
		}
		result.ByType[o.rtype] = append(result.ByType[o.rtype], analysis.ResolverAnswer{Resolver: o.res.Name(), Answer: o.answer})
	}

	return result
}
