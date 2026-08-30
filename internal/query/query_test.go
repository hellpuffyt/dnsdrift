package query

import (
	"context"
	"testing"

	"github.com/prabeshsharma/dnsdrift/internal/resolver"
)

func TestRunPanelCollectsPerResolverAnswers(t *testing.T) {
	r1 := resolver.NewFakeResolver("Google", "8.8.8.8:53").
		WithAnswer(resolver.TypeA, resolver.Answer{Records: []string{"1.2.3.4"}, TTL: 300}).
		WithAnswer(resolver.TypeSOA, resolver.Answer{SOA: &resolver.SOA{Serial: 100}})
	r2 := resolver.NewFakeResolver("Cloudflare", "1.1.1.1:53").
		WithAnswer(resolver.TypeA, resolver.Answer{Records: []string{"1.2.3.4"}, TTL: 300}).
		WithAnswer(resolver.TypeSOA, resolver.Answer{SOA: &resolver.SOA{Serial: 100}})

	res := RunPanel(context.Background(), []resolver.Resolver{r1, r2}, "example.com", []resolver.RecordType{resolver.TypeA})

	if len(res.ByType[resolver.TypeA]) != 2 {
		t.Fatalf("expected 2 A answers, got %d", len(res.ByType[resolver.TypeA]))
	}
	if res.SOAByResolver["Google"] != 100 || res.SOAByResolver["Cloudflare"] != 100 {
		t.Fatalf("expected SOA serials collected, got %+v", res.SOAByResolver)
	}
	// SOA was not explicitly requested as an output type, so it should not
	// appear in ByType.
	if _, ok := res.ByType[resolver.TypeSOA]; ok {
		t.Errorf("SOA should not be a requested output type here")
	}
}

func TestRunPanelExplicitSOARequestSurfacesInByType(t *testing.T) {
	r1 := resolver.NewFakeResolver("Google", "8.8.8.8:53").
		WithAnswer(resolver.TypeSOA, resolver.Answer{SOA: &resolver.SOA{Serial: 55}})

	res := RunPanel(context.Background(), []resolver.Resolver{r1}, "example.com", []resolver.RecordType{resolver.TypeSOA})

	if len(res.ByType[resolver.TypeSOA]) != 1 {
		t.Fatalf("expected SOA answer in ByType, got %+v", res.ByType)
	}
	if res.SOAByResolver["Google"] != 55 {
		t.Errorf("expected serial 55, got %+v", res.SOAByResolver)
	}
}

func TestRunPanelSkipsSOACollectionOnError(t *testing.T) {
	r1 := resolver.NewFakeResolver("Google", "8.8.8.8:53")
	// No SOA answer configured -> Query returns an error Answer.
	res := RunPanel(context.Background(), []resolver.Resolver{r1}, "example.com", []resolver.RecordType{resolver.TypeA})
	if _, ok := res.SOAByResolver["Google"]; ok {
		t.Errorf("a failed SOA query should not populate SOAByResolver")
	}
}

func TestRunPanelQueriesEveryResolverForEveryType(t *testing.T) {
	r1 := resolver.NewFakeResolver("Google", "8.8.8.8:53")
	r2 := resolver.NewFakeResolver("Cloudflare", "1.1.1.1:53")

	RunPanel(context.Background(), []resolver.Resolver{r1, r2}, "example.com", []resolver.RecordType{resolver.TypeA, resolver.TypeAAAA})

	// A, AAAA, plus the implicit companion SOA query = 3 calls each.
	if len(r1.Calls) != 3 {
		t.Errorf("r1 got %d calls, want 3: %+v", len(r1.Calls), r1.Calls)
	}
	if len(r2.Calls) != 3 {
		t.Errorf("r2 got %d calls, want 3: %+v", len(r2.Calls), r2.Calls)
	}
}

func TestRunPanelEmptyPanel(t *testing.T) {
	res := RunPanel(context.Background(), nil, "example.com", []resolver.RecordType{resolver.TypeA})
	if len(res.ByType[resolver.TypeA]) != 0 {
		t.Errorf("expected no answers for an empty panel")
	}
}

func TestRunPanelResolverErrorBecomesAnswerErr(t *testing.T) {
	r1 := resolver.NewFakeResolver("Google", "8.8.8.8:53")
	r1.QueryErr = context.DeadlineExceeded
	res := RunPanel(context.Background(), []resolver.Resolver{r1}, "example.com", []resolver.RecordType{resolver.TypeA})
	answers := res.ByType[resolver.TypeA]
	if len(answers) != 1 || answers[0].Answer.Err == "" {
		t.Fatalf("expected an error answer, got %+v", answers)
	}
}
