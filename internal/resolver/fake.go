package resolver

import "context"

// FakeResolver is an in-memory Resolver used by tests. It lets tests build
// deterministic, offline scenarios (agreement, split answers, propagation
// lag, misconfiguration, and error conditions) without touching the
// network.
type FakeResolver struct {
	name string
	addr string
	// Answers maps a RecordType to the canned Answer this resolver returns.
	Answers map[RecordType]Answer
	// QueryErr, when set, is returned as the error from Query for every
	// call (simulating context cancellation / transport failure rather
	// than a DNS-level error).
	QueryErr error
	// Calls records every (name, rtype) pair this resolver was asked
	// about, in order, so tests can assert on call patterns.
	Calls []FakeCall
}

// FakeCall records a single Query invocation against a FakeResolver.
type FakeCall struct {
	Name  string
	RType RecordType
}

// NewFakeResolver builds a FakeResolver with the given label/address and no
// canned answers; use WithAnswer to add them.
func NewFakeResolver(name, addr string) *FakeResolver {
	return &FakeResolver{name: name, addr: addr, Answers: map[RecordType]Answer{}}
}

// WithAnswer registers the Answer this resolver returns for rtype and
// returns the receiver for chaining.
func (f *FakeResolver) WithAnswer(rtype RecordType, a Answer) *FakeResolver {
	a.RecordType = rtype
	f.Answers[rtype] = a
	return f
}

func (f *FakeResolver) Name() string    { return f.name }
func (f *FakeResolver) Address() string { return f.addr }

// Query implements Resolver.
func (f *FakeResolver) Query(ctx context.Context, name string, rtype RecordType) (Answer, error) {
	f.Calls = append(f.Calls, FakeCall{Name: name, RType: rtype})
	if f.QueryErr != nil {
		return Answer{}, f.QueryErr
	}
	if a, ok := f.Answers[rtype]; ok {
		return a, nil
	}
	return Answer{RecordType: rtype, Err: "no such record configured in fake"}, nil
}
