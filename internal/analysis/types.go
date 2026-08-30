// Package analysis contains dnsdrift's pure, offline-testable logic:
// grouping resolver answers into consensus/disagreement, deciding whether a
// disagreement is propagation lag or genuine misconfiguration, and running
// health checks over resolved data. Nothing in this package touches the
// network -- it operates entirely on the resolver.Answer values callers
// already collected.
package analysis

import "github.com/prabeshsharma/dnsdrift/internal/resolver"

// ResolverAnswer pairs a resolver's identity with what it returned for one
// (name, type) query.
type ResolverAnswer struct {
	Resolver string          `json:"resolver"`
	Answer   resolver.Answer `json:"answer"`
}
