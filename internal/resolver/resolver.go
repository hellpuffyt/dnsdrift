// Package resolver defines the abstraction dnsdrift uses to query DNS
// resolvers, plus a real implementation on top of github.com/miekg/dns.
//
// Everything above this package (consensus analysis, propagation-vs-
// misconfiguration reasoning, health findings) depends only on the Resolver
// interface and the Answer/SOA structs, never on the network. That is what
// lets the rest of the codebase be tested offline with FakeResolver.
package resolver

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// RecordType is a DNS RR type that dnsdrift understands.
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeNS    RecordType = "NS"
	TypeSOA   RecordType = "SOA"
)

// AllTypes is the default set of record types dnsdrift queries.
var AllTypes = []RecordType{TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeTXT, TypeNS, TypeSOA}

// ParseRecordType normalizes user input (case-insensitive) into a RecordType,
// validating it against the set dnsdrift supports.
func ParseRecordType(s string) (RecordType, error) {
	rt := RecordType(strings.ToUpper(strings.TrimSpace(s)))
	switch rt {
	case TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeTXT, TypeNS, TypeSOA:
		return rt, nil
	default:
		return "", fmt.Errorf("unsupported record type %q", s)
	}
}

// SOA carries the fields of an SOA record that matter for drift analysis.
type SOA struct {
	// Zone is the owner name of the SOA record, i.e. the zone apex, with
	// the trailing root dot stripped (e.g. "example.com").
	Zone    string `json:"zone"`
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// Answer is what a single resolver returned for a single (name, type) query.
// Records holds normalized, sorted string representations of the RR data
// (e.g. IP addresses, "10 mail.example.com" for MX, TXT content, NS/CNAME
// targets). TTL is the minimum TTL observed across the returned records.
type Answer struct {
	RecordType RecordType `json:"recordType"`
	Records    []string   `json:"records"`
	TTL        uint32     `json:"ttl"`
	SOA        *SOA       `json:"soa,omitempty"`
	Err        string     `json:"error,omitempty"`
}

// NormalizeRecords sorts and dedupes a slice of record strings in place and
// returns it, so answers compare equal regardless of the order a resolver
// returned them in.
func NormalizeRecords(records []string) []string {
	if len(records) == 0 {
		return records
	}
	sort.Strings(records)
	out := records[:1]
	for _, r := range records[1:] {
		if r != out[len(out)-1] {
			out = append(out, r)
		}
	}
	return out
}

// Key returns a stable string identifying an answer's record content, used
// to group resolvers that agree with each other. Two answers with the same
// Key are considered to agree, independent of TTL or SOA.
func (a Answer) Key() string {
	if a.Err != "" {
		return "ERROR:" + a.Err
	}
	return strings.Join(a.Records, "|")
}

// Resolver queries a single DNS server for a single (name, type) pair.
type Resolver interface {
	// Name is a human-readable label, e.g. "Google (8.8.8.8)".
	Name() string
	// Address is the resolver's network address, e.g. "8.8.8.8:53".
	Address() string
	// Query resolves name for the given record type against this resolver.
	// A failed query is reported via Answer.Err, not a returned error; the
	// returned error is reserved for context cancellation and similar.
	Query(ctx context.Context, name string, rtype RecordType) (Answer, error)
}

// WellKnown is the default panel of public resolvers dnsdrift queries.
var WellKnown = []struct {
	Name string
	Addr string
}{
	{"Google", "8.8.8.8:53"},
	{"Cloudflare", "1.1.1.1:53"},
	{"Quad9", "9.9.9.9:53"},
	{"OpenDNS", "208.67.222.222:53"},
}
