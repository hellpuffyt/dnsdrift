package analysis

import "fmt"

// Severity is how serious a health Finding is.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Finding is a single health issue (or the absence of one) surfaced by a
// check.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

const (
	CodeNoNS              = "no-ns-records"
	CodeSingleNS          = "single-ns-record"
	CodeSOASerialMismatch = "soa-serial-mismatch"
	CodeTTLTooLow         = "ttl-too-low"
	CodeTTLTooHigh        = "ttl-too-high"
	CodeCNAMEAtApex       = "cname-at-apex"
	CodeDanglingCNAME     = "dangling-cname"
)

// Tunable thresholds for TTL plausibility, exported so callers/tests can
// reference them rather than hardcoding magic numbers.
const (
	// MinPlausibleTTL below this is likely to overload authoritative
	// servers and public resolvers with cache-miss traffic.
	MinPlausibleTTL = 60 // seconds
	// MaxPlausibleTTL above this makes a zone unreasonably slow to
	// converge after any future change.
	MaxPlausibleTTL = 7 * 24 * 3600 // 7 days, in seconds
)

// CheckNSRedundancy flags zones with no NS records at all, or with only a
// single NS record (no failover if that one nameserver becomes unreachable).
func CheckNSRedundancy(nsRecords []string) []Finding {
	switch len(nsRecords) {
	case 0:
		return []Finding{{
			Code:     CodeNoNS,
			Severity: SeverityError,
			Message:  "no NS records found; the zone is not delegated or is unresolvable",
		}}
	case 1:
		return []Finding{{
			Code:     CodeSingleNS,
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("only one NS record (%s); no redundancy if this nameserver becomes unreachable", nsRecords[0]),
		}}
	default:
		return nil
	}
}

// CheckSOASerialConsistency flags disagreement in SOA serial among a set of
// authoritative-ish sources (e.g. one query per authoritative nameserver).
// serials maps a source label (nameserver name) to the serial it reported.
// Fewer than two serials is not actionable and returns no finding.
func CheckSOASerialConsistency(serials map[string]uint32) []Finding {
	if len(serials) < 2 {
		return nil
	}
	var first uint32
	firstSet := false
	mismatched := false
	for _, s := range serials {
		if !firstSet {
			first = s
			firstSet = true
			continue
		}
		if s != first {
			mismatched = true
			break
		}
	}
	if !mismatched {
		return nil
	}
	return []Finding{{
		Code:     CodeSOASerialMismatch,
		Severity: SeverityError,
		Message:  "authoritative nameservers disagree on the SOA serial; zone transfer between them may have failed",
	}}
}

// CheckTTL flags a TTL that is implausibly low (excessive load on
// authoritative infrastructure) or implausibly high (slow to converge after
// a change). recordType is used only for the message text.
func CheckTTL(ttl uint32, recordType string) []Finding {
	var findings []Finding
	switch {
	case ttl < MinPlausibleTTL:
		findings = append(findings, Finding{
			Code:     CodeTTLTooLow,
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("%s TTL is %ds, below the %ds floor considered safe; this can overload resolvers and authoritative servers", recordType, ttl, MinPlausibleTTL),
		})
	case ttl > MaxPlausibleTTL:
		findings = append(findings, Finding{
			Code:     CodeTTLTooHigh,
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("%s TTL is %ds, above the %ds ceiling considered reasonable; future changes will take a long time to converge", recordType, ttl, MaxPlausibleTTL),
		})
	}
	return findings
}

// CheckCNAMEAtApex flags a CNAME record at the zone apex, which is invalid
// per RFC 1034 (the apex must also hold SOA/NS records, which cannot
// coexist with a CNAME).
func CheckCNAMEAtApex(isApex bool, hasCNAME bool) []Finding {
	if isApex && hasCNAME {
		return []Finding{{
			Code:     CodeCNAMEAtApex,
			Severity: SeverityError,
			Message:  "CNAME record found at the zone apex; this is invalid alongside required SOA/NS records",
		}}
	}
	return nil
}

// CheckDanglingCNAME flags a CNAME whose target does not resolve, which
// often indicates a decommissioned resource (e.g. a deleted cloud storage
// bucket or app) still pointed to by DNS -- a takeover risk.
func CheckDanglingCNAME(target string, targetResolves bool) []Finding {
	if target == "" || targetResolves {
		return nil
	}
	return []Finding{{
		Code:     CodeDanglingCNAME,
		Severity: SeverityError,
		Message:  fmt.Sprintf("CNAME target %q does not resolve; this may be a dangling record vulnerable to subdomain takeover", target),
	}}
}

// RunAll runs every health check against the supplied HealthInput and
// returns the combined findings.
func RunAll(in HealthInput) []Finding {
	var findings []Finding
	findings = append(findings, CheckNSRedundancy(in.NSRecords)...)
	findings = append(findings, CheckSOASerialConsistency(in.AuthoritativeSerials)...)
	if in.HasTTL {
		findings = append(findings, CheckTTL(in.TTL, in.TTLRecordType)...)
	}
	findings = append(findings, CheckCNAMEAtApex(in.IsApex, in.HasCNAME)...)
	if in.HasCNAME {
		findings = append(findings, CheckDanglingCNAME(in.CNAMETarget, in.CNAMETargetResolves)...)
	}
	return findings
}

// HealthInput bundles the already-resolved facts RunAll needs. Building it
// is the CLI's job; RunAll and the individual Check* functions stay pure.
type HealthInput struct {
	NSRecords            []string
	AuthoritativeSerials map[string]uint32
	HasTTL               bool
	TTL                  uint32
	TTLRecordType        string
	IsApex               bool
	HasCNAME             bool
	CNAMETarget          string
	CNAMETargetResolves  bool
}
