package analysis

import "testing"

func hasCode(findings []Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestCheckNSRedundancyNone(t *testing.T) {
	f := CheckNSRedundancy(nil)
	if len(f) != 1 || f[0].Code != CodeNoNS || f[0].Severity != SeverityError {
		t.Fatalf("got %+v", f)
	}
}

func TestCheckNSRedundancySingle(t *testing.T) {
	f := CheckNSRedundancy([]string{"ns1.example.com"})
	if len(f) != 1 || f[0].Code != CodeSingleNS || f[0].Severity != SeverityWarning {
		t.Fatalf("got %+v", f)
	}
}

func TestCheckNSRedundancyHealthy(t *testing.T) {
	f := CheckNSRedundancy([]string{"ns1.example.com", "ns2.example.com"})
	if len(f) != 0 {
		t.Fatalf("expected no findings for 2 NS records, got %+v", f)
	}
}

func TestCheckNSRedundancyManyHealthy(t *testing.T) {
	f := CheckNSRedundancy([]string{"ns1.example.com", "ns2.example.com", "ns3.example.com"})
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %+v", f)
	}
}

func TestCheckSOASerialConsistencyMatch(t *testing.T) {
	f := CheckSOASerialConsistency(map[string]uint32{"ns1": 100, "ns2": 100, "ns3": 100})
	if len(f) != 0 {
		t.Fatalf("expected no findings when serials match, got %+v", f)
	}
}

func TestCheckSOASerialConsistencyMismatch(t *testing.T) {
	f := CheckSOASerialConsistency(map[string]uint32{"ns1": 100, "ns2": 101})
	if len(f) != 1 || f[0].Code != CodeSOASerialMismatch {
		t.Fatalf("got %+v", f)
	}
}

func TestCheckSOASerialConsistencyInsufficientData(t *testing.T) {
	f := CheckSOASerialConsistency(map[string]uint32{"ns1": 100})
	if len(f) != 0 {
		t.Fatalf("expected no findings with a single data point, got %+v", f)
	}
	f = CheckSOASerialConsistency(nil)
	if len(f) != 0 {
		t.Fatalf("expected no findings with no data, got %+v", f)
	}
}

func TestCheckTTLTooLow(t *testing.T) {
	f := CheckTTL(10, "A")
	if len(f) != 1 || f[0].Code != CodeTTLTooLow {
		t.Fatalf("got %+v", f)
	}
}

func TestCheckTTLTooHigh(t *testing.T) {
	f := CheckTTL(MaxPlausibleTTL+1, "A")
	if len(f) != 1 || f[0].Code != CodeTTLTooHigh {
		t.Fatalf("got %+v", f)
	}
}

func TestCheckTTLPlausible(t *testing.T) {
	f := CheckTTL(3600, "A")
	if len(f) != 0 {
		t.Fatalf("expected no findings for a normal TTL, got %+v", f)
	}
}

func TestCheckTTLBoundaries(t *testing.T) {
	if fs := CheckTTL(MinPlausibleTTL, "A"); len(fs) != 0 {
		t.Errorf("MinPlausibleTTL itself should be acceptable, got %+v", fs)
	}
	if fs := CheckTTL(MaxPlausibleTTL, "A"); len(fs) != 0 {
		t.Errorf("MaxPlausibleTTL itself should be acceptable, got %+v", fs)
	}
	if fs := CheckTTL(MinPlausibleTTL-1, "A"); len(fs) != 1 {
		t.Errorf("just below MinPlausibleTTL should flag, got %+v", fs)
	}
}

func TestCheckCNAMEAtApexFlagged(t *testing.T) {
	f := CheckCNAMEAtApex(true, true)
	if len(f) != 1 || f[0].Code != CodeCNAMEAtApex {
		t.Fatalf("got %+v", f)
	}
}

func TestCheckCNAMEAtApexNotApex(t *testing.T) {
	f := CheckCNAMEAtApex(false, true)
	if len(f) != 0 {
		t.Fatalf("CNAME on a subdomain is fine, got %+v", f)
	}
}

func TestCheckCNAMEAtApexNoCNAME(t *testing.T) {
	f := CheckCNAMEAtApex(true, false)
	if len(f) != 0 {
		t.Fatalf("apex without a CNAME is fine, got %+v", f)
	}
}

func TestCheckDanglingCNAMEFlagged(t *testing.T) {
	f := CheckDanglingCNAME("ghost.s3.amazonaws.com", false)
	if len(f) != 1 || f[0].Code != CodeDanglingCNAME {
		t.Fatalf("got %+v", f)
	}
}

func TestCheckDanglingCNAMEResolves(t *testing.T) {
	f := CheckDanglingCNAME("live.example.com", true)
	if len(f) != 0 {
		t.Fatalf("a resolving CNAME target should not be flagged, got %+v", f)
	}
}

func TestCheckDanglingCNAMENoTarget(t *testing.T) {
	f := CheckDanglingCNAME("", false)
	if len(f) != 0 {
		t.Fatalf("no target means no CNAME to check, got %+v", f)
	}
}

func TestRunAllCombinesFindings(t *testing.T) {
	in := HealthInput{
		NSRecords:            nil,
		AuthoritativeSerials: map[string]uint32{"ns1": 1, "ns2": 2},
		HasTTL:               true,
		TTL:                  1,
		TTLRecordType:        "A",
		IsApex:               true,
		HasCNAME:             true,
		CNAMETarget:          "dangling.example.net",
		CNAMETargetResolves:  false,
	}
	findings := RunAll(in)
	for _, code := range []string{CodeNoNS, CodeSOASerialMismatch, CodeTTLTooLow, CodeCNAMEAtApex, CodeDanglingCNAME} {
		if !hasCode(findings, code) {
			t.Errorf("expected finding code %s in %+v", code, findings)
		}
	}
}

func TestRunAllHealthyZoneHasNoFindings(t *testing.T) {
	in := HealthInput{
		NSRecords:            []string{"ns1.example.com", "ns2.example.com"},
		AuthoritativeSerials: map[string]uint32{"ns1": 100, "ns2": 100},
		HasTTL:               true,
		TTL:                  3600,
		TTLRecordType:        "A",
		IsApex:               false,
		HasCNAME:             false,
	}
	findings := RunAll(in)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a healthy zone, got %+v", findings)
	}
}

func TestRunAllSkipsTTLCheckWhenNotApplicable(t *testing.T) {
	in := HealthInput{
		NSRecords: []string{"ns1.example.com", "ns2.example.com"},
		HasTTL:    false,
	}
	findings := RunAll(in)
	if hasCode(findings, CodeTTLTooLow) || hasCode(findings, CodeTTLTooHigh) {
		t.Errorf("TTL findings should not appear when HasTTL is false, got %+v", findings)
	}
}

func TestRunAllSkipsDanglingCheckWithoutCNAME(t *testing.T) {
	in := HealthInput{
		NSRecords: []string{"ns1.example.com", "ns2.example.com"},
		HasCNAME:  false,
	}
	findings := RunAll(in)
	if hasCode(findings, CodeDanglingCNAME) {
		t.Errorf("dangling CNAME finding should not appear without a CNAME, got %+v", findings)
	}
}
