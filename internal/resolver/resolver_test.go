package resolver

import (
	"reflect"
	"testing"
)

func TestParseRecordType(t *testing.T) {
	cases := []struct {
		in      string
		want    RecordType
		wantErr bool
	}{
		{"A", TypeA, false},
		{"a", TypeA, false},
		{" aaaa ", TypeAAAA, false},
		{"cname", TypeCNAME, false},
		{"MX", TypeMX, false},
		{"txt", TypeTXT, false},
		{"NS", TypeNS, false},
		{"soa", TypeSOA, false},
		{"PTR", "", true},
		{"", "", true},
		{"bogus", "", true},
	}
	for _, c := range cases {
		got, err := ParseRecordType(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseRecordType(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRecordType(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRecordType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeRecords(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, nil},
		{"already sorted no dupes", []string{"a", "b"}, []string{"a", "b"}},
		{"needs sort", []string{"b", "a"}, []string{"a", "b"}},
		{"dedupes", []string{"b", "a", "b", "a"}, []string{"a", "b"}},
		{"single", []string{"only"}, []string{"only"}},
	}
	for _, c := range cases {
		got := NormalizeRecords(append([]string(nil), c.in...))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: NormalizeRecords(%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestAnswerKey(t *testing.T) {
	a1 := Answer{Records: []string{"1.2.3.4", "5.6.7.8"}}
	a2 := Answer{Records: []string{"1.2.3.4", "5.6.7.8"}}
	a3 := Answer{Records: []string{"1.2.3.4"}}
	if a1.Key() != a2.Key() {
		t.Errorf("expected equal keys for identical records: %q vs %q", a1.Key(), a2.Key())
	}
	if a1.Key() == a3.Key() {
		t.Errorf("expected different keys for different records")
	}

	errA := Answer{Err: "timeout"}
	errB := Answer{Err: "timeout"}
	errC := Answer{Err: "nxdomain"}
	if errA.Key() != errB.Key() {
		t.Errorf("expected equal keys for identical errors")
	}
	if errA.Key() == errC.Key() {
		t.Errorf("expected different keys for different errors")
	}
	if a1.Key() == errA.Key() {
		t.Errorf("an error answer must not collide with a records answer")
	}
}

func TestFakeResolverReturnsConfiguredAnswer(t *testing.T) {
	f := NewFakeResolver("Test", "1.2.3.4:53").WithAnswer(TypeA, Answer{Records: []string{"9.9.9.9"}, TTL: 300})
	got, err := f.Query(nil, "example.com", TypeA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.Records, []string{"9.9.9.9"}) {
		t.Errorf("got records %v", got.Records)
	}
	if got.TTL != 300 {
		t.Errorf("got ttl %d, want 300", got.TTL)
	}
	if len(f.Calls) != 1 || f.Calls[0].Name != "example.com" || f.Calls[0].RType != TypeA {
		t.Errorf("call not recorded correctly: %+v", f.Calls)
	}
}

func TestFakeResolverUnconfiguredTypeErrors(t *testing.T) {
	f := NewFakeResolver("Test", "1.2.3.4:53")
	got, err := f.Query(nil, "example.com", TypeAAAA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Err == "" {
		t.Errorf("expected an error answer for an unconfigured type")
	}
}

func TestFakeResolverQueryErr(t *testing.T) {
	f := NewFakeResolver("Test", "1.2.3.4:53")
	f.QueryErr = errTimeout{}
	_, err := f.Query(nil, "example.com", TypeA)
	if err == nil {
		t.Fatalf("expected error")
	}
}

type errTimeout struct{}

func (errTimeout) Error() string { return "timeout" }

func TestFakeResolverNameAndAddress(t *testing.T) {
	f := NewFakeResolver("Google", "8.8.8.8:53")
	if f.Name() != "Google" {
		t.Errorf("Name() = %q", f.Name())
	}
	if f.Address() != "8.8.8.8:53" {
		t.Errorf("Address() = %q", f.Address())
	}
}
