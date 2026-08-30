package snapshot

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	original := Snapshot{
		Domain:    "example.com",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Records: []Record{
			{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
		},
	}
	if err := Save(path, original); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Domain != original.Domain {
		t.Errorf("Domain = %q, want %q", loaded.Domain, original.Domain)
	}
	if !loaded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", loaded.Timestamp, original.Timestamp)
	}
	if len(loaded.Records) != 1 || loaded.Records[0].Resolver != "Google" {
		t.Errorf("Records = %+v", loaded.Records)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatalf("expected an error loading a missing file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected an error parsing invalid JSON")
	}
}

func TestCompareNoDrift(t *testing.T) {
	snap := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}}
	d := Compare(snap, snap)
	if d.HasDrift() {
		t.Fatalf("comparing a snapshot to itself should show no drift, got %+v", d)
	}
	if d.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", d.Unchanged)
	}
}

func TestCompareAddedRecord(t *testing.T) {
	old := Snapshot{Domain: "example.com"}
	next := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}}
	d := Compare(old, next)
	if len(d.Added) != 1 || len(d.Removed) != 0 || len(d.Changed) != 0 {
		t.Fatalf("got %+v", d)
	}
	if !d.HasDrift() {
		t.Errorf("expected drift")
	}
}

func TestCompareRemovedRecord(t *testing.T) {
	old := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}}
	next := Snapshot{Domain: "example.com"}
	d := Compare(old, next)
	if len(d.Removed) != 1 || len(d.Added) != 0 || len(d.Changed) != 0 {
		t.Fatalf("got %+v", d)
	}
}

func TestCompareChangedValues(t *testing.T) {
	old := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}}
	next := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"5.6.7.8"}, TTL: 300},
	}}
	d := Compare(old, next)
	if len(d.Changed) != 1 {
		t.Fatalf("got %+v", d)
	}
	c := d.Changed[0]
	if c.OldValues[0] != "1.2.3.4" || c.NewValues[0] != "5.6.7.8" {
		t.Errorf("unexpected change contents: %+v", c)
	}
}

func TestCompareChangedTTLOnly(t *testing.T) {
	old := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}}
	next := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 30},
	}}
	d := Compare(old, next)
	if len(d.Changed) != 1 {
		t.Fatalf("a TTL-only change should still be reported as changed, got %+v", d)
	}
}

func TestCompareValueOrderIndependent(t *testing.T) {
	old := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4", "5.6.7.8"}, TTL: 300},
	}}
	next := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"5.6.7.8", "1.2.3.4"}, TTL: 300},
	}}
	d := Compare(old, next)
	if d.HasDrift() {
		t.Fatalf("reordered but identical values must not count as drift, got %+v", d)
	}
}

func TestCompareDifferentResolversAndTypesIndependent(t *testing.T) {
	old := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
		{Resolver: "Google", Type: "AAAA", Values: []string{"::1"}, TTL: 300},
	}}
	next := Snapshot{Domain: "example.com", Records: []Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
		{Resolver: "Cloudflare", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}}
	d := Compare(old, next)
	if len(d.Added) != 1 || d.Added[0].Resolver != "Cloudflare" {
		t.Errorf("expected Cloudflare A added, got %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Type != "AAAA" {
		t.Errorf("expected AAAA removed, got %+v", d.Removed)
	}
	if d.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", d.Unchanged)
	}
}

func TestCompareMultipleChangesSortedDeterministically(t *testing.T) {
	old := Snapshot{Records: []Record{
		{Resolver: "Zeta", Type: "A", Values: []string{"1.1.1.1"}},
		{Resolver: "Alpha", Type: "A", Values: []string{"2.2.2.2"}},
	}}
	next := Snapshot{Records: []Record{
		{Resolver: "Zeta", Type: "A", Values: []string{"9.9.9.9"}},
		{Resolver: "Alpha", Type: "A", Values: []string{"8.8.8.8"}},
	}}
	d := Compare(old, next)
	if len(d.Changed) != 2 {
		t.Fatalf("got %+v", d)
	}
	if d.Changed[0].Resolver != "Alpha" || d.Changed[1].Resolver != "Zeta" {
		t.Errorf("expected sorted order Alpha, Zeta; got %s, %s", d.Changed[0].Resolver, d.Changed[1].Resolver)
	}
}
