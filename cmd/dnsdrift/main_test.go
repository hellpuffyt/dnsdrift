package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prabeshsharma/dnsdrift/internal/snapshot"
)

// captureOutput runs fn with a pipe wired to *os.File args and returns
// everything written to it as a string, alongside fn's return value.
func captureOutput(t *testing.T, fn func(w *os.File) int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	code := fn(w)
	w.Close()
	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	r.Close()
	return string(buf[:n]), code
}

func TestRunVersion(t *testing.T) {
	out, code := captureOutput(t, func(w *os.File) int { return run([]string{"version"}, w, w) })
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "dnsdrift") {
		t.Errorf("expected version string, got %q", out)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	_, code := captureOutput(t, func(w *os.File) int { return run([]string{"bogus"}, w, w) })
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunNoArgs(t *testing.T) {
	_, code := captureOutput(t, func(w *os.File) int { return run(nil, w, w) })
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunHelp(t *testing.T) {
	out, code := captureOutput(t, func(w *os.File) int { return run([]string{"help"}, w, w) })
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("expected usage text, got %q", out)
	}
}

func TestRunQueryMissingDomain(t *testing.T) {
	_, code := captureOutput(t, func(w *os.File) int { return run([]string{"query"}, w, w) })
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunQueryInvalidTypes(t *testing.T) {
	_, code := captureOutput(t, func(w *os.File) int { return run([]string{"query", "example.com", "--types", "bogus"}, w, w) })
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunQueryEmptyPanel(t *testing.T) {
	_, code := captureOutput(t, func(w *os.File) int {
		return run([]string{"query", "example.com", "--only-resolvers"}, w, w)
	})
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunDiffMissingArgs(t *testing.T) {
	_, code := captureOutput(t, func(w *os.File) int { return run([]string{"diff", "one.json"}, w, w) })
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunDiffMissingFile(t *testing.T) {
	_, code := captureOutput(t, func(w *os.File) int {
		return run([]string{"diff", "nope-old.json", "nope-new.json"}, w, w)
	})
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
}

func TestRunDiffNoDrift(t *testing.T) {
	dir := t.TempDir()
	p1 := writeSnap(t, dir, "old.json", snapshot.Snapshot{Domain: "example.com", Records: []snapshot.Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}})
	p2 := writeSnap(t, dir, "new.json", snapshot.Snapshot{Domain: "example.com", Records: []snapshot.Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}})
	out, code := captureOutput(t, func(w *os.File) int { return run([]string{"diff", p1, p2}, w, w) })
	if code != 0 {
		t.Errorf("exit code = %d, want 0; output: %s", code, out)
	}
	if !strings.Contains(out, "no drift detected") {
		t.Errorf("got %q", out)
	}
}

func TestRunDiffWithDriftAndJSON(t *testing.T) {
	dir := t.TempDir()
	p1 := writeSnap(t, dir, "old.json", snapshot.Snapshot{Domain: "example.com", Records: []snapshot.Record{
		{Resolver: "Google", Type: "A", Values: []string{"1.2.3.4"}, TTL: 300},
	}})
	p2 := writeSnap(t, dir, "new.json", snapshot.Snapshot{Domain: "example.com", Records: []snapshot.Record{
		{Resolver: "Google", Type: "A", Values: []string{"9.9.9.9"}, TTL: 300},
	}})
	out, code := captureOutput(t, func(w *os.File) int { return run([]string{"diff", "--json", p1, p2}, w, w) })
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	var parsed snapshot.Diff
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output was not valid JSON: %v\n%s", err, out)
	}
	if len(parsed.Changed) != 1 {
		t.Errorf("expected 1 changed record, got %+v", parsed)
	}
}

func writeSnap(t *testing.T, dir, name string, snap snapshot.Snapshot) string {
	t.Helper()
	snap.Timestamp = time.Now()
	path := filepath.Join(dir, name)
	if err := snapshot.Save(path, snap); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return path
}
