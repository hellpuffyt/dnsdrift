// Package snapshot implements dnsdrift's drift-over-time feature: saving a
// point-in-time view of a domain's answers to JSON, and diffing two such
// snapshots to report what changed.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// Record is one resolver's answer for one record type, as stored in a
// Snapshot.
type Record struct {
	Resolver string   `json:"resolver"`
	Type     string   `json:"type"`
	Values   []string `json:"values"`
	TTL      uint32   `json:"ttl"`
}

func (r Record) key() string { return r.Resolver + "|" + r.Type }

// Snapshot is a point-in-time capture of a domain's answers across a panel
// of resolvers, suitable for saving to disk and diffing later.
type Snapshot struct {
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
	Records   []Record  `json:"records"`
}

// Save writes snap to path as indented JSON.
func Save(path string, snap Snapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write snapshot %s: %w", path, err)
	}
	return nil
}

// Load reads and parses a Snapshot previously written by Save.
func Load(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	return snap, nil
}

// Change describes a resolver/type pair whose values or TTL differ between
// two snapshots.
type Change struct {
	Resolver  string   `json:"resolver"`
	Type      string   `json:"type"`
	OldValues []string `json:"oldValues"`
	NewValues []string `json:"newValues"`
	OldTTL    uint32   `json:"oldTtl"`
	NewTTL    uint32   `json:"newTtl"`
}

// Diff is the result of comparing two snapshots: entries present only in
// the newer one, entries present only in the older one, and entries present
// in both but with different values.
type Diff struct {
	OldDomain string   `json:"oldDomain"`
	NewDomain string   `json:"newDomain"`
	Added     []Record `json:"added"`
	Removed   []Record `json:"removed"`
	Changed   []Change `json:"changed"`
	Unchanged int      `json:"unchanged"`
}

// HasDrift reports whether the diff contains any additions, removals, or
// changes.
func (d Diff) HasDrift() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0
}

// Compare diffs old against next, keyed by (resolver, record type). A
// record present in both with identical Values (order-independent) and TTL
// is unchanged; identical Values but different TTL still counts as changed,
// since a TTL swing on an otherwise-stable answer is itself signal.
func Compare(old, next Snapshot) Diff {
	oldByKey := map[string]Record{}
	for _, r := range old.Records {
		oldByKey[r.key()] = r
	}
	newByKey := map[string]Record{}
	for _, r := range next.Records {
		newByKey[r.key()] = r
	}

	d := Diff{OldDomain: old.Domain, NewDomain: next.Domain}

	for key, nr := range newByKey {
		or, existed := oldByKey[key]
		if !existed {
			d.Added = append(d.Added, nr)
			continue
		}
		if !sameValues(or.Values, nr.Values) || or.TTL != nr.TTL {
			d.Changed = append(d.Changed, Change{
				Resolver:  nr.Resolver,
				Type:      nr.Type,
				OldValues: or.Values,
				NewValues: nr.Values,
				OldTTL:    or.TTL,
				NewTTL:    nr.TTL,
			})
		} else {
			d.Unchanged++
		}
	}
	for key, or := range oldByKey {
		if _, stillPresent := newByKey[key]; !stillPresent {
			d.Removed = append(d.Removed, or)
		}
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].key() < d.Added[j].key() })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].key() < d.Removed[j].key() })
	sort.Slice(d.Changed, func(i, j int) bool {
		if d.Changed[i].Resolver != d.Changed[j].Resolver {
			return d.Changed[i].Resolver < d.Changed[j].Resolver
		}
		return d.Changed[i].Type < d.Changed[j].Type
	})

	return d
}

func sameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
