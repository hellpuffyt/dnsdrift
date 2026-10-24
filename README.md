# dnsdrift

Detect DNS record drift across resolvers and over time, and tell the
difference between ordinary propagation lag and a genuine misconfiguration.

## What

`dnsdrift` queries a domain against many public DNS resolvers concurrently,
compares the answers, and explains any disagreement instead of just listing
it. It also snapshots a query to disk so you can diff two points in time and
see exactly what changed.

## Why

After a DNS change, "has it propagated?" usually gets answered by refreshing
a browser tab and guessing. That tells you nothing about *why* one place
sees the new answer and another doesn't, and it can't distinguish a change
still spreading through caches from a resolver that is stuck, misconfigured,
or serving stale split-horizon data indefinitely. `dnsdrift` queries the
panel in parallel, groups the answers, and — using each resolver's reported
TTL and SOA serial — reasons about whether a disagreement is expected to
resolve itself or is a real fault worth investigating.

## Features

- **Concurrent multi-resolver queries** across Google, Cloudflare, Quad9,
  OpenDNS, and any resolvers you add, for A, AAAA, CNAME, MX, TXT, NS, and
  SOA records.
- **Consensus analysis**: resolvers are grouped by their answer; the
  majority group and every disagreeing minority are shown explicitly, not
  buried in a flat list.
- **Propagation vs. misconfiguration verdicts** (the differentiator): for
  every resolver that disagrees with the majority, dnsdrift compares its SOA
  serial against the highest serial seen on the panel and looks at whether
  its TTL has expired:
  - Behind on serial, TTL still running → **propagating** (expected to
    converge on its own).
  - Behind on serial, TTL already expired → **misconfigured** (it should
    have refreshed by now and hasn't).
  - Reports the same/newer serial as the majority yet still disagrees →
    **misconfigured** (not explainable by lag at all).
  - No SOA data available for that resolver → **unknown**.
- **Snapshot and diff**: `--save` writes a query's results to JSON;
  `dnsdrift diff old.json new.json` reports additions, removals, and changes
  between two snapshots — the drift-over-time half of the tool.
- **Health findings**: no NS records, a single NS record (no redundancy),
  SOA serial mismatch, implausibly low/high TTL, CNAME at the zone apex, and
  dangling CNAME targets (subdomain takeover risk).
- **Human table or `--json`** output, and a non-zero exit code on
  disagreement or findings for use as a CI gate.

## Architecture

```
cmd/dnsdrift        CLI: flag parsing, orchestration, exit codes
internal/resolver    Resolver interface + real (miekg/dns) and fake implementations
internal/query       Concurrent fan-out across a panel of resolvers
internal/analysis    Consensus grouping, propagation/misconfig verdicts, health checks (pure, offline)
internal/snapshot    Save/load/diff of point-in-time JSON snapshots
internal/output      Table and JSON rendering
```

The important boundary is `resolver.Resolver`: it is the *only* thing that
touches the network. Everything above it — consensus grouping, the
propagation-vs-misconfiguration heuristic, health checks, and snapshot
diffing — is pure functions over plain data, exercised in tests with
`resolver.FakeResolver`. CI never depends on real DNS to validate that logic.

**Why `github.com/miekg/dns` instead of the stdlib `net` package**: the
propagation-vs-misconfiguration verdict depends on the raw TTL and SOA
serial of each answer, and on querying a *specific* resolver rather than
the OS's configured one. `net.LookupHost` and friends go through the local
resolver and return only resolved values — no TTL, no SOA, no choice of
upstream server. `miekg/dns` gives wire-level access to exactly the fields
this tool's core feature needs.

## Installation

Requires Go 1.26+ (the module's `go` directive; older toolchains refuse to
build it).

```sh
go install github.com/hellpuffyt/dnsdrift/cmd/dnsdrift@latest
```

Or build from source:

```sh
git clone https://github.com/hellpuffyt/dnsdrift
cd dnsdrift
go build -o dnsdrift ./cmd/dnsdrift
```

## Usage

```
dnsdrift query <domain> [flags]
dnsdrift diff <old-snapshot.json> <new-snapshot.json> [flags]
dnsdrift version
```

### Query flags

| Flag                | Description                                                        |
| -------------------- | ------------------------------------------------------------------ |
| `--types`             | Comma-separated record types (`A,AAAA,CNAME,MX,TXT,NS,SOA`); default: all |
| `--resolvers`          | Extra resolvers as `Name=host[:port]`, comma-separated               |
| `--only-resolvers`     | Use only `--resolvers`, skipping the built-in public panel           |
| `--timeout`            | Per-query timeout (default `5s`)                                     |
| `--save`               | Save this query's results as a JSON snapshot to the given path       |
| `--json`               | Emit JSON instead of a table                                         |

### Diff flags

| Flag     | Description                     |
| -------- | -------------------------------- |
| `--json` | Emit JSON instead of a table     |

### Exit codes

| Code | Meaning                                                     |
| ---- | ------------------------------------------------------------ |
| 0    | Full agreement across resolvers, no health findings           |
| 1    | Disagreement between resolvers, or at least one health finding, or a snapshot diff found drift |
| 2    | Usage error (bad flags/arguments)                              |
| 3    | No resolver answered any query, or a file operation could not complete |

## Examples

Query a domain across the default panel for every record type:

```sh
dnsdrift query --types A,NS,SOA example.com
```

Output captured on 2026-10-22 (exit code 0):

```
dnsdrift report for example.com
========================================

A
  all resolvers agree
  [majority]  Cloudflare, Google, OpenDNS, Quad9  104.20.23.154, 172.66.147.243

NS
  all resolvers agree
  [majority]  Cloudflare, Google, OpenDNS, Quad9  elliott.ns.cloudflare.com, hera.ns.cloudflare.com

SOA
  all resolvers agree
  [majority]  Cloudflare, Google, OpenDNS, Quad9  elliott.ns.cloudflare.com dns.cloudflare.com 2418004112

Health findings: none
```

A disagreement, with the propagation/misconfiguration verdict shown per
resolver. This run used three local test DNS servers (one still serving
the previous zone serial) via `--only-resolvers --resolvers`, as the
end-to-end tests do; exit code 1:

```
dnsdrift report for example.test
========================================

A
  DISAGREEMENT
  [minority]  Stale           192.0.2.10
  [majority]  Fresh1, Fresh2  192.0.2.99
  Stale: propagating -- resolver holds an older SOA serial and its cached answer's TTL has not expired; expected to converge

Health findings
  [ERROR] soa-serial-mismatch: SOA serials differ across sources (Fresh1=2024010102, Fresh2=2024010102, Stale=2024010101); either a change is still propagating through resolver caches or the zone's nameservers are out of sync
```

Add a custom resolver and use it exclusively:

```sh
dnsdrift query --only-resolvers --resolvers "Home=192.168.1.1" example.com
```

Snapshot a query, make a change, snapshot again, and diff:

```sh
dnsdrift query example.com --save before.json
# ... make a DNS change ...
dnsdrift query example.com --save after.json
dnsdrift diff before.json after.json
```

Real output from the local test server after changing the A record
(exit code 1):

```
dnsdrift snapshot diff: example.test -> example.test
========================================
~ Local A: 192.0.2.10 (ttl 300s) -> 192.0.2.99 (ttl 300s)
```

Only changed record values count as drift. A TTL-only difference does not:
public resolvers report the time left in their cache, which counts down
between any two snapshots.

Use it as a CI gate (fails the build on disagreement or findings):

```sh
dnsdrift query mycompany.com --types A,MX || exit 1
```

## Findings reference

| Code                    | Severity | Meaning                                                                |
| ------------------------ | -------- | ------------------------------------------------------------------------ |
| `no-ns-records`            | error    | No NS records found at the zone apex (checked only when NS is queried and the name is the apex) |
| `single-ns-record`         | warning  | Only one NS record; no redundancy if it becomes unreachable               |
| `soa-serial-mismatch`      | error    | Resolvers in the panel report different SOA serials (propagation in progress, or nameservers out of sync) |
| `ttl-too-low`              | warning  | Largest observed A TTL below 60s; can overload authoritative/resolver infrastructure |
| `ttl-too-high`             | warning  | TTL above 7 days; future changes will take a long time to converge        |
| `cname-at-apex`            | error    | A CNAME record exists at the zone apex (apex taken from the SOA answers; never assumed) |
| `dangling-cname`           | error    | A CNAME's target has neither A nor AAAA records; possible subdomain takeover risk |

## Testing

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .   # must print nothing
```

All analysis, consensus, verdict, health-check, and snapshot-diff logic is
tested offline using `resolver.FakeResolver`. The real resolver and the CLI
are tested end to end against small DNS servers started on 127.0.0.1
(`internal/dnstest`): every record type, truncation with TCP retry,
NXDOMAIN, timeouts, disagreement verdicts, health findings, exit codes and
snapshot diffs. `go test ./...` never contacts public DNS.

One live test queries the built-in public panel; it is skipped unless you
opt in:

```sh
DNSDRIFT_LIVE=1 go test -run TestLivePublicResolvers -v ./internal/resolver/
```

## Security

- dnsdrift only performs DNS lookups (UDP/TCP to port 53); it makes no other
  network calls and stores no credentials.
- Snapshot JSON files contain only DNS record data (IPs, hostnames, TXT
  content, TTLs, serials) for the domain you queried — review before sharing
  if your TXT records contain sensitive values (e.g. verification tokens).
- Report security issues privately at
  https://github.com/hellpuffyt/dnsdrift/security/advisories/new (see
  [SECURITY.md](SECURITY.md)).

## Limitations

- The propagation/misconfiguration verdict is a heuristic over the SOA
  serial and the *remaining* cache TTL each resolver reports; it cannot see
  a resolver's cache policy.
- Resolvers that apply filtering (e.g. OpenDNS) or geo-aware answers can
  legitimately disagree; dnsdrift reports that as disagreement.
- No DNSSEC validation; answers are taken as returned.
- Two resolvers given the same name collide in snapshots.
- Public resolvers must be reachable on UDP/TCP 53 from where you run it;
  with no answers at all the exit code is 3.

See [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) for the
audit evidence.

## License

MIT — see [LICENSE](LICENSE).
