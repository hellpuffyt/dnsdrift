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

```sh
go install github.com/prabeshsharma/dnsdrift/cmd/dnsdrift@latest
```

Or build from source:

```sh
git clone https://github.com/prabeshsharma/dnsdrift
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
| 3    | A query or file operation could not complete                   |

## Examples

Query a domain across the default panel for every record type:

```sh
dnsdrift query --types A,NS,SOA example.com
```

```
dnsdrift report for example.com
========================================

A
  all resolvers agree
  [majority]  Cloudflare, Google, OpenDNS, Quad9  93.184.215.14

NS
  all resolvers agree
  [majority]  Cloudflare, Google, OpenDNS, Quad9  a.iana-servers.net, b.iana-servers.net

SOA
  all resolvers agree
  [majority]  Cloudflare, Google, OpenDNS, Quad9  ns.icann.org noc.dns.icann.org 2019...

Health findings: none
```

A disagreement, with the propagation/misconfiguration verdict shown per
resolver:

```
AAAA
  DISAGREEMENT
  [majority]  Cloudflare, Google, OpenDNS  2606:2800:220:1:248:1893:25c8:1946
  [minority]  Quad9                        2606:2800:220:1:248:1893:25c8:1900
  Quad9: propagating -- resolver holds an older SOA serial and its cached answer's TTL has not expired; expected to converge
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

```
dnsdrift snapshot diff: example.com -> example.com
========================================
~ Google A: 93.184.215.14 (ttl 3600s) -> 93.184.216.34 (ttl 3600s)
```

Use it as a CI gate (fails the build on disagreement or findings):

```sh
dnsdrift query mycompany.com --types A,MX || exit 1
```

## Findings reference

| Code                    | Severity | Meaning                                                                |
| ------------------------ | -------- | ------------------------------------------------------------------------ |
| `no-ns-records`            | error    | No NS records found; the zone is not delegated or is unresolvable         |
| `single-ns-record`         | warning  | Only one NS record; no redundancy if it becomes unreachable               |
| `soa-serial-mismatch`      | error    | Resolvers/authoritative sources disagree on the SOA serial                |
| `ttl-too-low`              | warning  | TTL below 60s; can overload authoritative/resolver infrastructure         |
| `ttl-too-high`             | warning  | TTL above 7 days; future changes will take a long time to converge        |
| `cname-at-apex`            | error    | A CNAME record exists at the zone apex, which is invalid                  |
| `dangling-cname`           | error    | A CNAME's target does not resolve; possible subdomain takeover risk       |

## Testing

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .   # must print nothing
```

All analysis, consensus, verdict, health-check, and snapshot-diff logic is
tested offline using `resolver.FakeResolver` — no test depends on real DNS.

## Security

- dnsdrift only performs DNS lookups (UDP/TCP to port 53); it makes no other
  network calls and stores no credentials.
- Snapshot JSON files contain only DNS record data (IPs, hostnames, TXT
  content, TTLs, serials) for the domain you queried — review before sharing
  if your TXT records contain sensitive values (e.g. verification tokens).
- If you report a security issue, please open an issue describing it without
  including unrelated sensitive data.

## License

MIT — see [LICENSE](LICENSE).
