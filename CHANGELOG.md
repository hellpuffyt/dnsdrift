# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- Module path is `github.com/hellpuffyt/dnsdrift`; the README's
  `go install` and clone URLs pointed at a repository that does not exist.
- False `no-ns-records` errors when NS was not in `--types` or the name
  was below the zone apex.
- False `cname-at-apex` errors on CNAME'd subdomains (an unknown zone was
  assumed to be the queried name); the apex now comes from the companion
  SOA answers, including the authority section for names below the apex.
- SOA serials for names below the apex were never collected (they arrive in
  the authority section), so every subdomain verdict was `unknown`.
- False `dangling-cname` for targets with only AAAA records.
- `ttl-too-low` uses the largest observed TTL instead of the first
  resolver's remaining cache TTL.
- `diff` no longer reports drift for a TTL that merely counted down.
- Exit code 3 when no resolver answered any query (was 1).
- `--resolvers` accepts bare IPv6 addresses.
- Data race in `FakeResolver` under concurrent queries.

### Added

- Loopback DNS test server (`internal/dnstest`) and end-to-end tests for
  the real resolver and the CLI; an opt-in live test (`DNSDRIFT_LIVE=1`).

## [0.1.0] - 2026-08-30

### Added

- Concurrent querying of a domain across a panel of public resolvers (Google,
  Cloudflare, Quad9, OpenDNS) plus user-supplied resolvers, for A, AAAA,
  CNAME, MX, TXT, NS, and SOA records.
- Consensus analysis that groups resolvers by agreement and identifies the
  majority answer versus disagreeing minorities.
- Propagation-vs-misconfiguration verdicts using SOA serial and TTL
  comparison to explain *why* resolvers disagree.
- Health findings: no NS records, single NS, SOA serial mismatch, TTL too
  low/high, CNAME at apex, dangling CNAME.
- Snapshot save (`--save`) and `dnsdrift diff` to compare two point-in-time
  snapshots and report additions, removals, and changes.
- Human-readable table output and `--json` machine-readable output.
- Non-zero exit codes on disagreement or health findings, for CI use.
