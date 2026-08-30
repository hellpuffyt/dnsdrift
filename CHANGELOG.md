# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
