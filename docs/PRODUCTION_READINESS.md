# Production readiness — dnsdrift

Audit of the `audit/production-readiness` branch. Evidence only; the
classification at the end is a proposal for the maintainer to confirm.

- Tested commit: `5efb674cfcbae0e925fa4a3086b2cc5617bfe28a` (this file was
  added in the next commit and changes no code)
- Date: 2026-10-22
- Host: macOS 27 (Apple Silicon), Go 1.27.3. `go.mod` declares `go 1.22`.

## Scope

A CLI that queries one name across a panel of DNS resolvers (four public
ones plus any given with `--resolvers`), groups the answers, explains each
disagreement as propagating / misconfigured / unknown from SOA serials and
remaining TTLs, runs a handful of health checks, and saves / diffs JSON
snapshots. Wire access through `github.com/miekg/dns`.

## Platforms and prerequisites

- Go 1.22+. Verified locally on macOS arm64.
- CI: Go 1.22/1.23 on ubuntu and Windows, Go 1.23 on macOS; not yet run on
  this branch.
- `go test ./...` needs no network: DNS behaviour is tested against servers
  on 127.0.0.1 (`internal/dnstest`). `TestLivePublicResolvers` is the only
  test that uses public DNS; it is skipped unless `DNSDRIFT_LIVE=1`. The CI
  `smoke` job (a real query) is separate from the test job.

## Clean-clone verification

Fresh clone of the branch into an empty scratch directory; README "Build
from source", "Testing" and "Examples" followed literally:

| Command | Exit | Result |
|---|---|---|
| `go build -o dnsdrift ./cmd/dnsdrift`, `go build ./...`, `go vet ./...` | 0 | |
| `go test ./...` | 0 | 115 passed, 0 failed, 1 skipped (`TestLivePublicResolvers`, opt-in) |
| `go test -race ./...` | 0 | |
| `gofmt -l .` | 0 | no output |
| `DNSDRIFT_LIVE=1 go test -run TestLivePublicResolvers -v ./internal/resolver/` | 0 | passed against Google, Cloudflare, Quad9, OpenDNS |
| `./dnsdrift query --types A,NS,SOA example.com` | 0 | all resolvers agree; `Health findings: none` |
| `query example.com --types A --save before.json` / `after.json`, then `diff` | 0 | `no drift detected` (before the fix the TTL countdown made this exit 1) |
| `./dnsdrift version` | 0 | `dnsdrift 0.1.0` |

## Commands executed (working clone)

| Command | Exit | Outcome |
|---|---|---|
| `go test -count=1 -v ./...` (baseline) | 0 | 103 passed, 0 failed, 0 skipped |
| `go test -race -count=1 -v ./...` (baseline) | 1 | 102 passed, 1 failed (`TestRunPanelCollectsPerResolverAnswers`: data race in `FakeResolver`) |
| `go test -race -count=1 ./...` (after) | 0 | all packages ok |
| `go run honnef.co/go/tools/cmd/staticcheck@latest ./...` (v0.8.2) | 0 | after replacing three `nil` contexts in tests (SA1012) |
| `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` (v1.9.0) | 0 | no reachable vulnerabilities; 19 advisories in required modules (`golang.org/x/net` v0.27.0, `golang.org/x/sys` v0.22.0) that the code does not call |
| `go mod verify` | 0 | all modules verified |
| `go run github.com/zricethezav/gitleaks/v8@latest git --redact .` | 0 | no leaks in any commit |

The new end-to-end tests were run against the pre-fix code and failed
there (`no-ns-records,cname-at-apex` on `www`, exit 1 instead of 3, TTL
countdown reported as drift).

## CI status

- Default branch (`main`): last run `success`.
- Audit branch: pending until pushed. CI runs `go test` without `-race`,
  which is why the `FakeResolver` race was not caught there.

## Bugs found and fixed

| # | Severity | Bug | Fix | Regression test |
|---|---|---|---|---|
| 1 | High (install broken) | Module path and README URLs pointed at `github.com/prabeshsharma/dnsdrift`, which does not exist. | Module path `github.com/hellpuffyt/dnsdrift`. | build, clean clone |
| 2 | Medium | Data race in the exported `FakeResolver` (concurrent `Calls` appends); a test failed under `-race`. | Mutex. | `TestRunPanelCollectsPerResolverAnswers` under `-race` |
| 3 | High (wrong result) | `no-ns-records` (error, exit 1) whenever NS was not in `--types` — e.g. the README's own CI-gate example `--types A,MX` — and for every name below the apex. | NS check only at the apex with NS queried. | `TestBuildHealthInputSkipsNSCheckWhenNotApplicable`, `TestE2ECNAMEOnSubdomainIsHealthy` |
| 4 | High (wrong result) | `cname-at-apex` for CNAME'd subdomains: with no SOA in the output types the queried name was assumed to be the apex. | Zone from the companion SOA answers; unknown zone never treated as apex. | `TestBuildHealthInputSubdomainIsNotApex`, `TestE2ECNAMEOnSubdomainIsHealthy` |
| 5 | Medium | SOA for names below the apex (authority section) was ignored, so all subdomain verdicts were `unknown`. | Read the authority-section SOA. | `TestDNSResolverTakesSOAFromAuthoritySection` |
| 6 | Medium | Snapshot diff treated the cache TTL counting down as drift: diffing an unchanged domain always exited 1. | Only value changes are drift. One existing test expectation changed (justified in the test). | `TestCompareTTLOnlyDifferenceIsNotDrift`, `TestE2ESnapshotDiffIgnoresTTLCountdownButSeesChanges` |
| 7 | Low | `dangling-cname` for IPv6-only targets. | Try A then AAAA. | `TestE2ECNAMEOnSubdomainIsHealthy` (`v6.example.test`) |
| 8 | Low | `ttl-too-low` from whichever resolver came first (its remaining cache TTL). | Largest observed TTL. Existing `firstTTL` test replaced. | `TestObservedTTLSkipsErrorsAndTakesMax` |
| 9 | Low | Exit 1 instead of the documented 3 when no resolver answered. | Exit 3. | `TestE2ENoResolverAnswersExitsThree` |
| 10 | Low | `--resolvers Name=::1` produced an invalid address. | `net.JoinHostPort`. | `TestParseExtraResolversIPv6AndPorts` |
| 11 | Docs | `soa-serial-mismatch` claimed the serials came from authoritative nameservers; README example outputs were not from real runs. | Message and README corrected; examples replaced with captured output. | — |

Coverage added: the real `DNSResolver` had no tests; it is now tested
against loopback servers (all record types, min TTL, NXDOMAIN, truncation
→ TCP retry, timeout), and the CLI end to end (agreement, propagating
verdict, findings, exit codes, snapshots).

## Security review

- Network: DNS only, to the panel and `--resolvers`. Answers are parsed by
  miekg/dns and treated as data.
- No DNSSEC validation (documented in `SECURITY.md` and README).
- Dependencies: no reachable advisories; module-level advisories in
  `golang.org/x/net`/`x/sys` remain. Fixing them needs `x/net` ≥ v0.60.0,
  which raises the minimum Go version above the 1.22 the CI matrix tests,
  so the upgrade is left to the maintainer.
- Secrets: none in tree or history.
- Added `SECURITY.md`; README no longer asks for public issue reports.

## Known limitations

- Verdicts are heuristics over SOA serial and remaining cache TTL.
- Filtering or geo-aware resolvers legitimately disagree.
- Resolver name collisions in snapshots.
- Linux/Windows rely on CI.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| Install / build | README steps work | clean clone | pass | | `go.mod` |
| Real resolver | All 7 types parsed, TCP retry, timeouts | `dns_resolver_test.go` (loopback) | pass | | `dns_resolver.go` |
| Consensus | Majority/minority groups | `consensus_test.go`, `TestE2EAgreementExitsZero` | pass | | `consensus.go` |
| Verdicts | Stale serial + live TTL → propagating | `consensus_test.go`, `TestE2EDisagreementGetsPropagatingVerdict` | pass | `Stale: propagating` | `consensus.go` |
| Health findings | No false positives on subdomains / partial `--types`; real problems found | `TestE2ECNAMEOnSubdomainIsHealthy`, `health_test.go` | pass | `dangling-cname` only for the dangling name | `health.go`, `helpers.go` |
| Snapshot diff | Value change = drift; TTL countdown ≠ drift | `TestE2ESnapshotDiff…`, clean-clone diff | pass | `no drift detected` / `~ Local A: …` | `snapshot.go` |
| Exit codes | 0 / 1 / 2 / 3 as documented | CLI tests | pass | | `main.go` |
| Offline tests | No public DNS without opt-in | test review; live test skipped by default | pass | 1 skip | `live_test.go` |
| Live path | Public panel answers | `DNSDRIFT_LIVE=1` run | pass | 4/4 resolvers | |
| Static analysis | vet, staticcheck, govulncheck (reachable) clean | above | pass | | |

## Classification proposal

**Partially Verified** — every documented feature now has passing tests
(including end to end against local DNS servers) and the live path was
exercised once, but the CI matrix has not run on this branch and the
required `golang.org/x/net` version carries unreachable advisories that
need a Go-version decision from the maintainer.
