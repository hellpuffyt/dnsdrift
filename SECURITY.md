# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's advisory form:
https://github.com/hellpuffyt/dnsdrift/security/advisories/new

Include the dnsdrift version (`dnsdrift version`), the command line, and
what you observed. Please do not open a public issue for a suspected
vulnerability.

## Security model

- dnsdrift sends DNS queries (UDP, with TCP retry on truncation) to the
  built-in public resolvers and to any resolvers you pass with
  `--resolvers`. It makes no other network connections.
- Answers are untrusted data: they are parsed by `github.com/miekg/dns`,
  compared as strings and printed; nothing in an answer is executed or
  used to open files.
- No DNSSEC validation is performed; a resolver on the path can return
  forged data, which dnsdrift will report as an answer (and as a
  disagreement if other resolvers differ).
- Snapshot files contain record data (including TXT content) for the
  queried name; treat them like any other export of your DNS data.

Only the latest release receives fixes.
