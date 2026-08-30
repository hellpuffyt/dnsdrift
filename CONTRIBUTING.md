# Contributing

Thanks for considering a contribution to dnsdrift.

## Development setup

Requires Go 1.22+.

```sh
go build ./...
go test ./...
```

## Guidelines

- **No stubs.** Every change should be a real, working implementation.
- **Keep the network isolated.** All DNS querying goes through the
  `resolver.Resolver` interface in `internal/resolver`. Analysis logic in
  `internal/analysis` and `internal/snapshot` must stay pure and offline —
  test it with `resolver.FakeResolver`, never with real DNS.
- **Tests are required** for new behavior. Run the full gate before
  submitting:

  ```sh
  go build ./...
  go vet ./...
  go test ./...
  gofmt -l .   # must print nothing
  ```

- Keep functions small and focused; prefer adding a new pure function over
  growing an existing one.
- Update `CHANGELOG.md` for user-visible changes.

## Reporting issues

Open an issue with the domain/record type/resolver combination that
triggered the problem (redacting anything sensitive) and the exact command
you ran.

## License

By contributing, you agree that your contributions will be licensed under
the MIT License (see `LICENSE`).
