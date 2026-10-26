## Summary

<!-- What does this PR change, and why? Reference any related issue ("Closes #123"). -->

## Changes

<!-- Bullet list of the meaningful changes. -->

## Tests

<!-- How did you verify this change? -->

- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] `gofmt -l .` (excluding `samples/`) is empty
- [ ] `go test -race ./...` passes
- [ ] New / changed behavior covered by tests
- [ ] No internal traceability markers (V##/R-##/NF-.../P#-#) introduced in non-test code

## Checklist

- [ ] No real credentials, tokens, client secrets, private keys, or internal endpoints committed (use `example.com` placeholders)
- [ ] Public API changes are documented in `CHANGELOG.md` under `[Unreleased]`
- [ ] Backward-compatible where possible (v0.x beta — breaking changes must be called out explicitly)
- [ ] Comments use the SDK's idiom and do not leak internal review/design markers
