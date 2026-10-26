# slog adapter (nested module)

This directory is a **separate, nested Go module** (`logger/adapters/slog`) with
its own `go.mod` declaring `go 1.21`. It is intentionally **not published** as
an independently importable module.

## Why a nested module

`log/slog` is a Go 1.21 standard library package. The main SDK module locks
its floor at **Go 1.18** to honor the version it promises to consumers. Putting
the slog adapter in a nested sub-module lets it declare `go 1.21` without
raising the main module's floor — the sub-directory does not participate in the
main module's `go build ./...`. This is the same pattern used by `grpc-go` and
`opentelemetry-go` for stdlib-version-gated adapters.

## Why `require ... v0.0.0`

The `require github.com/cloud-idaas/idaas-go-core-sdk v0.0.0` plus
`replace github.com/cloud-idaas/idaas-go-core-sdk => ../.././` is deliberate:

- The `replace` points at the working copy in the repository root, so the
  adapter always builds against the current source — it never waits for a main
  module release.
- `v0.0.0` is a placeholder that exists only to satisfy `go mod` syntax. The
  module is **never tagged or published**: external consumers cannot and should
  not `go get github.com/cloud-idaas/idaas-go-core-sdk/logger/adapters/slog`.

## For external consumers

If you need a slog adapter for the SDK, **copy `adapter.go` into your own
project** (adjusting the import path) rather than attempting to import this
nested module. The adapter is small and self-contained by design.
