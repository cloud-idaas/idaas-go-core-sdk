# Contributing to IDaaS Go Core SDK

Thank you for your interest in contributing to the IDaaS Go Core SDK! This document outlines the process for contributing bug reports, feature requests, and code changes.

## Prerequisites

- Go 1.18 or above (the SDK targets Go 1.18 as the minimum version)
- `golangci-lint` (latest stable)
- Git

## Development Setup

```bash
# Clone the repository
git clone https://github.com/cloud-idaas/idaas-go-core-sdk.git
cd idaas-go-core-sdk

# Verify the build
go build ./...

# Run tests with race detector
go test -race ./...

# Run linter
golangci-lint run
```

## Code Style

1. **gofmt**: All code must be formatted with `gofmt`. CI will reject unformatted code.
2. **golangci-lint**: All lint checks must pass. See `.golangci.yml` for configuration.
3. **Go conventions**: Follow [Effective Go](https://go.dev/doc/effective_go) and the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

## Pull Request Process

1. **Fork & Branch**: Fork the repository and create a feature branch from `main`.
2. **Write Tests**: All new functionality must include tests. Aim for meaningful coverage of the code paths you add.
3. **Run Checks**: Before submitting, ensure the following pass:
   ```bash
   go build ./...
   go vet ./...
   go test -race ./...
   golangci-lint run
   ```
4. **Commit Messages**: Use clear, descriptive commit messages. Reference issues with `#issue-number`.
5. **Pull Request Description**: Describe what changed and why. Include any breaking changes.

## Testing Guidelines

- Use table-driven tests where appropriate.
- Test both success and error paths.
- For concurrency-related code, include `-race` compatible tests.
- Mock external dependencies (HTTP endpoints, file system) rather than relying on real services.

## Code Review Criteria

Reviewers will check for:

- **Correctness**: Logic is correct and handles edge cases.
- **Security**: No secrets in code/logs, TLS is not disabled by default, sensitive data is redacted.
- **Concurrency**: Proper lock usage, no goroutine leaks, context propagation.
- **Error Handling**: Errors are wrapped with context, not silently swallowed.
- **API Stability**: Public API changes are documented and backward-compatible where possible.

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.** Instead, report them privately via [GitHub Security Advisories](https://github.com/cloud-idaas/idaas-go-core-sdk/security/advisories/new) with details. We will respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
