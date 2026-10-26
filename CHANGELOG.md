# Changelog

All notable changes to the IDaaS Go Core SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `factory.WithHttpClient` option to inject a custom `http.HttpClient` (note: `Reset` clears the injected client)
- `factory.WithTracePropagator` option + `http.TracePropagator` / `http.HeaderCarrier` interfaces to inject distributed trace context (W3C TraceContext) into outbound requests to token endpoint / IMDS / OIDC provider; the SDK does not vendor OTel (host injects via a one-line adapter); default nil = no injection
- Error code `constants.OidcTokenFilePathNotFound`, returned when `clientDeployEnvironment=COMPUTER` has no OIDC token file path configured
- Apache 2.0 LICENSE file for open-source release
- `.golangci.yml` lint configuration with errcheck, govet, staticcheck, revive, gocritic
- `CONTRIBUTING.md` contributor guide
- `CHANGELOG.md` (this file)
- Shared HTTP timeout constants (`constants.DefaultConnectTimeoutMs`, `constants.DefaultReadTimeoutMs`) as single source of truth for config and http packages
- Comprehensive test suite for `http/default_http_client.go` (32 test functions covering constructors, Execute/ExecuteContext, TLS configuration, error classification, context cancellation, and edge cases)
- Moved `implementation/` to `internal/implementation/` to enforce Go's internal package visibility rules — prevents external consumers from importing implementation details directly
- `config.IDaaSClientConfig.StaleValueBehavior` field (`staleValueBehavior`, omitempty) controlling cache behavior when a credential enters the stale window; empty normalizes to `Refresh` (preserves beta default). Validated by `config_validator.go` with new error code `constants.InvalidStaleValueBehavior`
- `SECURITY.md` security policy (private disclosure via GitHub Security Advisories, 48h response, supported-versions table)
- `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1)
- `.github/ISSUE_TEMPLATE/` (bug report, feature request, config) and `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/workflows/release.yml` — tag-driven (`v*`) GitHub Release with version-stamped sample binary
- `logger/adapters/slog/README.md` documenting the by-design `v0.0.0` nested module (not published; copy the adapter into your project)
- `samples/idaas-config.example.json` template (moved from repo-root `idaas-config.json`; endpoints use `example.com` placeholders)

### Changed

- `DefaultConfigPath` now uses `os.UserHomeDir()` instead of `os.Getenv("HOME")` for cross-platform home directory resolution (fixes invalid path on Windows / containers / systemd)
- `human_federated_oidc_provider.go` replaced all `log.Printf` calls with SDK `logger.Default()` to ensure log redaction (`RedactKV`) is applied consistently
- `getPrivateKeyJwtCredential` now reuses `loadPrivateKeyFromEnv` (shared with `getPcaCredential`) to eliminate duplicated env-var-read + PEM-parse logic
- `requestIdFromChain` now has a depth guard (max 64) to prevent infinite recursion from self-referential Unwrap chains
- Factory write-lock patterns in `createCredentialProviderByScope` and `createTokenExchangeProviderByScope` converted from manual `Unlock` to `defer` for deadlock safety
- `samples/obtain-token/main.go` now uses public factory API (`InitWithConfig` / `GetIDaaSCredentialProvider` / `Reset`) instead of directly importing `implementation` package
- CI coverage gate raised to 90% (matches measured line coverage)
- `.golangci.yml` now enables `forbidigo` so that internal issue identifiers cannot leak into source comments; deprecated `structcheck`/`deadcode`/`varcheck` entries removed from `disable`
- `golangci-lint-action` version pinned to `v1.62.0` (was `latest`) for reproducible lint
- CI adds `gitleaks` secret-scan job and an `integration` test job (`-tags=integration`, skips on missing credentials)
- `.gitignore` ignores `*.env` / `credentials.env` (env-var secret files)
- Repo-root `idaas-config.json` moved to `samples/idaas-config.example.json`; `developerApiEndpoint` changed to `developerapi.example.com` placeholder
- `ClientDeployEnvironmentAwsEsk` / `"AWS_ESK"` renamed to `ClientDeployEnvironmentAwsEks` / `"AWS_EKS"` (correcting the transposed-letter typo of AWS **EKS**, Elastic Kubernetes Service). The value is currently unsupported (returns `UnsupportedClientDeployEnvironment`), so no working config is affected. Java/Python SDKs still carry the `"AWS_ESK"` typo and are pending upstream sync; the Go parity comment now documents this divergence

### Fixed

- **Endpoint normalization now accepts bare hosts** (`eiam.cn-hangzhou.aliyuncs.com`) and auto-prefixes them with `https://`, aligning with the Java SDK (`NormalizeUtil.convertHttps`) and Python SDK (`NormalizeUtil._convert_to_https`). Previously `factory.Init` rejected the bare-host `openApiEndpoint` / `developerApiEndpoint` form used by the SDK's own config templates and README examples with `InvalidEndpointScheme`, breaking config compatibility for existing deployments and POP-style endpoint conventions. Explicit illegal schemes (`ftp://`, `ws://`, …) are still rejected; the `allowInsecureEndpoint` escape hatch semantics are unchanged (bare hosts always normalize to `https://`, never `http://`)
- RFC 8693 token exchange now rejects a blank `subject_token` **client-side** with error code `SubjectTokenNotFound` (a REQUIRED parameter per the spec) instead of sending `subject_token=` over the wire — one less round trip, and negative behavior no longer depends on whether the IdP validates strictly
- `run-integration-item-by-item.sh`: a FAIL now prints the test's own assertion message when no masked `code=` line exists, so matrix output is self-diagnostic
- `CachedResultSupplier`: a panic in a synchronous refresh no longer leaves the in-flight call open forever (all later callers used to block); the panic is converted to `UnexpectedError`
- `CachedResultSupplier`: callers waiting on an in-flight refresh now honor their `ctx` and fall back to the cached value after `refreshLockWait`
- `CachedResultSupplier`: after a failed refresh during the stale / expired window, retries back off for 10s instead of hitting the IdP on every call; refresh failures are logged only when falling back to a cached value or in async refresh (no per-request WARN storm)
- Async refresh timeout raised from 5s to 2min so it no longer truncates legitimate slow requests (read timeout can be up to 60s)
- Deprecated `CreateCredentialProvider` no longer panics with a nil dereference when the factory is not initialized; it returns the not-initialized error
- `Initialize` is safe under concurrent first calls (first wins, later calls are idempotent no-ops)
- Token-exchange providers created with an empty scope now share the cache key of the configured default scope
- Missing X.509 client certificate now uses `constants.ClientX509CertificateNotFound` instead of a string literal
- `util/browser_util.go`: `fmt.Errorf` uses `%w` instead of `%v` to preserve `errors.Is` / `errors.As` chain
- Deduplicated HTTP timeout constants between `config/http_config.go` and `http/default_http_client.go`
- `secureCheckRedirect` now strips the request body, `Content-Type`, `Authorization`, and `Cookie` when an HTTP redirect crosses hosts — prevents `client_secret`/token replay to an attacker-controlled host
- Human-credential cache file path now includes `instanceId` (`~/.cloud_idaas/human-cache/{instanceId}_{clientId}.json`), isolating caches per IDaaS instance; empty `instanceId` falls back to the legacy `{clientId}.json` for compatibility
- `util.OpenBrowser` only opens `http`/`https` URLs; other schemes are rejected, blocking crafted-URL browser-launch injection

### Removed

- Unused exported constants: `GrantTypeAuthorizationCode`, `JVMConfigPathKey`, `ParamRedirectURI`, `ParamState`, `ParamCode`, `ParamResource`, `ParamAudience`, `ContentTypeRaw`
- Unused error codes: `HumanAuthenticateClientIdNotFound`, `HumanAuthenticateScopeNotFound`, `DeveloperApiEndpointNotFound`, `NotSupportedWebKey`, `IdTokenNotFound`, `RefreshTokenNotFound`, `InvalidRequest`, `UnsupportedOpenApiType`

### Breaking Changes

- **`NewRefreshResult` signature changed**: now returns `(RefreshResult[T], error)` and rejects `expires_in <= 0` with `InvalidExpiresIn`.
- **HTTP error classification**: `context.Canceled` and unknown body-read errors are now `ClientError` (previously `ReadTimeOut`); `context.DeadlineExceeded` remains `ReadTimeOut`. Callers that retry based on error code may behave differently.
- **`implementation` package moved to `internal/implementation`**: it can no longer be imported by external modules.
- **HUMAN identity defaults**: an empty `humanAuthenticateClientId` falls back to `constants.DefaultHumanAuthenticateClientId`; `deviceAuthorizationEndpoint` is required for `identityType=HUMAN`.
- **`token_type` must be `Bearer`** (case-insensitive): token responses with any other type are rejected by `ValidateLocalToken`.
- **HTTP timeouts are in milliseconds** (`connectTimeout` / `readTimeout`, each capped at 60s).
- **`Initialize` no longer mutates the caller's `*IDaaSClientConfig`**: defaults are applied to an internal copy; use `GetConfig()` to read the effective configuration.
- **COMPUTER deploy environment without OIDC token file path** now returns `OidcTokenFilePathNotFound` (previously `OidcAudienceNotFound`).
- **`RefreshResult.Error` field removed** (`cache/refresh_result.go`): errors are now returned via the `error` return value of refresh functions, not embedded in `RefreshResult`. Custom supplier implementations must change from single-return `RefreshResult[T]` to `(RefreshResult[T], error)` pattern.
- **`ExchangeToken` signature changed** (`internal/implementation/machine_token_exchange_provider.go`): from `ExchangeToken(subjectToken, actorToken string)` to `ExchangeToken(req TokenExchangeRequest)` using a 6-field struct. The struct design avoids positional parameter confusion, supports delegated `ActorToken`, and allows per-call scope override. See [API Divergence from Java/Python](#api-divergence-from-javapython) below.
- **`NewCachedResultSupplier` signature changed** (`cache/cached_result_supplier.go`): the third `prefetchThreshold time.Duration` parameter is removed — prefetch timing is now derived internally from the stale/expired windows. Callers passing a positional threshold argument must drop the third argument.
- **Module path renamed**: `github.com/aliyun/idaas-go-core-sdk` → `github.com/cloud-idaas/idaas-go-core-sdk`. Update `import` statements and the `require` block in your module's `go.mod`.
- **`HttpConfiguration.UnsafeIgnoreSSLCert` JSON tag renamed**: `unsafeIgnoreSSLCert` → `unsafeIgnoreSslCert` (aligns with Java/Python for cross-language config portability). Backward-compatible: the legacy `unsafeIgnoreSSLCert` key still deserializes with a WARN migration hint (see `HttpConfiguration.UnmarshalJSON`); update config files to the new key when convenient.
- **`enums.TokenAuthnMethodPCA` renamed to `TokenAuthnMethodPca`**: aligns with the sibling constants `TokenAuthnMethodPkcs7` / `TokenAuthnMethodOidc` — Go exported identifiers use MixedCaps (Effective Go "Names"), and `PCA`/`PKCS7`/`OIDC` are not in the golint initialism list so need not be all-caps; the surrounding code (`OidcTokenProvider`, `AwsEc2Pkcs7AttestedDocumentProvider`, `getPcaCredential`) already uses camelCase acronyms. Backward-compatible: `TokenAuthnMethodPCA` is retained as a `// Deprecated` alias of equal value (`"pca"`); staticcheck SA1019 flags internal usages. The alias will be removed before v1.0. Cross-language note: Java/Python keep all-caps enum constants (`PCA`/`PKCS7`/`OIDC`) per their own language convention; the wire value (`"pca"`) is lowercase and identical across all three SDKs.

### Security

- Device-flow logs no longer include `user_code`: only `verification_uri` is logged (RFC 8628 §5.4); `verification_uri_complete` is used solely to open the browser
- Test data and documentation carry no real tenants: endpoints, instance IDs and client IDs are `example.com` placeholders, and real integration configuration lives only in the gitignored `integration/testdata/.local/` (with `*.example.json` templates committed)

### API Divergence from Java/Python

The Go SDK intentionally diverges from Java/Python in several API signatures to leverage Go-specific strengths. These differences are documented here to aid cross-language migration:

| API | Go SDK | Java SDK | Python SDK | Rationale |
|-----|--------|----------|------------|-----------|
| **Factory init** | `Init(configPaths ...string)` | `init()` | `init(config_path=None)` | Go variadic is a superset; supports multiple config paths |
| **Token exchange** | `ExchangeToken(req TokenExchangeRequest)` | `getCredential(accessToken, tokenType, requestedTokenType)` | `get_credential(subject_token, subject_token_type, requested_token_type=None)` | Go struct avoids positional confusion, supports delegated ActorToken and per-call scope |
| **Token exchange method name** | `ExchangeToken` | `getCredential` | `get_credential` | Go name follows RFC 8693 semantics (`token-exchange`); Java/Python use broader `getCredential` |

These divergences are intentional and will be preserved through v1.0. Migration guides should reference this table when documenting cross-language patterns.
