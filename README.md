# IDaaS Go Core SDK

[![Go Version](https://img.shields.io/badge/go-1.18%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

IDaaS (Identity as a Service) M2M products Go SDK, providing convenient machine-to-machine authentication capabilities for developers.

[简体中文](README_zh.md)

## Features

- **Multiple Authentication Methods**: Supports various M2M authentication methods including Client Secret, JWT Private Key, Private CA Certificate, OIDC Federation, PKCS7 Attested Document, custom plugins, etc.
- **Plugin Extension**: Supports custom credential providers to meet special scenario requirements
- **Intelligent Caching Mechanism**: Built-in credential caching strategy with prefetch and stale value handling to reduce unnecessary network requests
- **Flexible Configuration**: Supports configuration files, environment variables, and programmatic configuration
- **Token Exchange (RFC 8693)**: Supports token exchange to obtain access tokens with different scopes or audiences, suitable for token downgrading and service-to-service call scenarios

## Requirements

- Go 1.18 or above (requires generics)

## Install Go SDK

Add the dependency via `go get`:

```bash
go get github.com/cloud-idaas/idaas-go-core-sdk
```

## Quickstart (5 minutes)

The fastest path: one config file + three lines of code.

1. **Create a config file** `config.json` (machine identity, client-secret auth):

```json
{
  "idaasInstanceId": "idaas-cn-xxx",
  "identityType": "CLIENT",
  "authnMethod": "CLIENT_SECRET",
  "clientId": "your-client-id",
  "clientSecretEnvVarName": "CLOUD_IDAAS_CLIENT_SECRET",
  "tokenEndpoint": "https://idaas.example.com/oauth2/token",
  "scope": "openid"
}
```

Export the secret as an env var (never hardcode it in the file):

```bash
export CLOUD_IDAAS_CLIENT_SECRET="your-client-secret"
```

2. **Point the SDK at the config** and initialize:

```go
package main

import (
    "fmt"
    "github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
    // Load config.json, validate, and prefetch the default-scope token
    // (fault-tolerant: prefetch failure logs WARN but does not block startup).
    if err := factory.Init("config.json"); err != nil {
        panic(err)
    }

    provider, err := factory.GetIDaaSCredentialProvider()
    if err != nil {
        panic(err)
    }
    cred, err := provider.GetCredential()
    if err != nil {
        panic(err)
    }
    fmt.Println("Access Token:", cred.GetAccessToken())
}
```

That's it — the SDK caches, prefetches, and refreshes the token automatically. See [Configuration File Description](#configuration-file-description) for all fields and [Code Integration](#code-integration) for the full API.

> **Human (device-code) login?** Set `identityType: "HUMAN"` + `authnMethod: "OIDC"` + `deviceAuthorizationEndpoint`. The SDK prints the verification URL and user code to stdout by default; override with `factory.GetInstance().WithUserCodeHandler(...)` for server-side integrations.

## Specify Configuration File

The default path for the configuration file is: `~/.cloud_idaas/client-config.json`. If not explicitly specified, the configuration file will be loaded from this path by default.

Configuration loading priority (from highest to lowest):
1. Explicit file path (passed as parameter)
2. Environment variable `CLOUD_IDAAS_CONFIG_PATH`
3. Default path `~/.cloud_idaas/client-config.json`

> **Note:** Individual environment variables (`CLOUD_IDAAS_CLIENT_ID`, `CLOUD_IDAAS_TOKEN_ENDPOINT`, etc.) are not part of the default priority chain. If you need to load config from environment variables, call `config.NewConfigReader().LoadFromEnv()` explicitly.

### Environment Variable Example

```bash
export CLOUD_IDAAS_CONFIG_PATH=/path/to/your/config.json
```

## Configuration File Description

Configuration file example:

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|read:file",
    "authnConfiguration": {
        "authnMethod": "CLIENT_SECRET_POST",
        "identityType": "CLIENT",
        "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
    },
    "httpConfiguration": {
        "connectTimeout": 5000,
        "readTimeout": 10000
    }
}
```

### Parameter Description

| Field Name | Description |
|------------|-------------|
| clientId | Required, IDaaS application ID, can be viewed in the corresponding IDaaS application. |
| idaasInstanceId | Required, IDaaS EIAM instance ID. |
| issuer | Required, IDaaS EIAM instance Issuer endpoint, can be viewed in any M2M application under the IDaaS EIAM instance. |
| tokenEndpoint | Required, IDaaS EIAM instance token endpoint, can be viewed in any M2M application under the IDaaS EIAM instance. |
| scope | Required, specifies the audience identifier and permission identifier of the M2M server application to access, format is `audience\|scope`. |
| deviceAuthorizationEndpoint | Optional, Device Code authorization endpoint. Required when `identityType=HUMAN`, used to initiate device authorization requests. |
| developerApiEndpoint | Optional, Developer API endpoint. Used to call IDaaS Developer API. |
| openApiEndpoint | Optional, OpenAPI endpoint. Required for `PLUGIN` authn method (the plugin calls EIAM OpenAPI `GenerateOauthToken` via this endpoint). |
| allowInsecureEndpoint | Optional, default `false`. Escape hatch: allows `http://` endpoints. Must remain `false` in production; enabling it logs a WARN on every initialization. |
| authnConfiguration | Authentication configuration:<br>- authnMethod: Required when `identityType=CLIENT` (not needed for `HUMAN`), authentication method. Different authentication methods require different fields, see **authnMethod Values and authnConfiguration Field Mapping** for details.<br>- identityType: Optional, default value is `CLIENT`, currently supports `CLIENT` and `HUMAN`.<br>- clientDeployEnvironment: Optional, **only** used by `PKCS7` / `OIDC` authentication methods. Values: `ALIBABA_CLOUD_ECS` (for PKCS7), `KUBERNETES` (for OIDC), `COMPUTER` (for OIDC local dev mode, requires `oidcTokenFilePath`).<br>- humanAuthenticateClientId: Optional, used only when `identityType=HUMAN`, default value is `iap_developer`.<br><br>**Case sensitivity**: `authnMethod`, `identityType`, `clientDeployEnvironment` are case-insensitive (normalized internally: `authnMethod`→lowercase, `identityType`/`clientDeployEnvironment`→uppercase). Examples use uppercase to match Alibaba Cloud's official documentation. |
| httpConfiguration | HTTP protocol related configuration, contains 3 fields (in milliseconds):<br>- connectTimeout: Optional, maximum wait time for client to establish connection with server, default is 5000.<br>- readTimeout: Optional, maximum wait time for client to wait for server data after connection is established, default is 10000.<br>- unsafeIgnoreSslCert: Optional, default `false`. Set to `true` to disable SSL certificate verification. **For local testing only** — must remain `false` in production. |

### authnMethod Values and authnConfiguration Field Mapping

| authnMethod | Required authnConfiguration Field | authnConfiguration Field Description | Sample |
|--------------|-----------------------------------|--------------------------------------|--------|
| client_secret_basic | clientSecretEnvVarName | M2M client Secret env var name (sent via HTTP Basic Auth header). | `samples/obtain-token/` |
| client_secret_post | clientSecretEnvVarName | M2M client Secret env var name (sent via form body). | `samples/obtain-token/` |
| client_secret_jwt | clientSecretEnvVarName | M2M client Secret env var name (used as HS256 signing key for the JWT client assertion). | `samples/obtain-token/` |
| private_key_jwt | privateKeyEnvVarName | M2M client Private Key (PEM) env var name (RS256/ES256 JWT assertion). | `samples/obtain-token/` |
| pca | privateKeyEnvVarName, applicationFederatedCredentialName, clientX509Certificate, x509CertChains | Private CA X509: PEM private key (signs JWT) + leaf cert + intermediate chain + federated credential name. | `samples/obtain-token/` |
| pkcs7 | applicationFederatedCredentialName, clientDeployEnvironment | PKCS#7 federation with `clientDeployEnvironment=ALIBABA_CLOUD_ECS`; SDK fetches attested document from ECS IMDS. | `samples/obtain-token/` |
| oidc | applicationFederatedCredentialName, clientDeployEnvironment | OIDC federation with `clientDeployEnvironment=KUBERNETES`; SDK reads K8s SA Token. `COMPUTER` (local dev) additionally needs `oidcTokenFilePath` / `oidcTokenFilePathEnvVarName`. | `samples/obtain-token/` |
| plugin | pluginName | Custom credential provider plugin name; plugin must be registered in PluginRegistry (e.g. via `import _` anonymous import). | [alibabacloud plugin](https://github.com/cloud-idaas/idaas-go-core-alibabacloud-authentication-plugin) |
| (identityType=HUMAN) | humanAuthenticateClientId | Device Code human login. Do not set `authnMethod`; set `identityType=HUMAN` + `humanAuthenticateClientId` (default `iap_developer`) and top-level `deviceAuthorizationEndpoint`. | `samples/device-code/` |

> Refresh Token renewal and Token Exchange (RFC 8693) are not authnMethods — see `samples/refresh-token/` and `samples/token-exchange/`.

## Configuration Examples

All authentication methods share the top-level structure shown in [Configuration File Description](#configuration-file-description); only the `authnConfiguration` block differs — see the [authnMethod Field Mapping](#authnmethod-values-and-authnconfiguration-field-mapping) table for each method's required fields. The two methods below add extra top-level fields, so their full examples are given separately.

### Human Device Code Login Configuration Example

For CLI tools or input-constrained devices where a human user logs in via a browser on another device.

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "deviceAuthorizationEndpoint": "https://xxx/api/v2/iauths_system/oauth2/device_authorization",
    "scope": "api.example.com|read:file",
    "authnConfiguration": {
        "identityType": "HUMAN",
        "humanAuthenticateClientId": "iap_developer"
    }
}
```

### Plugin Configuration Example

The `plugin` authentication method delegates credential acquisition entirely to an external plugin. The SDK does not make any HTTP requests — the plugin handles everything.

**Step 1**: Install the plugin module (e.g. Alibaba Cloud plugin):

```bash
go get github.com/cloud-idaas/idaas-go-core-alibabacloud-authentication-plugin
```

**Step 2**: Anonymous import in your `main` package to trigger auto-registration:

```go
import _ "github.com/cloud-idaas/idaas-go-core-alibabacloud-authentication-plugin"
```

**Step 3**: Configuration file:

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|read:file",
    "openApiEndpoint": "eiam.cn-hangzhou.aliyuncs.com",
    "authnConfiguration": {
        "authnMethod": "PLUGIN",
        "identityType": "CLIENT",
        "pluginName": "alibabacloudPluginCredentialProvider"
    }
}
```

> `pluginName` must match `PluginCredentialProvider.GetName()`; `openApiEndpoint` is required (the plugin calls EIAM OpenAPI `GenerateOauthToken`); Alibaba Cloud AK/SK load automatically via the default credential chain (env vars > ECS metadata > `~/.aliyun/config.json`).

See [samples/README.md](samples/README.md) for full scenario details and run instructions.

## Code Integration

### SDK Initialization

Initialize the factory with configuration:

```go
package main

import (
    "fmt"
    "github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
    // Initialize factory (loads config, validates, and prefetches token)
    err := factory.Init()
    if err != nil {
        panic(err)
    }

    // Get credential provider
    provider, err := factory.GetIDaaSCredentialProvider()
    if err != nil {
        panic(err)
    }

    // Get access token
    cred, err := provider.GetCredential()
    if err != nil {
        panic(err)
    }

    fmt.Println("Access Token:", cred.GetAccessToken())
}
```

> **Important Notes**:
> - `factory.Init()` must complete before any `GetIDaaSCredentialProvider` call; it is idempotent (re-calling is a no-op; re-init with a different config requires `factory.Reset()` first). Configuration validation (Defaulting → Normalize → Validate) fails fast on missing/invalid config.
> - Init ends with a **fault-tolerant prefetch** of the configured scope's Access Token: on failure it only logs WARN and does **not block startup**, so transient network issues can't make the process unstartable; the first `GetCredential()` then triggers a refresh.

### Get Access Token

After initialization, call `provider.GetCredential()` (a cache hit issues no HTTP request). The full call sequence is shown in [SDK Initialization](#sdk-initialization); the access token is Bearer type, obtained via `cred.GetAccessToken()`.

## Token Exchange

Token Exchange (RFC 8693) allows you to exchange a subject token for a new access token with different scopes or audiences. This is useful for token downgrading and service-to-service access scenarios.

### Basic Token Exchange

Assuming the factory is already initialized (see [SDK Initialization](#sdk-initialization)):

```go
subjectToken := "your_subject_token_here"

// Get token exchange provider (factory reads client_secret from env)
tokenExchangeProvider, err := factory.GetIDaaSTokenExchangeCredentialProvider()
if err != nil {
    panic(err)
}

// Perform token exchange
cred, err := tokenExchangeProvider.ExchangeToken(provider.TokenExchangeRequest{
    SubjectToken: subjectToken,
})
if err != nil {
    panic(err)
}

fmt.Println("Exchanged Access Token:", cred.GetAccessToken())
```

### Token Exchange Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| SubjectToken | string | Yes | The token to be exchanged |
| SubjectTokenType | string | No | Token type URI (defaults to `urn:ietf:params:oauth:token-type:access_token`) |
| ActorToken | string | No | Actor token for delegated authorization (optional) |
| ActorTokenType | string | No | Actor token type URI |
| RequestedTokenType | string | No | Desired token type for the response |
| Scope | string | No | Requested scope for the exchanged token |

### Use Cases

1. **Token Downgrading**: Exchange a token with broader permissions for a token with limited scope
2. **Service-to-Service Access**: Pass the same user identity between services to obtain required access tokens

## Integration Tests

`integration/` contains end-to-end tests that request a real token from an IDaaS endpoint, one per `authnMethod`. The package is gated behind the `integration` build tag, so plain `go test ./...` (and CI) never issues real requests. See [integration/README.md](integration/README.md) for setup steps, run commands, and known limitations.

## Troubleshooting (Error Code Reference)

Every SDK error carries an `ErrorCode()` (match with `errors.As` against the `interface{ ErrorCode() string }` contract). The table maps each code to its cause and the action to take.

### Configuration / startup (fail-fast at `Initialize`)

| Code | Cause | Action |
| --- | --- | --- |
| `IDaaSCredentialProviderFactoryNotInit` | `factory.Init` not called or `Reset` cleared the singleton | Call `factory.Init` / `InitWithConfig` before any `GetIDaaSCredentialProvider` |
| `ClientConfigurationNotFound` | `nil` config passed to `InitWithConfig` | Pass a non-nil `*config.IDaaSClientConfig` |
| `IDaaSInstanceIdNotFound` / `ClientIdNotFound` / `TokenEndpointNotFound` / `DeviceAuthorizationEndpointNotFound` / `AuthnConfigurationNotFound` | Required config field missing | Fill the field in `config.json` |
| `InvalidEndpointScheme` / `InvalidEndpointFormat` | `tokenEndpoint` / `issuerEndpoint` not `https://` or not a valid absolute URL | Use an `https://` absolute URL; bare hosts are auto-completed to `https://` |
| `InsecureTLSDisallowed` (Experimental) | `WithTLSEnforcement()` is on and `unsafeIgnoreSslCert=true` | Remove `unsafeIgnoreSslCert` from config for production, or drop `WithTLSEnforcement()` for test/mock-server use |
| `LoadConfigFileFailed` | `config.json` unreadable or invalid JSON | Check file path, permissions, JSON syntax |
| `InvalidScope` / `MultipleAudienceNotSupported` / `InvalidStaleValueBehavior` / `UnsupportedIdentityType` / `UnsupportedAuthenticationMethod` | Unsupported enum value | Use a supported value (see [Parameter Description](#parameter-description)) |
| `*EnvVarNameNotFound` / `*NotFound` / `PrivateKeyInvalid` | Credential material missing/invalid | Set the named env var to a valid value; for private key, provide valid PEM/PKCS#8 |

### Runtime (HTTP / token / cache)

| Code | Cause | Action |
| --- | --- | --- |
| `ConnectTimeOut` / `ReadTimeOut` | Network timeout | Check connectivity to `tokenEndpoint`; raise `httpConfiguration.connectTimeout`/`readTimeout` if legitimate |
| `DnsLookupFailed` | DNS unresolvable | Check VPC DNS / hosts |
| `TlsHandshakeFailed` | TLS / cert validation failed | Check CA chain, endpoint cert, clock skew |
| `ConnectionReset` / `ResponseTruncated` | TCP RST / premature EOF | Retry; if persistent, check LB / proxy |
| `ResponseTooLarge` | Response exceeded client hard cap | Suspect malicious/faulty IdP; capture and report |
| `InvalidURL` | Request URL unparseable | Config or base-URL issue |
| `AccessTokenNotFound` | Token response missing `access_token` | IdP misbehaving; capture the (redacted) response |
| `InvalidExpiresIn` | `expires_in` ≤ 0 → degraded cache | Check IdP; temporary — next refresh recovers |
| `ClientRequestCanceled` (Experimental) | Caller cancelled `context` before the credential request completed | Expected when caller timeout/deadline hit; `errors.Is(err, context.Canceled)` / `context.DeadlineExceeded` distinguishes the reason |
| `CachedRefreshInBackoff` (Experimental) | BLOCK-mode stale request short-circuited within the 10s backoff window after a failed refresh | Retry shortly; protects the IdP from a refresh stampede |
| `CachedResultStale` | Stale cached value returned as degradation | Investigate upstream refresh failures |
| `RefreshPanicRecovered` (Experimental) | A refresh goroutine panicked and was recovered; the error carries the recovered value as a string in the message | Treat as an SDK bug — capture logs and report; refresh resumes on next call |
| `GcpVmIdentityTokenFetchFailed` / `AzureVmIdentityTokenFetchFailed` / `*Empty` / `AzureVmIdentityTokenInvalidJson` | Cloud metadata service fetch failed | Verify the workload is on the claimed cloud VM and the IMDS endpoint is reachable |
| `OAuth2Error` (`OAuth2Failed`) | OAuth2 error response with no standard `error` field | Inspect the IdP response; check `clientId`/`scope`/`audience` |
| `UnexpectedError` | Internal unhandled branch | Treat as SDK bug — report with logs |

## Support and Feedback

- **Issue Feedback**: If you have questions or suggestions, please submit a [GitHub Issue](https://github.com/cloud-idaas/idaas-go-core-sdk/issues)
- **Security Vulnerabilities**: Please report privately via [GitHub Security Advisories](https://github.com/cloud-idaas/idaas-go-core-sdk/security/advisories/new) instead of opening a public issue

## License

This project is licensed under the [Apache License 2.0](LICENSE).
