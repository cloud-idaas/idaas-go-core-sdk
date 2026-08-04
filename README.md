# IDaaS Go Core SDK

[![Go Version](https://img.shields.io/badge/go-1.18%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

IDaaS (Identity as a Service) M2M products Go SDK, providing convenient machine-to-machine authentication capabilities for developers.

[简体中文](README_zh.md)

## Features

- **Multiple Authentication Methods**: Supports various M2M authentication methods including Client Secret, JWT Private Key, OIDC Token, PKCS7 Attested Document, etc.
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

## Specify Configuration File

The default path for the configuration file is: `~/.cloud_idaas/client-config.json`. If not explicitly specified, the configuration file will be loaded from this path by default.

Configuration loading priority (from highest to lowest):
1. Explicit file path (passed as parameter)
2. Environment variable `CLOUD_IDAAS_CONFIG_PATH`
3. Default path `~/.cloud_idaas/client-config.json`
4. Individual environment variables

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
    "deployEnvironment": "LOCAL",
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
| authnConfiguration | Authentication configuration:<br>- authnMethod: Required, authentication method. Different authentication methods require different fields, see **authnMethod Values and authnConfiguration Field Mapping** for details.<br>- identityType: Optional, default value is `CLIENT`, currently supports `CLIENT` and `HUMAN`.<br>- clientDeployEnvironment: Optional, **only** used by `PKCS7` / `OIDC` authentication methods. Values: `ALIBABA_CLOUD_ECS` (for PKCS7), `KUBERNETES` (for OIDC).<br><br>**Case sensitivity**: `authnMethod`, `identityType` and `clientDeployEnvironment` values are case-insensitive (the SDK normalizes them internally — `authnMethod` to lowercase, `identityType` / `clientDeployEnvironment` to uppercase). All examples in this repo use the uppercase form to stay consistent with Alibaba Cloud's official documentation. |
| httpConfiguration | HTTP protocol related configuration, contains 2 fields (in milliseconds):<br>- connectTimeout: Optional, maximum wait time for client to establish connection with server, default is 5000.<br>- readTimeout: Optional, maximum wait time for client to wait for server data after connection is established, default is 10000. |

### authnMethod Values and authnConfiguration Field Mapping

| authnMethod | Required authnConfiguration Field | authnConfiguration Field Description |
|--------------|-----------------------------------|--------------------------------------|
| client_secret_basic | clientSecretEnvVarName | Environment variable name for M2M client application's Client Secret. |
| client_secret_post | clientSecretEnvVarName | Environment variable name for M2M client application's Client Secret. |
| client_secret_jwt | clientSecretEnvVarName | Environment variable name for M2M client application's Client Secret (used as HS256 signing key). |
| private_key_jwt | privateKeyEnvVarName | Environment variable name for M2M client application's Private Key (PEM format). |
| pca | privateKeyEnvVarName, applicationFederatedCredentialName, clientX509Certificate, x509CertChains | Private CA X509 certificate authentication. |
| oidc | applicationFederatedCredentialName, clientDeployEnvironment | OIDC federation (e.g. Kubernetes Service Account Token). |
| pkcs7 | applicationFederatedCredentialName, clientDeployEnvironment | PKCS#7 federation (e.g. Alibaba Cloud ECS attested document). |
| plugin | pluginName | Plugin name for custom credential provider. Requires a plugin registered in PluginRegistry (e.g. via `import _` anonymous import). |
| none | - | Public client, no client credential required. |

## Configuration Examples

### Client Secret Configuration Example

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
    }
}
```

### Private Key JWT Configuration Example

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|read:file",
    "authnConfiguration": {
        "authnMethod": "PRIVATE_KEY_JWT",
        "identityType": "CLIENT",
        "privateKeyEnvVarName": "IDAAS_PRIVATE_KEY"
    }
}
```

### Kubernetes OIDC Configuration Example

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|read:file",
    "authnConfiguration": {
        "authnMethod": "OIDC",
        "identityType": "CLIENT",
        "applicationFederatedCredentialName": "k8s_federation",
        "clientDeployEnvironment": "KUBERNETES"
    }
}
```

### Alibaba Cloud ECS Configuration Example

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|.all",
    "authnConfiguration": {
        "authnMethod": "PKCS7",
        "identityType": "CLIENT",
        "applicationFederatedCredentialName": "aliyun_ecs",
        "clientDeployEnvironment": "ALIBABA_CLOUD_ECS"
    }
}
```

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
go get github.com/aliyun/idaas-go-core-alibabacloud-authentication-plugin
```

**Step 2**: Anonymous import in your `main` package to trigger auto-registration:

```go
import _ "github.com/aliyun/idaas-go-core-alibabacloud-authentication-plugin"
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

> **Notes**:
> - `pluginName` must match the value returned by `PluginCredentialProvider.GetName()` in the plugin.
> - `openApiEndpoint` is required by the Alibaba Cloud plugin to call EIAM OpenAPI `GenerateOauthToken`.
> - Alibaba Cloud credentials (AK/SK) are loaded automatically via the default credential chain (env vars > ECS metadata > `~/.aliyun/config.json`).

### Sample Index by Scenario

| Authentication Method | `authnMethod` | Sample File |
|---|---|---|
| Client Secret + Basic Auth | `CLIENT_SECRET_BASIC` | `samples/obtain_token_sample.go` |
| Client Secret + Form Post | `CLIENT_SECRET_POST` | `samples/obtain_token_sample.go` |
| Client Secret + HS256 JWT Assertion | `CLIENT_SECRET_JWT` | `samples/obtain_token_sample.go` |
| Private Key JWT | `PRIVATE_KEY_JWT` | `samples/obtain_token_sample.go` |
| Private CA X509 Certificate | `PCA` | `samples/obtain_token_sample.go` |
| PKCS#7 Federation (Alibaba Cloud ECS) | `PKCS7` | `samples/obtain_token_sample.go` |
| OIDC Federation (Kubernetes) | `OIDC` | `samples/obtain_token_sample.go` |
| Device Code Human Login | identityType=HUMAN | `samples/device_code_sample.go` |
| Refresh Token Renewal | - | `samples/refresh_token_sample.go` |
| Token Exchange (RFC 8693) | - | `samples/token_exchange_sample.go` |
| Plugin (Alibaba Cloud) | `PLUGIN` | See [idaas-go-core-alibabacloud-authentication-plugin](https://github.com/aliyun/idaas-go-core-alibabacloud-authentication-plugin) |

> The `plugin` method requires a plugin registered in `PluginRegistry`. See [Plugin Configuration](#plugin-configuration-example) below.

See [samples/README.md](samples/README.md) for full scenario details and run instructions.

## Code Integration

### SDK Initialization

Initialize the factory with configuration:

```go
package main

import (
    "fmt"
    "github.com/cloud-idaas/idaas-go-core-sdk/config"
    "github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
    // Load configuration
    reader := config.NewConfigReader()
    cfg, err := reader.LoadWithPriority("")
    if err != nil {
        panic(err)
    }

    // Initialize factory
    factoryInstance := factory.GetInstance()
    err = factoryInstance.Initialize(cfg)
    if err != nil {
        panic(err)
    }

    // Get credential provider
    provider, err := factoryInstance.CreateCredentialProvider()
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
> - SDK functionality depends on the `Initialize()` method, so initialization must be completed first, otherwise getting `IDaaSCredentialProvider` will fail.
> - Initialization checks configuration and attempts to get Access Token for the scope specified in the configuration file. If configuration is missing or incorrect, it will fail directly.

### Get Access Token

1. Get IDaaS credentialProvider for obtaining Access Token:

   ```go
   provider, err := factoryInstance.CreateCredentialProvider()
   if err != nil {
       panic(err)
   }
   ```

2. Access Token is Bearer type, get it through credentialProvider's `GetCredential()` method:

   ```go
   cred, err := provider.GetCredential()
   if err != nil {
       panic(err)
   }
   
   accessToken := cred.GetAccessToken()
   ```

## Token Exchange

Token Exchange (RFC 8693) allows you to exchange a subject token for a new access token with different scopes or audiences. This is useful for token downgrading and service-to-service access scenarios.

### Basic Token Exchange

```go
package main

import (
    "fmt"
    "github.com/cloud-idaas/idaas-go-core-sdk/config"
    "github.com/cloud-idaas/idaas-go-core-sdk/factory"
    "github.com/cloud-idaas/idaas-go-core-sdk/implementation"
    "github.com/cloud-idaas/idaas-go-core-sdk/http"
)

func main() {
    // Load configuration
    reader := config.NewConfigReader()
    cfg, err := reader.LoadWithPriority("")
    if err != nil {
        panic(err)
    }

    // Initialize factory
    factoryInstance := factory.GetInstance()
    err = factoryInstance.Initialize(cfg)
    if err != nil {
        panic(err)
    }

    // Subject token to exchange
    subjectToken := "your_subject_token_here"

    // Create token exchange provider
    httpClient := http.GetHttpClient()
    tokenExchangeProvider := implementation.NewIDaaSMachineTokenExchangeCredentialProvider(
        cfg.ClientId,
        cfg.AuthnConfiguration.ClientSecret,
        cfg.TokenEndpoint,
        httpClient,
    )

    // Perform token exchange
    cred, err := tokenExchangeProvider.ExchangeToken(subjectToken, "")
    if err != nil {
        panic(err)
    }

    fmt.Println("Exchanged Access Token:", cred.GetAccessToken())
}
```

### Token Exchange Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| subjectToken | string | Yes | The token to be exchanged |
| actorToken | string | No | Actor token for delegated authorization (optional) |

### Use Cases

1. **Token Downgrading**: Exchange a token with broader permissions for a token with limited scope
2. **Service-to-Service Access**: Pass the same user identity between services to obtain required access tokens

## Support and Feedback

- **Email**: cloudidaas@list.alibaba-inc.com
- **Issue Feedback**: If you have questions or suggestions, please submit an Issue

## License

This project is licensed under the [Apache License 2.0](LICENSE).
