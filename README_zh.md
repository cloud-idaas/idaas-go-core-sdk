# IDaaS Go Core SDK

[![Go Version](https://img.shields.io/badge/go-1.18%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

IDaaS（身份即服务）M2M 产品的 Go SDK，为开发者提供便捷的机器对机器认证能力。

[English](README.md)

## 功能特性

- **多种认证方式**：支持 Client Secret、JWT 私钥、OIDC Token、PKCS7 认证文档等多种 M2M 认证方式
- **插件扩展**：支持自定义凭证提供器，满足特殊场景需求
- **智能缓存机制**：内置凭证缓存策略，支持预取和过期值处理，减少不必要的网络请求
- **灵活配置**：支持配置文件、环境变量和编程式配置
- **令牌交换（RFC 8693）**：支持令牌交换以获取不同 scope 或 audience 的访问令牌，适用于令牌降权和服务间调用场景

## 环境要求

- Go 1.18 或以上版本（需要泛型支持）

## 安装 Go SDK

通过 `go get` 添加依赖：

```bash
go get github.com/aliyun/idaas-go-core-sdk
```

## 指定配置文件

配置文件的默认路径：`~/.cloud_idaas/client-config.json`。如未明确指定，则默认从该路径下获取配置文件。

配置加载优先级（从高到低）：
1. 显式文件路径（作为参数传入）
2. 环境变量 `CLOUD_IDAAS_CONFIG_PATH`
3. 默认路径 `~/.cloud_idaas/client-config.json`
4. 各个独立的环境变量

### 环境变量配置示例

```bash
export CLOUD_IDAAS_CONFIG_PATH=/path/to/your/config.json
```

## 配置文件说明

配置文件示例如下：

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

### 参数说明

| 字段名 | 备注 |
|--------|------|
| clientId | 必填，IDaaS 应用的应用 ID，可在对应 IDaaS 应用中查看。 |
| idaasInstanceId | 必填，IDaaS EIAM 的实例 ID。 |
| issuer | 必填，IDaaS EIAM 实例的 Issuer 端点，可在 IDaaS EIAM 实例下的任意 M2M 应用中查看。 |
| tokenEndpoint | 必填，IDaaS EIAM 实例的令牌端点，可在 IDaaS EIAM 实例下的任意 M2M 应用中查看。 |
| scope | 必填，指定要访问的 M2M 服务端应用的受众标识和权限标识，格式为 `受众标识\|权限标识`。 |
| authnConfiguration | 认证配置：<br>- authnMethod：必填，认证方式。不同认证方式所需的字段不同，详细对应关系参见 **authnMethod 字段值和 authnConfiguration 字段对应关系**。<br>- identityType：可选，默认值为 `CLIENT`，目前支持 `CLIENT` 和 `HUMAN`。<br>- clientDeployEnvironment：可选，**仅** `PKCS7` / `OIDC` 认证方式使用。取值：`ALIBABA_CLOUD_ECS`（PKCS7）、`KUBERNETES`（OIDC）。<br><br>**大小写说明**：`authnMethod` 与 `identityType`、`clientDeployEnvironment` 配置值大小写不敏感，SDK 内部会自动归一化（`authnMethod` → 小写、`identityType` / `clientDeployEnvironment` → 大写）。推荐统一使用大写写法以便与阿里云官方文档保持一致。 |
| httpConfiguration | HTTP 协议相关配置，包含 2 个字段（单位为毫秒）：<br>- connectTimeout：可选，客户端与服务端建立连接的最大等待时间，默认为 5000。<br>- readTimeout：可选，连接建立后，客户端等待服务端返回数据的最大等待时间，默认为 10000。 |

### authnMethod 字段值和 authnConfiguration 字段对应关系

| authnMethod | 需要的 authnConfiguration 字段 | authnConfiguration 字段说明 |
|--------------|-------------------------------|-----------------------------|
| client_secret_basic | clientSecretEnvVarName | M2M 客户端应用的 Client Secret 的环境变量名称，secret 通过 HTTP Basic Auth 头发送。 |
| client_secret_post | clientSecretEnvVarName | M2M 客户端应用的 Client Secret 的环境变量名称，secret 通过 form body 字段发送。 |
| client_secret_jwt | clientSecretEnvVarName | M2M 客户端应用的 Client Secret 的环境变量名称，SDK 用 secret 做 HS256 签名生成 JWT 客户端断言。 |
| private_key_jwt | privateKeyEnvVarName | M2M 客户端应用的 Private Key（PEM 格式）的环境变量名称，SDK 用私钥做 RS256/ES256 签名生成 JWT 客户端断言。 |
| pca | privateKeyEnvVarName、clientX509Certificate、x509CertChains、applicationFederatedCredentialName | Private CA 证书认证。需要 PEM 私钥（用于签 JWT）+ 终端证书 + 中间证书链 + 联邦凭证名。 |
| pkcs7 | applicationFederatedCredentialName、clientDeployEnvironment | PKCS#7 联邦认证，配合 `clientDeployEnvironment=ALIBABA_CLOUD_ECS` 使用。SDK 自动从 ECS Metadata Service 获取 attested document。 |
| oidc | applicationFederatedCredentialName、clientDeployEnvironment | OIDC 联邦认证，配合 `clientDeployEnvironment=KUBERNETES` 使用。SDK 自动读取 K8s SA Token。 |
| plugin | pluginName | 自定义凭证提供器的插件名称，必须在 PluginRegistry 中注册。 |

## 配置参数示例

不同认证方式下的具体的配置示例。

### Client Secret 凭证配置示例

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

### Client Secret JWT（HS256）凭证配置示例

`client_secret` 不直接传输，而是用作 HMAC 密钥对 JWT 做 HS256 签名后作为 `client_assertion` 提交。

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|read:file",
    "authnConfiguration": {
        "authnMethod": "CLIENT_SECRET_JWT",
        "identityType": "CLIENT",
        "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
    }
}
```

### 公私钥凭证配置示例

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

### Private CA 证书认证（PCA）配置示例

使用 PrivateCA 签发的 X509 证书 + 对应私钥进行客户端认证。SDK 用私钥签发 RS256/ES256 JWT 作为 `client_assertion`（`iss=sub=clientId`），同时提交终端证书与中间证书链。

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|.all",
    "authnConfiguration": {
        "authnMethod": "PCA",
        "identityType": "CLIENT",
        "privateKeyEnvVarName": "IDAAS_PRIVATE_KEY",
        "clientX509Certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
        "x509CertChains": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
        "applicationFederatedCredentialName": "private_ca"
    }
}
```

### Kubernetes OIDC 配置示例

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

### 阿里云 ECS 配置示例

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

### 人类 Device Code 登录配置示例

适用于 CLI / 受限输入设备的人类用户登录场景。

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

### 各场景 Sample 速查表

| 认证方式 | 配置 authnMethod | 对应 Sample |
|---|---|---|
| Client Secret + Basic Auth | `CLIENT_SECRET_BASIC` | `samples/obtain_token_sample.go` |
| Client Secret + Form Post | `CLIENT_SECRET_POST` | `samples/obtain_token_sample.go` |
| Client Secret + HS256 JWT 断言 | `CLIENT_SECRET_JWT` | `samples/obtain_token_sample.go` |
| 私钥 JWT | `PRIVATE_KEY_JWT` | `samples/obtain_token_sample.go` |
| Private CA 证书认证 | `PCA` | `samples/obtain_token_sample.go` |
| PKCS#7 联邦认证（阿里云 ECS） | `PKCS7` | `samples/obtain_token_sample.go` |
| OIDC 联邦认证（Kubernetes） | `OIDC` | `samples/obtain_token_sample.go` |
| Device Code 人类登录 | identityType=HUMAN | `samples/device_code_sample.go` |
| Refresh Token 续期 | - | `samples/refresh_token_sample.go` |
| Token Exchange (RFC 8693) | - | `samples/token_exchange_sample.go` |

> `plugin` 自定义凭证插件需自行在 `PluginRegistry` 注册。

更多场景细节与各 sample 的运行方式，请参考 [samples/README.md](samples/README.md)。

## 代码集成

### SDK 初始化

读取用户在环境准备阶段指定的配置文件，完成 IDaaS 配置的初始化。

```go
package main

import (
    "fmt"
    "github.com/aliyun/idaas-go-core-sdk/config"
    "github.com/aliyun/idaas-go-core-sdk/factory"
)

func main() {
    // 加载配置
    reader := config.NewConfigReader()
    cfg, err := reader.LoadWithPriority("")
    if err != nil {
        panic(err)
    }

    // 初始化工厂
    factoryInstance := factory.GetInstance()
    err = factoryInstance.Initialize(cfg)
    if err != nil {
        panic(err)
    }

    // 获取凭证提供者
    provider, err := factoryInstance.CreateCredentialProvider()
    if err != nil {
        panic(err)
    }

    // 获取访问令牌
    cred, err := provider.GetCredential()
    if err != nil {
        panic(err)
    }

    fmt.Println("Access Token:", cred.GetAccessToken())
}
```

> **重要提示**：
> - SDK 功能均依赖 `Initialize()` 初始化方法，因此 `Initialize()` 初始化方法必须先完成，否则获取 `IDaaSCredentialProvider` 等均会报错，导致业务中断。
> - 初始化会检查配置并尝试获取配置文件中指定的 scope 的 Access Token，若配置缺失或配置错误导致获取 Access Token 失败，会直接报错，导致业务中断。

### 获取 Access Token

1. 获取 IDaaS credentialProvider，用于获取 Access Token：

   ```go
   provider, err := factoryInstance.CreateCredentialProvider()
   if err != nil {
       panic(err)
   }
   ```

2. Access Token 是 Bearer 类型，通过 credentialProvider 的 `GetCredential()` 方法获取：

   ```go
   cred, err := provider.GetCredential()
   if err != nil {
       panic(err)
   }
   
   accessToken := cred.GetAccessToken()
   ```

## 令牌交换

令牌交换（RFC 8693）允许您将主体令牌交换为具有不同范围或受众的新访问令牌。这对于令牌降级和服务间访问场景非常有用。

### 基本令牌交换

```go
package main

import (
    "fmt"
    "github.com/aliyun/idaas-go-core-sdk/config"
    "github.com/aliyun/idaas-go-core-sdk/factory"
    "github.com/aliyun/idaas-go-core-sdk/implementation"
    "github.com/aliyun/idaas-go-core-sdk/http"
)

func main() {
    // 加载配置
    reader := config.NewConfigReader()
    cfg, err := reader.LoadWithPriority("")
    if err != nil {
        panic(err)
    }

    // 初始化工厂
    factoryInstance := factory.GetInstance()
    err = factoryInstance.Initialize(cfg)
    if err != nil {
        panic(err)
    }

    // 要交换的主体令牌
    subjectToken := "your_subject_token_here"

    // 创建令牌交换提供者
    httpClient := http.GetHttpClient()
    tokenExchangeProvider := implementation.NewIDaaSMachineTokenExchangeCredentialProvider(
        cfg.ClientId,
        cfg.AuthnConfiguration.ClientSecret,
        cfg.TokenEndpoint,
        httpClient,
    )

    // 执行令牌交换
    cred, err := tokenExchangeProvider.ExchangeToken(subjectToken, "")
    if err != nil {
        panic(err)
    }

    fmt.Println("Exchanged Access Token:", cred.GetAccessToken())
}
```

### 令牌交换参数

| 参数 | 类型 | 必填 | 描述 |
|-----------|------|----------|-------------|
| subjectToken | string | 是 | 要交换的令牌 |
| actorToken | string | 否 | 用于委托授权的 Actor 令牌（可选） |

### 使用场景

1. **令牌降级**：将具有较宽权限的令牌交换为具有有限范围的令牌
2. **服务间访问**：在服务之间传递相同的用户身份以获取所需的访问令牌

## 支持与反馈

- **邮箱**：cloudidaas@list.alibaba-inc.com
- **问题反馈**：如有问题或建议，请提交 Issue

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 许可证授权。
