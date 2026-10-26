# IDaaS Go Core SDK

[![Go Version](https://img.shields.io/badge/go-1.18%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

IDaaS（身份即服务）M2M 产品的 Go SDK，为开发者提供便捷的机器对机器认证能力。

[English](README.md)

## 功能特性

- **多种认证方式**：支持 Client Secret、JWT 私钥、Private CA 证书、OIDC 联邦、PKCS7 认证文档、自定义插件等多种 M2M 认证方式
- **插件扩展**：支持自定义凭证提供器，满足特殊场景需求
- **智能缓存机制**：内置凭证缓存策略，支持预取和过期值处理，减少不必要的网络请求
- **灵活配置**：支持配置文件、环境变量和编程式配置
- **令牌交换（RFC 8693）**：支持令牌交换以获取不同 scope 或 audience 的访问令牌，适用于令牌降权和服务间调用场景

## 环境要求

- Go 1.18 或以上版本（需要泛型支持）

## 安装 Go SDK

通过 `go get` 添加依赖：

```bash
go get github.com/cloud-idaas/idaas-go-core-sdk
```

## 快速开始(5 分钟)

最快路径:一个配置文件 + 三行代码。

1. **创建配置文件** `config.json`(机器身份,client-secret 认证):

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

把密钥以环境变量形式导出(不要硬编码进文件):

```bash
export CLOUD_IDAAS_CLIENT_SECRET="your-client-secret"
```

2. **指向配置文件并初始化**:

```go
package main

import (
    "fmt"
    "github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
    // 加载 config.json、校验、预取默认 scope 的 token
    // (容错:预取失败只记 WARN,不阻塞启动)。
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

这样就行了 —— SDK 自动完成令牌的缓存、预取与刷新。全部字段见[配置文件说明](#配置文件说明),完整 API 见[代码集成](#代码集成)。

> **人类(device-code)登录?** 设 `identityType: "HUMAN"` + `authnMethod: "OIDC"` + `deviceAuthorizationEndpoint`。SDK 默认把验证 URL 与 user_code 打印到 stdout;服务端集成用 `factory.GetInstance().WithUserCodeHandler(...)` 覆盖。

## 指定配置文件

配置文件的默认路径：`~/.cloud_idaas/client-config.json`。如未明确指定，则默认从该路径下获取配置文件。

配置加载优先级（从高到低）：
1. 显式文件路径（作为参数传入）
2. 环境变量 `CLOUD_IDAAS_CONFIG_PATH`
3. 默认路径 `~/.cloud_idaas/client-config.json`

> **注意**：独立环境变量（`CLOUD_IDAAS_CLIENT_ID`、`CLOUD_IDAAS_TOKEN_ENDPOINT` 等）不在默认优先级链中。如需从环境变量加载配置，请显式调用 `config.NewConfigReader().LoadFromEnv()`。

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
| deviceAuthorizationEndpoint | 可选，Device Code 登录端点。仅 `identityType=HUMAN` 时必填，用于发起设备授权请求。 |
| developerApiEndpoint | 可选，Developer API 端点。用于调用 IDaaS Developer API。 |
| openApiEndpoint | 可选，OpenAPI 端点。`PLUGIN` 认证方式必填（插件通过此端点调用 EIAM OpenAPI `GenerateOauthToken`）。 |
| allowInsecureEndpoint | 可选，默认 `false`。逃生门：允许使用 `http://` 端点。生产环境必须保持 `false`，启用后会在每次初始化时记录 WARN 日志。 |
| authnConfiguration | 认证配置：<br>- authnMethod：`identityType=CLIENT` 时必填（`HUMAN` 无需设置），认证方式。不同认证方式所需的字段不同，详细对应关系参见 **authnMethod 字段值和 authnConfiguration 字段对应关系**。<br>- identityType：可选，默认值为 `CLIENT`，目前支持 `CLIENT` 和 `HUMAN`。<br>- clientDeployEnvironment：可选，**仅** `PKCS7` / `OIDC` 认证方式使用。取值：`ALIBABA_CLOUD_ECS`（PKCS7）、`KUBERNETES`（OIDC）、`COMPUTER`（OIDC 本地开发模式，需配合 `oidcTokenFilePath`）。<br>- humanAuthenticateClientId：可选，仅 `identityType=HUMAN` 时使用，默认值为 `iap_developer`。<br><br>**大小写说明**：`authnMethod`、`identityType`、`clientDeployEnvironment` 配置值大小写不敏感（SDK 内部归一化：`authnMethod` → 小写、`identityType` / `clientDeployEnvironment` → 大写），示例统一使用大写以与阿里云官方文档保持一致。 |
| httpConfiguration | HTTP 协议相关配置，包含 3 个字段（单位为毫秒）：<br>- connectTimeout：可选，客户端与服务端建立连接的最大等待时间，默认为 5000。<br>- readTimeout：可选，连接建立后，客户端等待服务端返回数据的最大等待时间，默认为 10000。<br>- unsafeIgnoreSslCert：可选，默认 `false`。设为 `true` 时禁用 SSL 证书校验，**仅限本地联调使用**，生产环境必须保持 `false`。 |

### authnMethod 字段值和 authnConfiguration 字段对应关系

| authnMethod | 需要的 authnConfiguration 字段 | authnConfiguration 字段说明 | Sample |
|--------------|-------------------------------|-----------------------------|--------|
| client_secret_basic | clientSecretEnvVarName | M2M 客户端 Client Secret 的环境变量名（通过 HTTP Basic Auth 头发送）。 | `samples/obtain-token/` |
| client_secret_post | clientSecretEnvVarName | M2M 客户端 Client Secret 的环境变量名（通过 form body 字段发送）。 | `samples/obtain-token/` |
| client_secret_jwt | clientSecretEnvVarName | M2M 客户端 Client Secret 的环境变量名（SDK 用 secret 做 HS256 签名生成 JWT 客户端断言）。 | `samples/obtain-token/` |
| private_key_jwt | privateKeyEnvVarName | M2M 客户端 Private Key（PEM）的环境变量名（SDK 用私钥做 RS256/ES256 签名生成 JWT 客户端断言）。 | `samples/obtain-token/` |
| pca | privateKeyEnvVarName、clientX509Certificate、x509CertChains、applicationFederatedCredentialName | Private CA 证书认证：PEM 私钥（签 JWT）+ 终端证书 + 中间证书链 + 联邦凭证名。 | `samples/obtain-token/` |
| pkcs7 | applicationFederatedCredentialName、clientDeployEnvironment | PKCS#7 联邦认证，配合 `clientDeployEnvironment=ALIBABA_CLOUD_ECS`，SDK 自动从 ECS IMDS 获取 attested document。 | `samples/obtain-token/` |
| oidc | applicationFederatedCredentialName、clientDeployEnvironment | OIDC 联邦认证，配合 `clientDeployEnvironment=KUBERNETES`，SDK 自动读取 K8s SA Token。`COMPUTER`（本地开发）需额外配置 `oidcTokenFilePath` / `oidcTokenFilePathEnvVarName`。 | `samples/obtain-token/` |
| plugin | pluginName | 自定义凭证提供器插件名，必须在 PluginRegistry 中注册（如 `import _` 匿名导入）。 | [alibabacloud 插件](https://github.com/cloud-idaas/idaas-go-core-alibabacloud-authentication-plugin) |
| （identityType=HUMAN） | humanAuthenticateClientId | Device Code 人类登录。不设 `authnMethod`，设 `identityType=HUMAN` + `humanAuthenticateClientId`（默认 `iap_developer`），并在顶层配置 `deviceAuthorizationEndpoint`。 | `samples/device-code/` |

> Refresh Token 续期与 Token Exchange（RFC 8693）不是 authnMethod，分别见 `samples/refresh-token/` 与 `samples/token-exchange/`。

## 配置参数示例

所有认证方式共享[配置文件说明](#配置文件说明)中的顶层结构，仅 `authnConfiguration` 块不同——各方法所需字段见 [authnMethod 字段对应关系](#authnmethod-字段值和-authnconfiguration-字段对应关系)表。下列两种方式有额外的顶层字段，故单独给出完整示例。

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

### 插件配置示例

`plugin` 认证方式将凭证获取完全委托给外部插件，SDK 不发起任何 HTTP 请求——一切由插件处理。

**第 1 步**：安装插件模块（如阿里云插件）：

```bash
go get github.com/cloud-idaas/idaas-go-core-alibabacloud-authentication-plugin
```

**第 2 步**：在 `main` 包中匿名导入以触发自动注册：

```go
import _ "github.com/cloud-idaas/idaas-go-core-alibabacloud-authentication-plugin"
```

**第 3 步**：配置文件：

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

> `pluginName` 须与插件的 `PluginCredentialProvider.GetName()` 一致；`openApiEndpoint` 必填（插件通过它调用 EIAM OpenAPI `GenerateOauthToken`）；阿里云 AK/SK 通过默认凭证链自动加载（环境变量 > ECS 元数据 > `~/.aliyun/config.json`）。

更多场景细节与各 sample 的运行方式，请参考 [samples/README.md](samples/README.md)。

## 代码集成

### SDK 初始化

读取用户在环境准备阶段指定的配置文件，完成 IDaaS 配置的初始化。

```go
package main

import (
    "fmt"
    "github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
    // 初始化工厂(自动加载配置、校验、预热 token)
    err := factory.Init()
    if err != nil {
        panic(err)
    }

    // 获取凭证提供者
    provider, err := factory.GetIDaaSCredentialProvider()
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
> - `factory.Init()` 必须先于任何 `GetIDaaSCredentialProvider` 调用完成；它是幂等的（再次调用为空操作，如需用新配置重新初始化请先调用 `factory.Reset()`）。配置校验（Defaulting → Normalize → Validate）对缺失/非法配置直接快速失败。
> - 初始化末尾会对配置 scope 的 Access Token 做**容错预热**：失败时仅记录 WARN 日志，**不阻断启动**，避免启动期网络抖动导致进程无法启动；首次 `GetCredential()` 时会重新触发刷新。

### 获取 Access Token

初始化后调用 `provider.GetCredential()` 即可（命中缓存不发起 HTTP 请求）。完整调用序列见 [SDK 初始化](#sdk-初始化)；Access Token 为 Bearer 类型，通过 `cred.GetAccessToken()` 获取。

## 令牌交换

令牌交换（RFC 8693）允许您将主体令牌交换为具有不同范围或受众的新访问令牌。这对于令牌降级和服务间访问场景非常有用。

### 基本令牌交换

假设 factory 已初始化（见 [SDK 初始化](#sdk-初始化)）：

```go
subjectToken := "your_subject_token_here"

// 获取令牌交换提供者（factory 内部从环境变量读取 client_secret）
tokenExchangeProvider, err := factory.GetIDaaSTokenExchangeCredentialProvider()
if err != nil {
    panic(err)
}

// 执行令牌交换
cred, err := tokenExchangeProvider.ExchangeToken(provider.TokenExchangeRequest{
    SubjectToken: subjectToken,
})
if err != nil {
    panic(err)
}

fmt.Println("Exchanged Access Token:", cred.GetAccessToken())
```

### 令牌交换参数

| 参数 | 类型 | 必填 | 描述 |
|-----------|------|----------|-------------|
| SubjectToken | string | 是 | 要交换的令牌 |
| SubjectTokenType | string | 否 | 令牌类型 URI(默认 `urn:ietf:params:oauth:token-type:access_token`) |
| ActorToken | string | 否 | 用于委托授权的 Actor 令牌(可选) |
| ActorTokenType | string | 否 | Actor 令牌类型 URI |
| RequestedTokenType | string | 否 | 期望返回的令牌类型 |
| Scope | string | 否 | 请求的授权范围 |

### 使用场景

1. **令牌降级**：将具有较宽权限的令牌交换为具有有限范围的令牌
2. **服务间访问**：在服务之间传递相同的用户身份以获取所需的访问令牌

## 集成测试

`integration/` 目录下提供向真实 IDaaS Endpoint 请求令牌的端到端测试，覆盖每种 `authnMethod`。整个包由构建标签 `integration` 门控，不带标签时 `go test ./...`（含 CI）不会发起真实请求。运行细节与所需凭证见 [integration/README](integration/README.md)。

## 故障排查(错误码参考)

SDK 每个错误都带 `ErrorCode()`(用 `errors.As` 匹配 `interface{ ErrorCode() string }` 契约)。下表把每个码映射到原因与处置动作。

### 配置 / 启动(`Initialize` 快速失败)

| 错误码 | 原因 | 处置 |
| --- | --- | --- |
| `IDaaSCredentialProviderFactoryNotInit` | 未调 `factory.Init` 或 `Reset` 清空了单例 | 在任何 `GetIDaaSCredentialProvider` 之前调 `factory.Init` / `InitWithConfig` |
| `ClientConfigurationNotFound` | `InitWithConfig` 收到 `nil` 配置 | 传非 nil 的 `*config.IDaaSClientConfig` |
| `IDaaSInstanceIdNotFound` / `ClientIdNotFound` / `TokenEndpointNotFound` / `DeviceAuthorizationEndpointNotFound` / `AuthnConfigurationNotFound` | 必填配置字段缺失 | 在 `config.json` 中补齐 |
| `InvalidEndpointScheme` / `InvalidEndpointFormat` | `tokenEndpoint` / `issuerEndpoint` 非 `https://` 或非合法绝对 URL | 用 `https://` 绝对 URL;裸 host 会自动补全为 `https://` |
| `InsecureTLSDisallowed`(Experimental) | 启用了 `WithTLSEnforcement()` 且 `unsafeIgnoreSslCert=true` | 生产环境移除 `unsafeIgnoreSslCert`,或测试/mock server 场景去掉 `WithTLSEnforcement()` |
| `LoadConfigFileFailed` | `config.json` 不可读或非法 JSON | 检查路径、权限、JSON 语法 |
| `InvalidScope` / `MultipleAudienceNotSupported` / `InvalidStaleValueBehavior` / `UnsupportedIdentityType` / `UnsupportedAuthenticationMethod` | 不支持的枚举值 | 用支持的值(见[参数说明](#参数说明)) |
| `*EnvVarNameNotFound` / `*NotFound` / `PrivateKeyInvalid` | 凭证材料缺失/非法 | 把命名的环境变量设为合法值;私钥须为合法 PEM/PKCS#8 |

### 运行时(HTTP / token / 缓存)

| 错误码 | 原因 | 处置 |
| --- | --- | --- |
| `ConnectTimeOut` / `ReadTimeOut` | 网络超时 | 检查到 `tokenEndpoint` 的连通性;合理时调高 `httpConfiguration.connectTimeout`/`readTimeout` |
| `DnsLookupFailed` | DNS 不可解析 | 检查 VPC DNS / hosts |
| `TlsHandshakeFailed` | TLS / 证书校验失败 | 检查 CA 链、端点证书、时钟偏移 |
| `ConnectionReset` / `ResponseTruncated` | TCP RST / 提前 EOF | 重试;持续则查 LB / 代理 |
| `ResponseTooLarge` | 响应超客户端硬上限 | 疑似恶意/故障 IdP;抓取并上报 |
| `InvalidURL` | 请求 URL 不可解析 | 配置或 base URL 问题 |
| `AccessTokenNotFound` | token 响应缺 `access_token` | IdP 异常;抓取(脱敏后的)响应 |
| `InvalidExpiresIn` | `expires_in` ≤ 0 → 退化缓存 | 查 IdP;临时,下次刷新恢复 |
| `ClientRequestCanceled`(Experimental) | 调用方在凭证请求完成前取消了 `context` | 调用方超时/截止命中时的预期行为;`errors.Is(err, context.Canceled)` / `context.DeadlineExceeded` 区分取消原因 |
| `CachedRefreshInBackoff`(Experimental) | BLOCK 模式 stale 请求在刷新失败后的 10s 退避窗内被短路 | 稍后重试;保护 IdP 不被刷新洪流冲击 |
| `CachedResultStale` | 降级返回了过期缓存值 | 排查上游刷新失败 |
| `RefreshPanicRecovered`(Experimental) | 刷新 goroutine panic 被恢复;错误把 recovered 值以字符串形式带在 message 中 | 当作 SDK bug —— 抓日志上报;下次调用恢复刷新 |
| `GcpVmIdentityTokenFetchFailed` / `AzureVmIdentityTokenFetchFailed` / `*Empty` / `AzureVmIdentityTokenInvalidJson` | 云元数据服务拉取失败 | 确认工作负载确实在所声称的云 VM 上、IMDS 端点可达 |
| `OAuth2Error`(`OAuth2Failed`) | OAuth2 错误响应且无标准 `error` 字段 | 检视 IdP 响应;查 `clientId`/`scope`/`audience` |
| `UnexpectedError` | 内部未覆盖分支 | 当作 SDK bug —— 带日志上报 |

## 支持与反馈

- **问题反馈**：如有问题或建议，请提交 [GitHub Issue](https://github.com/cloud-idaas/idaas-go-core-sdk/issues)
- **安全漏洞**：请通过 [GitHub Security Advisories](https://github.com/cloud-idaas/idaas-go-core-sdk/security/advisories/new) 私下报告，不要提交公开 Issue

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 许可证授权。
