# IDaaS Go Core SDK Samples

本目录包含 IDaaS Go Core SDK 的使用示例，覆盖阿里云 IDaaS（EIAM）M2M 客户端令牌调用文档中支持的各种认证方式。

> 阿里云官方文档参考：[通过客户端凭证模式获取 M2M 认证的访问令牌](https://help.aliyun.com/zh/idaas/eiam/user-guide/m2m-client-token-invocation-example)

## 设计原则

**SDK 的核心抽象 = `Factory.CreateCredentialProvider()`**，它会根据配置文件里的 `authnMethod` 自动分发到对应认证流程。
因此 sample 代码本身完全不需要为每种 authnMethod 写一遍，**只需切换配置文件即可**。

本目录提供 **4 个 sample**，覆盖所有官方文档场景：

| 文件 | 覆盖场景 | 备注 |
|---|---|---|
| `obtain_token_sample.go` | 全部 7 种 CLIENT 认证方式 | 通用入口；切换 `-config` 指向不同配置即可 |
| `device_code_sample.go`  | HUMAN identity 的 Device Code 流程 | UX 提示文案与机器流程独立呈现 |
| `refresh_token_sample.go` | refresh_token 续期 | 不走 factory，直接调 `OAuth2TokenUtil.RefreshToken` |
| `token_exchange_sample.go` | RFC 8693 令牌交换 | 不走 factory，直接调 `IDaaSMachineTokenExchangeCredentialProvider` |

## 前置条件

1. 安装 Go 1.21 或更高版本
2. 在 IDaaS 控制台创建 M2M 应用，并按需配置 Token Endpoint 认证方式
3. 通过配置文件或环境变量提供凭证（推荐使用配置文件）

## 配置加载优先级（从高到低）

1. `-config /path/to/cfg.json`（显式指定）
2. 环境变量 `CLOUD_IDAAS_CONFIG_PATH`
3. 默认路径 `~/.cloud_idaas/client-config.json`
4. 独立环境变量 `CLOUD_IDAAS_CLIENT_ID` + `CLOUD_IDAAS_TOKEN_ENDPOINT` 等

> **大小写约定**：`authnMethod` 与 `identityType` 配置值大小写不敏感（SDK 内部自动归一化），但为与阿里云官方文档风格保持一致，本仓库所有示例统一使用大写写法（如 `CLIENT_SECRET_BASIC` / `CLIENT`）。

> 由于 `samples/` 目录下所有文件都是 `package main` + `func main()`，**不能使用 `go build ./samples/...`**。请单独运行某个 sample，例如：`go run samples/obtain_token_sample.go -config /path/to/cfg.json`。

---

## 运行示例

### `obtain_token_sample.go` —— 通用 Access Token 获取入口

```bash
# 走默认配置（~/.cloud_idaas/client-config.json）
go run samples/obtain_token_sample.go

# 显式指定配置文件
go run samples/obtain_token_sample.go -config /path/to/private_key_jwt.json
```

下文 7 段 JSON 配置示例分别对应一种 `authnMethod`，保存为 `.json` 文件后用 `-config` 传入即可。

### `device_code_sample.go` —— 人类 Device Code 登录

```bash
go run samples/device_code_sample.go -config /path/to/human-device.json
```

按提示在浏览器完成授权后，SDK 自动轮询 token endpoint 拿到 Access Token。
SDK 内部按 RFC 8628 §3.5 区分 `authorization_pending` / `slow_down` / `access_denied` / `expired_token`。

### `refresh_token_sample.go` —— Refresh Token 续期

```bash
export IDAAS_REFRESH_TOKEN='your_refresh_token'
go run samples/refresh_token_sample.go -config /path/to/any-config.json
```

> 任何含 `clientId` + `tokenEndpoint` 的配置都可用，因为 refresh_token grant 不需要 client_secret。

### `token_exchange_sample.go` —— Token Exchange (RFC 8693)

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
export IDAAS_SUBJECT_TOKEN='the_token_to_exchange'
go run samples/token_exchange_sample.go -config /path/to/client_secret_post.json
```

> 配置必须包含 `client_secret_basic` / `client_secret_post` 类认证，SDK 才能从 `clientSecretEnvVarName` 指定的 env var 读到 secret。

---

## 各 authnMethod 配置文件示例

### 1. `client_secret_basic` —— Client Secret + HTTP Basic Auth

`client_secret` 通过 `Authorization: Basic base64(clientId:clientSecret)` 头发送。

```json
{
    "clientId": "app_xxx",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api://api.xxxxx.com|read:file",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "CLIENT_SECRET_BASIC",
        "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
    }
}
```

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
go run samples/obtain_token_sample.go -config /path/to/client_secret_basic.json
```

### 2. `client_secret_post` —— Client Secret + Form Post

`client_id` / `client_secret` 通过 form body 字段发送。

```json
{
    "clientId": "app_xxx",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api://api.xxxxx.com|read:file",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "CLIENT_SECRET_POST",
        "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
    }
}
```

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
go run samples/obtain_token_sample.go -config /path/to/client_secret_post.json
```

### 3. `client_secret_jwt` —— Client Secret + HS256 JWT 客户端断言

SDK 用 `client_secret` 作为 HMAC 密钥自动签发 HS256 JWT 作为 `client_assertion`，避免 secret 明文随请求传输。

```json
{
    "clientId": "app_xxx",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api://api.xxxxx.com|read:file",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "CLIENT_SECRET_JWT",
        "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
    }
}
```

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
go run samples/obtain_token_sample.go -config /path/to/client_secret_jwt.json
```

### 4. `private_key_jwt` —— RS256 JWT 客户端断言

SDK 用 PEM 私钥自动签发 JWT 作为 `client_assertion`。

```json
{
    "clientId": "app_xxx",
    "issuer": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api://api.xxxxx.com|read:file",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "PRIVATE_KEY_JWT",
        "privateKeyEnvVarName": "IDAAS_PRIVATE_KEY"
    }
}
```

```bash
# 方式 A：环境变量直接装 PEM 文本（推荐）
export IDAAS_PRIVATE_KEY="$(cat /path/to/private_key.pem)"

# 方式 B：环境变量装文件路径（绝对路径或以 ~/ 开头）
export IDAAS_PRIVATE_KEY=/absolute/path/to/private_key.pem

go run samples/obtain_token_sample.go -config /path/to/private_key_jwt.json
```

### 5. `pca` —— Private CA X509 证书认证

SDK 用 PEM 私钥签发 RS256/ES256 JWT 作为 `client_assertion`（`iss=sub=clientId`），同时提交终端证书与中间证书链。IDaaS 通过应用上配置的 PrivateCA 联邦凭证验证证书链与签名。`client_assertion_type` 为 IDaaS 自定义的 `x509-jwt-bearer`。

```json
{
    "clientId": "app_xxx",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api://api.xxxxx.com|.all",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "PCA",
        "privateKeyEnvVarName": "IDAAS_PRIVATE_KEY",
        "applicationFederatedCredentialName": "private_ca",
        "clientX509Certificate": "-----BEGIN CERTIFICATE-----\nMIIB...(终端证书)...\n-----END CERTIFICATE-----",
        "x509CertChains": "-----BEGIN CERTIFICATE-----\nMIIB...(中间CA证书)...\n-----END CERTIFICATE-----"
    }
}
```

```bash
export IDAAS_PRIVATE_KEY="$(cat /path/to/private_key.pem)"
go run samples/obtain_token_sample.go -config /path/to/pca.json
```

> 提示：
> - `clientX509Certificate` 为终端证书（叶子证书）PEM，`x509CertChains` 为中间证书链 PEM（多张证书直接换行拼接）。
> - `applicationFederatedCredentialName` 对应 IDaaS 控制台上创建的 PrivateCA 联邦凭证名称。
> - `IDAAS_PRIVATE_KEY` 环境变量既支持直接装 PEM 文本，也支持装文件路径，SDK 会自动识别。

### 6. `oidc` —— OIDC 联邦认证（K8s Service Account）

SDK 自动读取 `/var/run/secrets/kubernetes.io/serviceaccount/token`，作为 OIDC `client_assertion` 发送。需配合 `clientDeployEnvironment` 指定运行环境。

```json
{
    "clientId": "app_xxx",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api://api.xxxxx.com|read:file",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "OIDC",
        "applicationFederatedCredentialName": "k8s_federation",
        "clientDeployEnvironment": "KUBERNETES"
    }
}
```

```bash
# 必须在 K8s Pod 内运行
go run samples/obtain_token_sample.go -config /path/to/oidc_kubernetes.json
```

### 7. `pkcs7` —— PKCS#7 联邦认证（阿里云 ECS）

SDK 自动从 ECS Metadata Service 拉取 PKCS#7 attested document 作为 `client_assertion`。需配合 `clientDeployEnvironment` 指定运行环境。

```json
{
    "clientId": "app_xxx",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api://api.xxxxx.com|.all",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "PKCS7",
        "applicationFederatedCredentialName": "aliyun_ecs",
        "clientDeployEnvironment": "ALIBABA_CLOUD_ECS"
    }
}
```

```bash
# 必须在阿里云 ECS 实例内运行
go run samples/obtain_token_sample.go -config /path/to/pkcs7_ecs.json
```

### 8. `plugin` —— 自定义插件认证（如阿里云 EIAM OpenAPI）

PLUGIN 模式下 SDK 不发起任何 HTTP 请求，完全委托给已注册的插件获取 token。

**使用方式**：在 `main` 包中匿名导入插件包即可自动注册：

```go
import _ "github.com/aliyun/idaas-go-core-alibabacloud-authentication-plugin"
```

```json
{
    "clientId": "app_xxx",
    "idaasInstanceId": "idaas_xxx",
    "issuer": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "scope": "api.example.com|read:file",
    "openApiEndpoint": "eiam.cn-hangzhou.aliyuncs.com",
    "authnConfiguration": {
        "identityType": "CLIENT",
        "authnMethod": "PLUGIN",
        "pluginName": "alibabacloudPluginCredentialProvider"
    }
}
```

```bash
# 配置阿里云凭证
export ALIBABA_CLOUD_ACCESS_KEY_ID="your_ak"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your_sk"

# 运行（sample 位于插件项目中）
cd /path/to/idaas-go-core-alibabacloud-authentication-plugin
go run samples/plugin_authentication.go -config /path/to/plugin.json
```

> 提示：
> - `pluginName` 必须与插件 `GetName()` 返回值一致
> - `openApiEndpoint` 为阿里云 EIAM OpenAPI 端点（如 `eiam.cn-hangzhou.aliyuncs.com`）
> - 阿里云凭证通过默认凭证链自动获取（环境变量 > ECS Metadata > `~/.aliyun/config.json`）

### 9. 人类 Device Code 登录（HUMAN identity）

适用于 CLI / 受限输入设备的人类用户登录。**必须使用 `device_code_sample.go`**（识别 identityType=HUMAN 并提供 UX 提示）。

```json
{
    "clientId": "app_xxx",
    "tokenEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/token",
    "deviceAuthorizationEndpoint": "https://xxx.aliyunidaas.com/api/v2/iauths_system/oauth2/device_authorization",
    "scope": "api://api.xxxxx.com|read:file",
    "authnConfiguration": {
        "identityType": "HUMAN",
        "humanAuthenticateClientId": "iap_developer"
    }
}
```

```bash
go run samples/device_code_sample.go -config /path/to/human-device.json
```

---

## 扩展场景

| 文档场景 | 状态 | 说明 |
|---|---|---|
| `plugin` 自定义凭证插件 | ✅ 已实现 | 通过匿名导入插件包自动注册，sample 位于插件项目 `samples/plugin_authentication.go` |

---

## 注意事项

- **不要在代码或配置文件中硬编码 client_secret / 私钥**，所有敏感信息均通过环境变量名注入
- zsh 下 export 带特殊字符（`$`、`!`、`#` 等）的 secret 时**必须用单引号**包裹
- 配置的 `authnMethod` 必须与 IDaaS 控制台上"Token Endpoint Authentication Method"配置一致，否则会返回 `invalid_client_credential`
- `scope` 格式为 `resourceServerIdentifier|scopeName`，使用 `|.all` 表示获取当前 client 已授权的全部 scope
