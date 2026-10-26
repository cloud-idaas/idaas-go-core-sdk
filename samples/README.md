# IDaaS Go Core SDK Samples

本目录包含 IDaaS Go Core SDK 的使用示例，覆盖阿里云 IDaaS（EIAM）M2M 客户端令牌调用文档中支持的各种认证方式。

> 阿里云官方文档参考：[通过客户端凭证模式获取 M2M 认证的访问令牌](https://help.aliyun.com/zh/idaas/eiam/user-guide/m2m-client-token-invocation-example)

> **关于本 module**：`samples/` 是一个带独立 `go.mod` 的嵌套子 module（`require` 主 SDK + `replace => ../` 指向仓库工作副本），与主 SDK module 边界隔离，**不会作为独立 module 发布**。它仅用于本地构建/运行示例，依赖与 Go 版本需求不会反向抬高主 SDK 的下限。

## 设计原则

**SDK 的核心抽象 = `factory.GetIDaaSCredentialProvider()`**，它会根据配置文件里的 `authnMethod` 自动分发到对应认证流程。
因此 sample 代码本身完全不需要为每种 authnMethod 写一遍，**只需切换配置文件即可**。

本目录提供 **4 个 sample**，覆盖所有官方文档场景：

| 文件 | 覆盖场景 | 备注 |
|---|---|---|
| `obtain-token/` | 全部 7 种 CLIENT 认证方式 | 通用入口；切换 `-config` 指向不同配置即可 |
| `device-code/`  | HUMAN identity 的 Device Code 流程 | UX 提示文案与机器流程独立呈现 |
| `refresh-token/` | refresh_token 续期 | 不走 factory provider，直接调 `OAuth2TokenUtil.RefreshToken` |
| `token-exchange/` | RFC 8693 令牌交换 | 走 `factory.GetIDaaSTokenExchangeCredentialProvider()` |

## 前置条件

1. 安装 Go 1.21 或更高版本
2. 在 IDaaS 控制台创建 M2M 应用，并按需配置 Token Endpoint 认证方式
3. 通过配置文件或环境变量提供凭证（推荐使用配置文件）

## 配置加载优先级（从高到低）

1. `-config /path/to/cfg.json`（显式指定）
2. 环境变量 `CLOUD_IDAAS_CONFIG_PATH`
3. 默认路径 `~/.cloud_idaas/client-config.json`

> **配置变更**：独立环境变量（`CLOUD_IDAAS_CLIENT_ID` 等）已从默认优先级链移除。如需从环境变量加载，请显式调用 `config.NewConfigReader().LoadFromEnv()`。

> **大小写约定**：`authnMethod` 与 `identityType` 配置值大小写不敏感（SDK 内部自动归一化），但为与阿里云官方文档风格保持一致，本仓库所有示例统一使用大写写法（如 `CLIENT_SECRET_BASIC` / `CLIENT`）。

> **`samples/` 是一个独立 module**。它有自己的 `go.mod`，并通过 `replace` 指向上一级目录的 SDK 源码，因此样例跑的永远是当前工作副本，不需要等 SDK 发版。
>
> 这样拆分是为了让样例可以自由使用 Go 1.21+ 特性，而不会反向抬高 SDK 自身承诺的 **Go 1.18** 下限。
>
> 代价是：**所有命令都要先 `cd samples`**，在仓库根目录执行 `go run ./samples/...` 不再有效，根目录的 `go build ./...` 也不会再构建样例。
>
> ```bash
> cd samples
> go build ./...                 # 构建全部样例
> go run ./obtain-token -config /path/to/cfg.json
> ```

---

## 运行示例

### `obtain-token/` —— 通用 Access Token 获取入口

```bash
# 走默认配置（~/.cloud_idaas/client-config.json）
go run ./obtain-token

# 显式指定配置文件
go run ./obtain-token -config /path/to/private_key_jwt.json
```

下文 [各 authnMethod 配置文件示例](#各-authnmethod-配置文件示例) 列出每种方式的 `authnConfiguration` 差异块，补上顶层公共字段保存为 `.json` 后用 `-config` 传入即可。

### `device-code/` —— 人类 Device Code 登录

```bash
go run ./device-code -config /path/to/human-device.json
```

按提示在浏览器完成授权后，SDK 自动轮询 token endpoint 拿到 Access Token。
SDK 内部按 RFC 8628 §3.5 区分 `authorization_pending` / `slow_down` / `access_denied` / `expired_token`。

### `refresh-token/` —— Refresh Token 续期

```bash
export IDAAS_REFRESH_TOKEN='your_refresh_token'
go run ./refresh-token -config /path/to/any-config.json
```

> 任何含 `clientId` + `tokenEndpoint` 的配置都可用，因为 refresh_token grant 不需要 client_secret。

### `token-exchange/` —— Token Exchange (RFC 8693)

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
export IDAAS_SUBJECT_TOKEN='the_token_to_exchange'
go run ./token-exchange -config /path/to/client_secret_post.json
```

> 配置必须包含 `client_secret_basic` / `client_secret_post` 类认证，SDK 才能从 `clientSecretEnvVarName` 指定的 env var 读到 secret。

---

## 各 authnMethod 配置文件示例

完整顶层结构（`clientId` / `tokenEndpoint` / `scope` 等）见[主 README 配置文件说明](../README_zh.md#配置文件说明)与 [authnMethod 字段对应关系](../README_zh.md#authnmethod-字段值和-authnconfiguration-字段对应关系)表。下面每种方式只列出差异部分——`authnConfiguration` 块（及少数方式需要的额外顶层字段）+ 运行命令。

### 1. `client_secret_basic` —— Client Secret + HTTP Basic Auth

`client_secret` 通过 `Authorization: Basic base64(clientId:clientSecret)` 头发送。

```json
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "CLIENT_SECRET_BASIC",
    "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
}
```

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
go run ./obtain-token -config /path/to/client_secret_basic.json
```

### 2. `client_secret_post` —— Client Secret + Form Post

`client_id` / `client_secret` 通过 form body 字段发送。

```json
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "CLIENT_SECRET_POST",
    "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
}
```

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
go run ./obtain-token -config /path/to/client_secret_post.json
```

### 3. `client_secret_jwt` —— Client Secret + HS256 JWT 客户端断言

SDK 用 `client_secret` 作为 HMAC 密钥自动签发 HS256 JWT 作为 `client_assertion`，避免 secret 明文随请求传输。

```json
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "CLIENT_SECRET_JWT",
    "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
}
```

```bash
export IDAAS_CLIENT_SECRET='your_client_secret'
go run ./obtain-token -config /path/to/client_secret_jwt.json
```

### 4. `private_key_jwt` —— RS256 JWT 客户端断言

SDK 用 PEM 私钥自动签发 JWT 作为 `client_assertion`。`issuer` 顶层字段必填（JWT `iss` 声明需要）。

```json
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "PRIVATE_KEY_JWT",
    "privateKeyEnvVarName": "IDAAS_PRIVATE_KEY"
}
```

```bash
# 方式 A：环境变量直接装 PEM 文本（推荐）
export IDAAS_PRIVATE_KEY="$(cat /path/to/private_key.pem)"

# 方式 B：环境变量装文件路径（绝对路径或以 ~/ 开头）
export IDAAS_PRIVATE_KEY=/absolute/path/to/private_key.pem

go run ./obtain-token -config /path/to/private_key_jwt.json
```

> `IDAAS_PRIVATE_KEY` 既支持直接装 PEM 文本，也支持装文件路径，SDK 会自动识别——这是 `private_key_jwt` 与 `pca` 共有的私钥注入约定。

### 5. `pca` —— Private CA X509 证书认证

SDK 用 PEM 私钥签发 RS256/ES256 JWT 作为 `client_assertion`（`iss=sub=clientId`），同时提交终端证书与中间证书链。IDaaS 通过应用上配置的 PrivateCA 联邦凭证验证证书链与签名。`client_assertion_type` 为 IDaaS 自定义的 `x509-jwt-bearer`。

```json
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "PCA",
    "privateKeyEnvVarName": "IDAAS_PRIVATE_KEY",
    "applicationFederatedCredentialName": "private_ca",
    "clientX509Certificate": "-----BEGIN CERTIFICATE-----\nMIIB...(终端证书)...\n-----END CERTIFICATE-----",
    "x509CertChains": "-----BEGIN CERTIFICATE-----\nMIIB...(中间CA证书)...\n-----END CERTIFICATE-----"
}
```

```bash
export IDAAS_PRIVATE_KEY="$(cat /path/to/private_key.pem)"
go run ./obtain-token -config /path/to/pca.json
```

> - `clientX509Certificate` 为终端证书（叶子证书）PEM，`x509CertChains` 为中间证书链 PEM（多张证书直接换行拼接）。
> - `applicationFederatedCredentialName` 对应 IDaaS 控制台上创建的 PrivateCA 联邦凭证名称。

### 6. `oidc` —— OIDC 联邦认证（K8s Service Account）

SDK 自动读取 `/var/run/secrets/kubernetes.io/serviceaccount/token`，作为 OIDC `client_assertion` 发送。需配合 `clientDeployEnvironment` 指定运行环境。

```json
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "OIDC",
    "applicationFederatedCredentialName": "k8s_federation",
    "clientDeployEnvironment": "KUBERNETES"
}
```

```bash
# 必须在 K8s Pod 内运行
go run ./obtain-token -config /path/to/oidc_kubernetes.json
```

### 7. `pkcs7` —— PKCS#7 联邦认证（阿里云 ECS）

SDK 自动从 ECS Metadata Service 拉取 PKCS#7 attested document 作为 `client_assertion`。需配合 `clientDeployEnvironment` 指定运行环境。

```json
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "PKCS7",
    "applicationFederatedCredentialName": "aliyun_ecs",
    "clientDeployEnvironment": "ALIBABA_CLOUD_ECS"
}
```

```bash
# 必须在阿里云 ECS 实例内运行
go run ./obtain-token -config /path/to/pkcs7_ecs.json
```

### 8. `plugin` —— 自定义插件认证（如阿里云 EIAM OpenAPI）

PLUGIN 模式下 SDK 不发起任何 HTTP 请求，完全委托给已注册的插件获取 token。需额外顶层字段 `openApiEndpoint`（插件通过它调用 EIAM OpenAPI `GenerateOauthToken`）。

**使用方式**：在 `main` 包中匿名导入插件包即可自动注册：

```go
import _ "github.com/cloud-idaas/idaas-go-core-alibabacloud-authentication-plugin"
```

```json
"openApiEndpoint": "eiam.cn-hangzhou.aliyuncs.com",
"authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "PLUGIN",
    "pluginName": "alibabacloudPluginCredentialProvider"
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

> - `pluginName` 必须与插件 `GetName()` 返回值一致。
> - 阿里云凭证通过默认凭证链自动获取（环境变量 > ECS Metadata > `~/.aliyun/config.json`），无法在配置文件中硬编码 AK/SK。

### 9. 人类 Device Code 登录（HUMAN identity）

适用于 CLI / 受限输入设备的人类用户登录。**必须使用 `device-code/`**（识别 identityType=HUMAN 并提供 UX 提示）。需额外顶层字段 `deviceAuthorizationEndpoint`。

```json
"deviceAuthorizationEndpoint": "https://your-idaas-instance.aliyuncs.com/api/v2/iauths_system/oauth2/device_authorization",
"authnConfiguration": {
    "identityType": "HUMAN",
    "humanAuthenticateClientId": "iap_developer"
}
```

```bash
go run ./device-code -config /path/to/human-device.json
```

---

## 注意事项

- **不要在代码或配置文件中硬编码 client_secret / 私钥**，所有敏感信息均通过环境变量名注入
- zsh 下 export 带特殊字符（`$`、`!`、`#` 等）的 secret 时**必须用单引号**包裹
- 配置的 `authnMethod` 必须与 IDaaS 控制台上"Token Endpoint Authentication Method"配置一致，否则会返回 `invalid_client_credential`
- `scope` 格式为 `resourceServerIdentifier|scopeName`，使用 `|.all` 表示获取当前 client 已授权的全部 scope
