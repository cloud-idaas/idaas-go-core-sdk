# 集成测试（真实 IDaaS Endpoint）

覆盖 SDK 全部用户入口链路：M2M 换票、令牌交换（RFC 8693）、factory 公共 API、缓存、负面路径、
安全修复端到端。仓库只提交占位模板 `testdata/<authnMethod>.example.json`，真实环境配置与凭证都
放在本地 `testdata/.local/`，不入库。

整个包由构建标签 `integration` 门控：**不带标签时 `go build ./...` / `go vet ./...` / `go test ./...`
都不会编译或运行这些用例**，CI（无凭证、无内网）因此不受影响；CI 的 integration job
（`go test -tags integration -race ./...`）无凭证时全量 skip，等价于"编译 + 门控"校验。

## 覆盖范围

### M2M 换票（每种认证方式一个用例，`obtain_token_test.go` / `plugin_authn_test.go`）

| 测试方法 | authnMethod | 配置文件 | 需要的凭证 / 环境 |
| --- | --- | --- | --- |
| `TestClientSecretBasic` | `client_secret_basic` | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` |
| `TestClientSecretPost` | `client_secret_post` | `.local/client_secret_post.json` | `IDAAS_CLIENT_SECRET` |
| `TestClientSecretJwt` | `client_secret_jwt` | `.local/client_secret_jwt.json` | `IDAAS_CLIENT_SECRET`（HS256） |
| `TestPrivateKeyJwt` | `private_key_jwt` | `.local/private_key_jwt.json` | `IDAAS_PRIVATE_KEY`（RS256/ES256） |
| `TestPCA` | `pca` | `.local/pca.json` | `IDAAS_PRIVATE_KEY`（需与叶子证书配对） |
| `TestPkcs7` | `pkcs7` | `.local/pkcs7.json` | **仅真实阿里云 ECS**（IMDS 探活失败自动 skip） |
| `TestOidc` | `oidc`（COMPUTER） | `.local/oidc_computer.json` | 本地 ID Token 文件（`OIDC_TOKEN_FILE_PATH`） |
| `TestPkcs7AwsEc2` | `pkcs7` | `.local/pkcs7_aws_ec2.json` | **仅真实 AWS EC2**（IMDSv2 探活失败自动 skip） |
| `TestOidcKubernetes` | `oidc`（KUBERNETES） | `.local/oidc_kubernetes.json` | 集群内 Pod（SA token 路径可回落默认） |
| `TestOidcAzureVm` | `oidc`（AZURE_VM） | `.local/oidc_azure_vm.json` | **仅绑定了 MI 的 Azure VM**（探活=真实取 MI token） |
| `TestOidcGoogleVm` | `oidc`（GOOGLE_VM） | `.local/oidc_google_vm.json` | **仅 GCE VM**（metadata.google.internal 仅 GCP 内可解析） |
| `TestPluginAuthn` | `plugin` | 无独立配置* | 复用 `client_secret_basic` 链路（*插件由测试进程内注册，非配置驱动） |
| `TestAllAuthnMethods` | 其余 11 种配置驱动方式 | 逐个加载 | 全部（plugin 不在枚举内，见上；多云用例在非对应云上自动 skip） |

多云部署面的从零操作步骤（确认机器身份、在 IDaaS 侧登记联邦凭证、排错速查）见各用例文件顶部注释里的
探活命令，以及 [`scripts/run-integration-on-ecs.sh`](../scripts/run-integration-on-ecs.sh)
（阿里云 ECS PKCS#7 一键探活 + 执行 + 脱敏摘要）。

断言内容：`AccessToken` 非空、`TokenType=Bearer`、`ExpiresIn>0`、`Scope` 含期望值，并打印 JWT header
的 `alg/kid` 以确认实际走的签名路径（HS256 / RS256 / ES256）。

### 链路与行为（`token_exchange_test.go` / `factory_path_test.go` / `negative_test.go`）

| 测试方法 | 场景 | 前置 |
| --- | --- | --- |
| `TestCachedCredentialIsReused` | 同一 provider 二次取凭证命中缓存（令牌一致、无二次 HTTP） | `client_secret_basic` |
| `TestTokenExchange` | RFC 8693：M2M 取 subject token → 交换新令牌；负面：空 subject_token 必须被拒 | `client_secret_post` + 实例开通 token-exchange |
| `TestFactoryPublicApiFlow` | 用户真实入口：`factory.Init` → 取票 → 缓存复用 → exchange provider 创建 → `Reset` 后报 `FactoryNotInit` | `client_secret_basic` |
| `TestWrongClientSecretInvalidClient` | 负面路径：假 secret 必须被真实 endpoint 拒绝（`invalid_client`），错误文本不泄漏 secret | `client_secret_basic` |
| `TestRefreshTokenRenewal` | refresh_token 续期链路（`oauth2.OAuth2TokenUtil.RefreshToken` 公共 API） | `IDAAS_REFRESH_TOKEN` 环境变量（device code/human 流程取得；未设置 skip） |

### 安全修复端到端（`security_fixes_integration_test.go`）

| 测试方法 | 验证内容 | 开关 |
| --- | --- | --- |
| `TestFileOidcPermissionCheck_RealTokenFile` | OIDC token 文件权限校验在完整装配链路触发；核心契约 warn-only 不阻断 | `.local/oidc_computer.json` + token 文件 |
| `TestOpenBrowser_RealSubprocess_NoUserCodeLeak` | 真实 `xdg-open`/`open` 子进程下 URL 不泄漏 `user_code` | `IDAAS_IT_BROWSER=on`（会弹浏览器） |
| `TestHumanFederatedDeviceFlow_RealIdP` | human federated device flow：构造段自动；阻塞段需人工扫码并断言 `~/.cloud_idaas/human-cache/` 缓存写入 | `IDAAS_IT_HUMAN_FLOW=on` |

### 门控与 skip 约定

- `-tags integration`：编译门控（CI 无凭证时仍能验证可编译）。
- `-short` 或 `IDAAS_IT=off/0/false/no`：跳过真实请求。
- 缺 `.local/<name>.json` / 缺凭证环境变量：skip 并提示复制/设置命令。
- ECS IMDS 探活失败、OIDC token 文件不可读、endpoint DNS/连接不可达（负面用例）：skip 而非 FAIL，
  不把环境问题伪装成代码问题。
- `newProvider` 与 factory 一致地规范化 `staleValueBehavior`：`.local` 配置显式声明时按其生效，空值回退 `REFRESH`。

## 准备环境配置与凭证

```bash
cd integration/testdata
mkdir -p .local
# 环境配置：按需复制模板，填入实例的 idaasInstanceId / clientId / issuer / tokenEndpoint 等
for n in client_secret_basic client_secret_post client_secret_jwt private_key_jwt pca \
         pkcs7 pkcs7_aws_ec2 oidc_computer oidc_kubernetes oidc_azure_vm oidc_google_vm; do
  cp "$n.example.json" ".local/$n.json"
done
# 凭证：填入 IDAAS_CLIENT_SECRET / IDAAS_PRIVATE_KEY
cp credentials.env.example .local/credentials.env
```

`plugin.example.json` 是真实插件接入参考模板，集成运行不需要复制到 `.local`。

缺少某个 `.local/<authnMethod>.json` 时对应用例会 skip 并提示复制命令；凭证也可直接用环境变量临时覆盖，环境变量优先于文件内容。

## 运行

```bash
# 全部场景（必须带 -tags integration）
go test -tags integration -v ./integration/

# 只跑某一种
go test -tags integration -v -run TestClientSecretBasic ./integration/
go test -tags integration -v -run 'TestClientSecret' ./integration/   # 三种 client_secret 变体
go test -tags integration -v -run TestPlugin ./integration/            # 插件认证（含负面子用例）
go test -tags integration -v -run TestTokenExchange ./integration/     # RFC 8693 令牌交换
go test -tags integration -v -run TestFactoryPublicApiFlow ./integration/  # factory 公共入口
go test -tags integration -v -run TestWrongClientSecret ./integration/  # 负面路径
go test -tags integration -v -run TestPkcs7AwsEc2 ./integration/        # AWS EC2 PKCS7（需在该云上）
go test -tags integration -v -run 'TestOidc(Kubernetes|AzureVm|GoogleVm)' ./integration/  # OIDC 多云
go test -tags integration -v -run TestRefreshTokenRenewal ./integration/ # refresh_token 续期（需 IDAAS_REFRESH_TOKEN）

# 只编译不发包（-short 或 IDAAS_IT=off 均可跳过真实请求）
go test -tags integration -short ./integration/
IDAAS_IT=off go test -tags integration ./integration/
```

## 已知问题

- `pca`：`clientX509Certificate` 必须与 `IDAAS_PRIVATE_KEY` 配对；`x509CertChains` 若只含中间 CA，
  能否通过取决于服务端联邦凭证（`applicationFederatedCredentialName`）上登记的 CA 材料，报证书链校验失败时需补 RootCA。
- `pkcs7` / `oidc_computer`：元数据服务地址硬编码 `100.100.100.200`，token 文件须真实可解析为 JWT。
- endpoint 需从当前网络可达，否则报 `DnsLookupFailed`/`ConnectTimeOut`（负面用例对此 skip）。
- `TestTokenExchange` 依赖服务端实例已开通 token-exchange grant；未开通时报 OAuth2 错误（附 requestId）。

## 尚未覆盖（后续按需补）

- 缓存 prefetch / 异步刷新 / jitter 的时间链路（依赖服务端签发短时效 token，难以稳定自动化）。
- invalid_grant 回退（凭证轮换瞬间窗口）的真实环境验证——当前由 mock 单测
  `invalid_grant_fallback_test.go` 覆盖逻辑分支。
- `HUAWEI_CLOUD_ECS` / `ALIBABA_CLOUD_ECI` / `ALIBABA_CLOUD_ACK` / `AWS_EKS` / `CUSTOM` 等
  部署环境枚举当前未接入取票路由（validator 白名单外会明确报 `UnsupportedClientDeployEnvironment`），
  属于实现缺口而非测试缺口。
