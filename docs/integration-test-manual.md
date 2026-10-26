# IDaaS Go Core SDK 集成测试操作手册

> **适用分支**: `main`
> **最后更新**: 2026-10-22
> **测试代码位置**: `integration/` 目录
> **配套脚本**: `scripts/run-integration-item-by-item.sh`（逐项矩阵）、`scripts/run-integration-on-ecs.sh`（ECS 专用）

---

## 目录

- [一、总览](#一总览)
- [二、环境准备](#二环境准备)
- [三、测试用例清单](#三测试用例清单)
- [四、M2M 换票场景](#四m2m-换票场景)
- [五、链路与行为场景](#五链路与行为场景)
- [六、负面路径场景](#六负面路径场景)
- [七、安全修复端到端场景](#七安全修复端到端场景)
- [八、Factory 公共 API 扩展场景](#八factory-公共-api-扩展场景)
- [九、WithContext 方法场景](#九withcontext-方法场景)
- [十、TokenListener 场景](#十tokenlistener-场景)
- [十一、StaleValueBehavior 场景](#十一stalevaluebehavior-场景)
- [十二、未实现部署环境场景](#十二未实现部署环境场景)
- [十三、一键运行全部场景](#十三一键运行全部场景)
- [十四、常见问题排查](#十四常见问题排查)
- [附录](#附录)

---

## 一、总览

### 1.1 测试架构

本 SDK 集成测试覆盖 **26 个测试用例**，分为四大类：

| 分类 | 用例数 | 说明 |
|------|--------|------|------|
| M2M 换票 | 12 | 8 种认证方式 + 多云部署面 + Plugin + 全量回归 |
| 链路与行为 | 10 | 缓存复用、Token Exchange、Factory API、Refresh Token |
| 负面路径 | 6 | 错误凭证拒绝 + 凭证防泄漏 |
| 安全修复 | 3 | 文件权限、浏览器防泄漏、Human Device Flow |

### 1.2 构建标签门控

所有集成测试文件都带 `//go:build integration` 标签：

```bash
# 默认编译/测试不包含集成测试（CI 安全）
go build ./...
go test ./...

# 显式开启集成测试
go test -tags integration -v ./integration/
```

### 1.3 跳过机制

| 条件 | 行为 |
|------|------|------|
| `-short` 标志 | 跳过所有集成测试 |
| `IDAAS_IT=off` / `0` / `false` / `no` | 跳过所有集成测试 |
| 缺少 `.local/<name>.json` 配置文件 | 跳过对应用例并提示复制命令 |
| 缺少凭证环境变量 | 跳过对应用例并提示设置命令 |
| 云元数据服务不可达（ECS/EC2/Azure/GCP） | 跳过对应用例（环境探活失败） |
| endpoint DNS/连接不可达 | 跳过对应用例（不把环境问题当代码问题） |

---

## 二、环境准备

### 2.1 基础环境

| # | 条件 | 校验命令 | 最低版本 |
|---|------|----------|----------|
| 1 | Go 已安装 | `go version` | 1.18 |
| 2 | 代码已拉取且可编译 | `go vet -tags integration ./integration/` | - |
| 3 | 时钟同步（JWT nbf/exp 校验依赖） | `date -u` 与 UTC 偏差 < 5min | - |

### 2.2 配置与凭证准备

#### 步骤 1：创建本地配置目录

```bash
cd integration/testdata
mkdir -p .local
```

> **安全提示**：`testdata/.local/` 已被 `.gitignore` 忽略，所有真实配置和凭证都存放在此，**切勿提交到仓库**。

#### 步骤 2：复制配置文件模板

按需复制要测试的场景模板：

```bash
cd integration/testdata

# 按需复制 - 只复制你要测试的场景即可
for n in client_secret_basic client_secret_post client_secret_jwt private_key_jwt pca \
         pkcs7 pkcs7_aws_ec2 oidc_computer oidc_kubernetes oidc_azure_vm oidc_google_vm; do
  cp "$n.example.json" ".local/$n.json"
done
```

#### 步骤 3：编辑配置文件，填入真实值

每个 `.local/<name>.json` 都需要替换以下占位字段：

| 占位字段 | 说明 | 获取方式 |
|----------|------|----------|
| `idaasInstanceId` | IDaaS 实例 ID（如 `idaas_xxx`） | IDaaS 控制台 - 实例详情 |
| `clientId` | 应用客户端 ID（如 `app_xxx`） | IDaaS 控制台 - 应用详情 |
| `issuer` | OAuth2 Issuer URL | IDaaS 控制台 - 应用 - OAuth2 元数据 |
| `tokenEndpoint` | Token 端点 URL | `https://<实例域名>/api/v2/iauths_system/oauth2/token` |
| `scope` | 授权范围 | 格式：`urn:cloud:idaas:pam\|urn:alibaba:idaas:scope:<resource>:<action>` |
| `applicationFederatedCredentialName` | 联邦凭证名称 | IDaaS 控制台 - 应用 - 联邦凭证 |

**示例**（以 `client_secret_basic` 为例）：

```bash
vim .local/client_secret_basic.json
```

```json
{
  "idaasInstanceId": "idaas_actual_instance_id",
  "clientId": "app_actual_client_id",
  "issuer": "https://my-instance.example.com/api/v2/iauths_system/oauth2",
  "tokenEndpoint": "https://my-instance.example.com/api/v2/iauths_system/oauth2/token",
  "scope": "urn:cloud:idaas:pam|urn:alibaba:idaas:scope:cloud_account_resource:manage_all",
  "httpConfiguration": { "connectTimeout": 5000, "readTimeout": 10000 },
  "authnConfiguration": {
    "identityType": "CLIENT",
    "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET",
    "authnMethod": "CLIENT_SECRET_BASIC"
  }
}
```

#### 步骤 4：准备凭证

```bash
cp credentials.env.example .local/credentials.env
vim .local/credentials.env
```

凭证文件内容：

```bash
# client_secret 方式需要（TC-01/02/03）
IDAAS_CLIENT_SECRET=your-actual-client-secret

# 私钥方式需要（TC-04/05），可填 PEM 原文或文件路径
IDAAS_PRIVATE_KEY=testdata/.local/your-client.key
```

**私钥文件准备**（TC-04/05 需要）：

```bash
cp /path/to/your/private.key .local/your-client.key
chmod 600 .local/your-client.key
```

#### 步骤 5：OIDC 场景的 ID Token 文件（TC-08 需要）

```bash
export OIDC_TOKEN_FILE_PATH=/path/to/your/id-token.jwt
```

> **注意**：ID Token 必须是由 IDaaS 联邦凭证信任的 issuer 签发的有效 JWT，过期 token 会被服务端拒绝。

### 2.3 网络连通性验证

```bash
# 验证 IDaaS endpoint 可达
curl -s -o /dev/null -w '%{http_code}\n' https://your-instance.example.com/api/v2/iauths_system/oauth2/token
# 期望：非 000（000 表示 DNS/连接失败）
```

---

## 三、测试用例清单

| 编号 | 用例名 | 场景 | 配置文件 | 所需凭证/环境 | 自动化 | 运行状态（2026-10-23） |
|------|--------|------|----------|---------------|--------|------|
| TC-01 | `TestClientSecretBasic` | M2M client_secret_basic | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-02 | `TestClientSecretPost` | M2M client_secret_post | `.local/client_secret_post.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-03 | `TestClientSecretJwt` | M2M client_secret_jwt (HS256) | `.local/client_secret_jwt.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-04 | `TestPrivateKeyJwt` | M2M private_key_jwt (RS256/ES256) | `.local/private_key_jwt.json` | `IDAAS_PRIVATE_KEY` | 全自动  | ✅ PASS |
| TC-05 | `TestPCA` | M2M PrivateCA | `.local/pca.json` | `IDAAS_PRIVATE_KEY` + 证书 | 全自动  | ✅ PASS |
| TC-06 | `TestPkcs7` | M2M PKCS7 @ 阿里云 ECS | `.local/pkcs7.json` | 阿里云 ECS 实例 | 全自动（非 ECS 自动 skip）  | ⏭️ SKIP（需阿里云 ECS） |
| TC-07 | `TestPkcs7AwsEc2` | M2M PKCS7 @ AWS EC2 | `.local/pkcs7_aws_ec2.json` | AWS EC2 实例 | 全自动（非 EC2 自动 skip）  | ⏭️ SKIP（需 AWS EC2） |
| TC-08 | `TestOidc` | M2M OIDC @ COMPUTER | `.local/oidc_computer.json` | ID Token 文件 | 全自动  | ⏭️ SKIP（需 OIDC_TOKEN_FILE_PATH） |
| TC-09 | `TestOidcKubernetes` | M2M OIDC @ K8s | `.local/oidc_kubernetes.json` | 集群内 Pod | 全自动（非 K8s 自动 skip）  | ⏭️ SKIP（需 K8s 集群） |
| TC-10 | `TestOidcAzureVm` | M2M OIDC @ Azure VM | `.local/oidc_azure_vm.json` | Azure VM + MI | 全自动（非 Azure 自动 skip）  | ⏭️ SKIP（需 Azure VM） |
| TC-11 | `TestOidcGoogleVm` | M2M OIDC @ GCE VM | `.local/oidc_google_vm.json` | GCE VM | 全自动（非 GCP 自动 skip）  | ⏭️ SKIP（需 GCE VM） |
| TC-12 | `TestPluginAuthn` | M2M PLUGIN | 复用 `client_secret_basic` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-13 | `TestAllAuthnMethods` | 全认证方式回归 | 逐个加载 | 全部 | 全自动  | ✅ PASS |
| TC-14 | `TestCachedCredentialIsReused` | 缓存复用 | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-15 | `TestTokenExchange` | RFC 8693 令牌交换 | `.local/client_secret_post.json` | `IDAAS_CLIENT_SECRET` + 实例开通 token-exchange | 全自动  | ❌ FAIL（服务端 token 校验问题） |
| TC-16 | `TestFactoryPublicApiFlow` | Factory 公共 API 完整流程 | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-17 | `TestRefreshTokenRenewal` | Refresh Token 续期 | `.local/client_secret_basic.json` | `IDAAS_REFRESH_TOKEN` | 半自动（需先获取 refresh_token）  | ⏭️ SKIP（需 IDAAS_REFRESH_TOKEN） |
| TC-18 | `TestWrongClientSecretInvalidClient` | 错误凭证拒绝 + 防泄漏 | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ❌ FAIL（服务端错误码不匹配） |
| TC-19 | `TestFileOidcPermissionCheck_RealTokenFile` | OIDC 文件权限校验 | `.local/oidc_computer.json` | ID Token 文件 | 全自动  | ⏭️ SKIP（需 OIDC_TOKEN_FILE_PATH） |
| TC-20 | `TestOpenBrowser_RealSubprocess_NoUserCodeLeak` | 浏览器 user_code 防泄漏 | - | `IDAAS_IT_BROWSER=on` | 需手动开启（会弹浏览器）  | ⏭️ SKIP（需 IDAAS_IT_BROWSER=on） |
| TC-21 | `TestHumanFederatedDeviceFlow_RealIdP` | Human Device Flow 端到端 | `.local/human_federated.json` | `IDAAS_IT_HUMAN_FLOW=on` + 人工扫码 | 需人工扫码  | ⏭️ SKIP（需人工扫码） |
| TC-22 | `TestFactoryOtherApis` | Factory 其他公共 API | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS（已修复 endpoint 规范化断言） |
| TC-23 | `TestGetCredentialWithContext` | WithContext 方法（context 支持） | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS（已修复 context 取消断言） |
| TC-24 | `TestGetCredentialWithDeadline` | WithContext 方法（deadline 超时） | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-25 | `TestTokenListener` | TokenListener 生命周期事件 | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-26 | `TestStaleValueBehaviorConfig` | StaleValueBehavior 配置解析 | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS |
| TC-27 | `TestUnsupportedDeployEnvironment` | 未实现部署环境报错 | `.local/client_secret_basic.json` | `IDAAS_CLIENT_SECRET` | 全自动  | ✅ PASS（已修复为 PKCS7/OIDC 认证方式测试） |

### 3.2 测试运行状态汇总（2026-10-23）

**测试环境**：本地开发机（macOS）
**测试配置**：client_secret_basic/post/jwt、private_key_jwt、pca 已配置

| 状态 | 数量 | 占比 | 说明 |
|------|------|------|------|
| ✅ PASS | 15 | 56% | 测试通过 |
| ⏭️ SKIP | 10 | 37% | 环境不具备，自动跳过 |
| ❌ FAIL | 2 | 7% | 需要修复 |

**PASS 用例**：
- TC-01 ~ TC-05：5 种 M2M 认证方式（client_secret_basic/post/jwt、private_key_jwt、pca）
- TC-12：Plugin 认证
- TC-13：全认证方式回归
- TC-14：缓存复用
- TC-16：Factory 公共 API 完整流程
- TC-22 ~ TC-27：新增的 6 个测试用例（Factory 其他 API、WithContext、TokenListener、StaleValueBehavior、未实现部署环境）

**SKIP 用例**（环境不具备）：
- TC-06：需阿里云 ECS 实例
- TC-07：需 AWS EC2 实例
- TC-08：需 OIDC_TOKEN_FILE_PATH 环境变量
- TC-09：需 K8s 集群
- TC-10：需 Azure VM
- TC-11：需 GCE VM
- TC-17：需 IDAAS_REFRESH_TOKEN 环境变量
- TC-19：需 OIDC_TOKEN_FILE_PATH 环境变量
- TC-20：需 IDAAS_IT_BROWSER=on 环境变量
- TC-21：需人工扫码

**FAIL 用例**（需修复）：
- TC-15：TestTokenExchange - 服务端报 `Invalid subject_token, _idaas_tag in subject_token invalid`，可能是测试环境的 token 格式问题
- TC-18：TestWrongClientSecretInvalidClient - 服务端返回 `invalid_client_credential` 而不是 RFC 6749 标准的 `invalid_client`

**修复建议**：
1. TC-15：检查 IDaaS 实例是否开通 token-exchange，或联系服务端确认 subject_token 格式要求
2. TC-18：更新测试断言，接受 `invalid_client_credential` 作为合法错误码（服务端实现与 RFC 6749 有差异）


---

## 四、M2M 换票场景

### TC-01: client_secret_basic

**认证方式**：HTTP Basic Authentication（client_id:client_secret 经 URL 编码后 Base64 放入 Authorization 头）

**前置条件**：
1. IDaaS 控制台已创建应用，认证方式为 `client_secret_basic`
2. 已获取 client_secret

**操作步骤**：

```bash
# 1. 确认配置文件已就绪
cat integration/testdata/.local/client_secret_basic.json | grep -E 'clientId|tokenEndpoint'

# 2. 确认凭证已设置
export IDAAS_CLIENT_SECRET="your-actual-secret"
# 或写入 credentials.env 文件（已配置则跳过）

# 3. 运行测试
cd /path/to/idaas-go-core-sdk
go test -count=1 -tags integration -v -run TestClientSecretBasic$ ./integration/
```

**预期结果**：
```
--- PASS: TestClientSecretBasic (x.xxxs)
    support_test.go:xxx: ✅ 获取成功 token=xxxxxxxx...yyyyyyyy type=Bearer expires_in=3600 scope=...
    support_test.go:xxx:    JWT header: alg=RS256 kid=xxx
```

**断言内容**：
- `AccessToken` 非空
- `TokenType` = `Bearer`
- `ExpiresIn` > 0
- `Scope` 包含 `cloud_account_resource:manage_all`

**失败排查**：

| 现象 | 原因 | 解决方案 |
|------|------|----------|------|
| `invalid_client` | client_secret 错误 | 核对 `IDAAS_CLIENT_SECRET` 环境变量 |
| `DnsLookupFailed` | endpoint 域名不可解析 | 检查网络/DNS |
| `ConnectTimeOut` | endpoint 不可达 | 检查防火墙/VPC 网络 |
| `SKIP` | 配置文件缺失 | 按 2.2 节准备 |

---

### TC-02: client_secret_post

**认证方式**：client_secret 放在 POST 请求体中（form 参数）

**操作步骤**：

```bash
# 1. 编辑配置
vim integration/testdata/.local/client_secret_post.json
# 填入真实的 idaasInstanceId / clientId / tokenEndpoint

# 2. 运行
go test -count=1 -tags integration -v -run TestClientSecretPost$ ./integration/
```

**预期结果**：同 TC-01，看到 `--- PASS` + `✅ 获取成功`。

---

### TC-03: client_secret_jwt

**认证方式**：用 client_secret 作为 HMAC-SHA256 密钥签名 JWT 断言（HS256）

**操作步骤**：

```bash
# 1. 编辑配置
vim integration/testdata/.local/client_secret_jwt.json

# 2. 运行
go test -count=1 -tags integration -v -run TestClientSecretJwt$ ./integration/
```

**预期结果**：
```
--- PASS: TestClientSecretJwt
    JWT header: alg=HS256 ...
```

> **注意**：JWT header 中 `alg=HS256` 确认走的是 HMAC-SHA256 签名路径。

---

### TC-04: private_key_jwt

**认证方式**：用 RSA/EC 私钥签名 JWT 断言（RS256/ES256）

**前置条件**：
1. 已生成 RSA 或 EC 私钥
2. 公钥已上传至 IDaaS 应用配置

**操作步骤**：

```bash
# 1. 准备私钥
cp /path/to/your/private.key integration/testdata/.local/your-client.key
chmod 600 integration/testdata/.local/your-client.key

# 2. 编辑配置（privateKeyEnvVarName 指向环境变量名）
vim integration/testdata/.local/private_key_jwt.json

# 3. 设置私钥环境变量（PEM 原文或文件路径均可）
export IDAAS_PRIVATE_KEY="integration/testdata/.local/your-client.key"

# 4. 运行
go test -count=1 -tags integration -v -run TestPrivateKeyJwt$ ./integration/
```

**预期结果**：
```
--- PASS: TestPrivateKeyJwt
    JWT header: alg=RS256 kid=xxx   # 或 ES256
```

---

### TC-05: PCA (PrivateCA)

**认证方式**：X.509 客户端证书 + 私钥签名 JWT 断言

**前置条件**：
1. 已签发 X.509 客户端证书（叶子证书 + 中间 CA）
2. 私钥与叶子证书配对
3. IDaaS 联邦凭证已登记 CA 材料

**操作步骤**：

```bash
# 1. 编辑配置（需填入证书原文）
vim integration/testdata/.local/pca.json
```

配置中需要填写的关键字段：

```json
{
  "authnConfiguration": {
    "authnMethod": "PCA",
    "privateKeyEnvVarName": "IDAAS_PRIVATE_KEY",
    "applicationFederatedCredentialName": "your-federated-credential-name",
    "clientX509Certificate": "-----BEGIN CERTIFICATE-----\n<叶子证书>\n-----END CERTIFICATE-----\n",
    "x509CertChains": "-----BEGIN CERTIFICATE-----\n<中间CA证书>\n-----END CERTIFICATE-----"
  }
}
```

```bash
# 2. 设置私钥
export IDAAS_PRIVATE_KEY="integration/testdata/.local/your-pca.key"

# 3. 运行
go test -count=1 -tags integration -v -run TestPCA$ ./integration/
```

**失败排查**：

| 现象 | 原因 | 解决方案 |
|------|------|----------|------|
| 证书链校验失败 | `x509CertChains` 缺少中间 CA 或 Root CA | 补全证书链 |
| `invalid_client` | 叶子证书与私钥不配对 | 确认私钥与 `clientX509Certificate` 匹配 |

---

### TC-06: PKCS7 @ 阿里云 ECS

**认证方式**：从 ECS IMDSv2 获取 PKCS7 签名的实例身份文档作为断言

**前置条件**：
1. **必须在阿里云 ECS 实例上运行**（开发机上会自动 skip）
2. 实例元数据访问未被禁用
3. IDaaS 联邦凭证已登记 ECS 实例身份

**操作步骤**：

```bash
# 1. 确认在 ECS 实例上
cat /sys/class/dmi/id/product_name  # 应包含 "ECS" 或 "Alinux"

# 2. 验证 IMDSv2 可达
curl -s -X PUT -H "x-aliyun-ecs-metadata-token-ttl-seconds: 60" \
  http://100.100.100.200/latest/api/token && echo
# 有输出 = IMDSv2 可用

# 3. 编辑配置
vim integration/testdata/.local/pkcs7.json
# 填入 idaasInstanceId / clientId / tokenEndpoint / applicationFederatedCredentialName

# 4. 运行
go test -count=1 -tags integration -v -run 'TestPkcs7$' ./integration/
```

> **注意**：正则用 `TestPkcs7$`（带 `$` 锚定），避免误匹配 `TestPkcs7AwsEc2`。

**预期结果**：`--- PASS: TestPkcs7` + `✅ 获取成功`

**失败排查**：

| 现象 | 原因 | 解决方案 |
|------|------|----------|------|
| `SKIP`（IMDS 探活失败） | 不在 ECS 上 | 确认实例类型 |
| `invalid_client` | 联邦凭证名称不匹配 | 核对 `applicationFederatedCredentialName` |
| `DnsLookupFailed` | VPC DNS 无法解析 IDaaS 域名 | 检查 VPC DNS 配置或 hosts 条目 |

**ECS 专用脚本**（推荐）：

```bash
./scripts/run-integration-on-ecs.sh
```

---

### TC-07: PKCS7 @ AWS EC2

**认证方式**：从 AWS EC2 IMDSv2 获取 PKCS7 签名的实例身份文档

**前置条件**：
1. **必须在 AWS EC2 实例上运行**
2. 实例启用 IMDSv2
3. IDaaS 联邦凭证登记了对应 AWS 账号的 `aws_account_id`

**操作步骤**：

```bash
# 1. 确认 IMDSv2 可用
TOKEN=$(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
  http://169.254.169.254/latest/api/token)
echo "Token length: ${#TOKEN}"

# 2. 查看实例 accountId（需与 IDaaS 登记一致）
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/dynamic/instance-identity/document | python3 -m json.tool

# 3. 编辑配置
vim integration/testdata/.local/pkcs7_aws_ec2.json

# 4. 运行
go test -count=1 -tags integration -v -run TestPkcs7AwsEc2$ ./integration/
```

---

### TC-08: OIDC @ COMPUTER (本地开发)

**认证方式**：从本地文件读取 OIDC ID Token 作为断言（COMPUTER 模式不回落 K8s 默认路径）

**前置条件**：
1. 有 IDaaS 联邦凭证信任的 issuer 签发的有效 ID Token（JWT 文件）
2. Token 未过期

**操作步骤**：

```bash
# 1. 准备 ID Token 文件
export OIDC_TOKEN_FILE_PATH=/path/to/your/id-token.jwt

# 2. 编辑配置
vim integration/testdata/.local/oidc_computer.json
# oidcTokenFilePath 或 oidcTokenFilePathEnvVarName 指向 token 文件

# 3. 运行
go test -count=1 -tags integration -v -run 'TestOidc$' ./integration/
```

> **注意**：正则用 `TestOidc$`（带 `$`），避免误匹配 `TestOidcKubernetes` 等。

---

### TC-09: OIDC @ KUBERNETES

**认证方式**：从 K8s Service Account Token 获取 OIDC 断言

**前置条件**：
1. **必须在 K8s 集群内 Pod 中运行**
2. IDaaS 联邦凭证信任该集群 API Server 的 OIDC issuer
3. Token 的 `aud` 与 IDaaS 联邦凭证约定匹配

**操作步骤**：

```bash
# 方式一：在 Pod 内直接运行
kubectl exec -it <pod> -- bash -lc \
  'cd /path/to/sdk && go test -count=1 -tags integration -v -run TestOidcKubernetes ./integration/'

# 方式二：开发机上生成 SA token
kubectl create token <service-account> \
  --audience=<IDaaS联邦凭证约定的audience> \
  --output=/tmp/sa.jwt
export OIDC_TOKEN_FILE_PATH=/tmp/sa.jwt
go test -count=1 -tags integration -v -run TestOidcKubernetes ./integration/
```

**失败排查**：

| 现象 | 原因 | 解决方案 |
|------|------|----------|------|
| `invalid_grant` | audience 不匹配 | `jwt decode` SA token 核对 `aud` 字段 |
| issuer 不匹配 | 集群 issuer URL 与 IDaaS 登记不一致 | `kubectl get --raw /.well-known/openid-configuration` 核对 |

---

### TC-10: OIDC @ AZURE_VM

**认证方式**：从 Azure IMDS 获取 Managed Identity 的 ARM resource token

**前置条件**：
1. **必须在绑定了 MI（系统或用户指派）的 Azure VM 上运行**
2. IDaaS 联邦凭证登记了该 MI 的 issuer/subject 规则

**操作步骤**：

```bash
# 1. 验证 MI 可用
curl -s -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"][:40])'
# 有输出 = MI 可用

# 2. 编辑配置
vim integration/testdata/.local/oidc_azure_vm.json

# 3. 运行
go test -count=1 -tags integration -v -run TestOidcAzureVm ./integration/
```

---

### TC-11: OIDC @ GOOGLE_VM

**认证方式**：从 GCE 元数据服务获取 ID Token

**前置条件**：
1. **必须在 GCE VM 上运行**（`metadata.google.internal` 仅 GCP 内可解析）
2. GCE VM 挂载的 service account 与 IDaaS 联邦凭证登记一致

**操作步骤**：

```bash
# 1. 验证 GCP 元数据服务
curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/ -o /dev/null -w '%{http_code}\n'
# 期望：200

# 2. 编辑配置
vim integration/testdata/.local/oidc_google_vm.json

# 3. 运行
go test -count=1 -tags integration -v -run TestOidcGoogleVm ./integration/
```

---

### TC-12: PLUGIN 认证

**认证方式**：进程内注册自定义插件，SDK 不发起 HTTP 请求，由插件自行获取完整 token

**特殊说明**：Plugin 认证不由配置文件驱动（`plugin.example.json` 仅供参考），测试进程内注册一个回声插件（`integration_echo`），内部委托给真实的 `client_secret_basic` 链路。

**操作步骤**：

```bash
# 无需额外配置，测试内部自动处理
go test -count=1 -tags integration -v -run TestPluginAuthn ./integration/
```

**预期结果**：
```
--- PASS: TestPluginAuthn (x.xxxs)
    --- PASS: TestPluginAuthn/unknown_plugin (x.xxxs)
    --- PASS: TestPluginAuthn/empty_plugin_name (x.xxxs)
```

**验证内容**：
1. 主链路：插件注册 -> 查找 -> scope 透传 -> 凭证回传 -> 拿到有效 Bearer token
2. 子用例 `unknown_plugin`：未注册的 pluginName -> 返回 `PluginNotFound` 错误
3. 子用例 `empty_plugin_name`：空 pluginName -> 返回 `PluginNameNotFound` 错误

---

## 五、链路与行为场景

### TC-13: 全认证方式回归

**目的**：一次性跑完所有配置驱动的认证方式，输出通过/失败汇总。单个失败不中断其余。

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestAllAuthnMethods ./integration/
```

**覆盖范围**（11 种，不含 Plugin）：
- `client_secret_basic` / `client_secret_post` / `client_secret_jwt`
- `private_key_jwt` / `pca`
- `pkcs7` / `pkcs7_aws_ec2`
- `oidc_computer` / `oidc_kubernetes` / `oidc_azure_vm` / `oidc_google_vm`

> **注意**：多云用例在非对应云上会自动 skip，不算失败。

---

### TC-14: 缓存复用验证

**目的**：验证同一 provider 第二次取凭证命中缓存（令牌完全一致，且第二次调用明显快于首次）

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestCachedCredentialIsReused ./integration/
```

**预期结果**：
```
--- PASS: TestCachedCredentialIsReused
    obtain_token_test.go:xxx: ✅ 缓存命中，第二次耗时 xxxus
```

**断言内容**：
- 两次 `GetCredential()` 返回的 `AccessToken` 完全一致
- 第二次耗时 < 1 秒（无 HTTP 请求）

---

### TC-15: RFC 8693 Token Exchange

**目的**：端到端验证 OAuth2 Token Exchange（RFC 8693）链路

**前置条件**：
1. IDaaS 实例/应用已开通 `token-exchange` grant 类型
2. `client_secret_post` 配置就绪

**操作步骤**：

```bash
# 默认方式：自动用 client_secret_post 链路先获取 subject_token
go test -count=1 -tags integration -v -run TestTokenExchange ./integration/

# 可选：手动注入 subject_token（某些实例只接受用户态 token 作 subject）
export IDAAS_SUBJECT_TOKEN="eyJ..."
export IDAAS_SUBJECT_TOKEN_TYPE="urn:ietf:params:oauth:token-type:id_token"  # 可选
export IDAAS_EXCHANGE_SCOPE="..."  # 可选，未设则沿用配置 scope
go test -count=1 -tags integration -v -run TestTokenExchange ./integration/
```

**预期结果**：
```
--- PASS: TestTokenExchange
    --- PASS: TestTokenExchange/missing_subject_token (x.xxxs)
```

**验证内容**：
1. 主链路：M2M 取 subject token -> 交换新令牌 -> 返回有效 Bearer token
2. 子用例 `missing_subject_token`：空 subject_token -> 被正确拒绝

**失败排查**：

| 现象 | 原因 | 解决方案 |
|------|------|----------|------|
| `invalid_grant` | 实例未开通 token-exchange | IDaaS 控制台 -> 应用 -> 授权类型 -> 添加 token-exchange |
| 换出 token 与 subject token 相同 | 服务端为直通语义 | 日志会提示"注意"，非错误 |

---

### TC-16: Factory 公共 API 完整流程

**目的**：从用户真实视角验证 `factory.Init` -> 取票 -> 缓存 -> Token Exchange Provider -> Reset 的完整生命周期

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestFactoryPublicApiFlow ./integration/
```

**验证内容**（5 步）：
1. `factory.Init(cfgPath)` 成功
2. `GetIDaaSCredentialProvider()` + `GetCredential()` 返回有效凭证
3. 第二次 `GetIDaaSCredentialProvider()` + `GetCredential()` 命中缓存（令牌一致）
4. `GetIDaaSTokenExchangeCredentialProvider()` 创建成功
5. `factory.Reset()` 后，`GetIDaaSCredentialProvider()` 返回 `FactoryNotInit` 错误

---

### TC-17: Refresh Token 续期

**目的**：验证 `oauth2.OAuth2TokenUtil.RefreshToken` 公共 API 的续期链路

**前置条件**：
1. 需要先通过 Device Code / Human 流程获取一个有效的 `refresh_token`
2. 设置环境变量 `IDAAS_REFRESH_TOKEN`

**操作步骤**：

```bash
# 1. 获取 refresh_token（通过 device code 流程或从其他渠道取得）
# 参考 samples/device-code 或 samples/obtain-token

# 2. 设置环境变量
export IDAAS_REFRESH_TOKEN="your-refresh-token-value"

# 3. 运行
go test -count=1 -tags integration -v -run TestRefreshTokenRenewal ./integration/
```

**预期结果**：
```
--- PASS: TestRefreshTokenRenewal
    refresh_token_test.go:xxx: ✅ refresh_token 续期成功（服务端可能轮换 refresh_token：true/false）
```

> **注意**：若未设置 `IDAAS_REFRESH_TOKEN`，用例会 `SKIP` 并提示。这是设计行为。

---

## 六、负面路径场景

### TC-18: 错误凭证拒绝与凭证防泄漏

**目的**：验证错误 client_secret 被真实 endpoint 拒绝，且错误文本/日志不泄漏 secret

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestWrongClientSecretInvalidClient ./integration/
```

**验证内容**：
1. 注入假 secret 后换票失败（返回错误）
2. 错误码包含 `invalid_client`（RFC 6749 标准错误）
3. `err.Error()` 不包含注入的假 secret 原文
4. `describeError(err)` 不包含注入的假 secret 原文

**预期结果**：
```
--- PASS: TestWrongClientSecretInvalidClient
    negative_test.go:xxx: ✅ 错误凭证正确拒绝且未泄漏 secret: code=invalid_client | ...
```

---

## 七、安全修复端到端场景

### TC-19: OIDC Token 文件权限校验

**目的**：验证 OIDC token 文件权限校验在完整 SDK 装配链路中正确触发，核心契约是 **warn-only 不阻断**

**操作步骤**：

```bash
# 1. 查看当前 token 文件权限
ls -la $OIDC_TOKEN_FILE_PATH

# 2. 运行
go test -count=1 -tags integration -v -run TestFileOidcPermissionCheck_RealTokenFile ./integration/
```

**验证内容**：
1. 无论文件权限是否安全，`GetCredential()` 必须成功返回 token（warn-only 不阻断）
2. 若文件权限为 `0600`（secure）-> 不产生 `insecure_permission` Warn
3. 若文件 group/other 可读 -> 产生一条 `insecure_permission` Warn

**可选：手动测试不安全权限的告警**

```bash
chmod 644 $OIDC_TOKEN_FILE_PATH
go test -count=1 -tags integration -v -run TestFileOidcPermissionCheck_RealTokenFile ./integration/
# 应看到 Warn 日志但测试仍 PASS
chmod 600 $OIDC_TOKEN_FILE_PATH
```

---

### TC-20: 浏览器启动 user_code 防泄漏

**目的**：验证真实 `xdg-open`/`open` 子进程下 URL 不泄漏 `user_code`

**前置条件**：需要设置 `IDAAS_IT_BROWSER=on`（会弹出真实浏览器窗口）

**操作步骤**：

```bash
# 注意：会弹出浏览器窗口！
IDAAS_IT_BROWSER=on go test -count=1 -tags integration -v \
  -run TestOpenBrowser_RealSubprocess_NoUserCodeLeak ./integration/
```

**验证内容**：
1. 浏览器进程成功启动（或在不支持的平台优雅处理）
2. 传递给浏览器的 URL 中不包含 `user_code` 参数
3. 错误日志中不包含 `user_code`（仅保留 `scheme://host`）

> **注意**：默认不运行此用例（需手动开启），因为会弹出浏览器窗口。

---

### TC-21: Human Federated Device Flow 端到端

**目的**：验证 Human Device Flow 的完整端到端链路

**前置条件**：
1. 配置 `.local/human_federated.json`（从模板复制并填入真实 IdP 信息）
2. 设置 `IDAAS_IT_HUMAN_FLOW=on`（否则仅验证构造不 panic）

**操作步骤**：

```bash
# 1. 准备配置
cp integration/testdata/human_federated.example.json integration/testdata/.local/human_federated.json
vim integration/testdata/.local/human_federated.json
# 填入真实的 instanceId / clientId / tokenEndpoint / deviceAuthorizationEndpoint

# 2. 仅验证构造（不阻塞，不需要扫码）
go test -count=1 -tags integration -v -run TestHumanFederatedDeviceFlow_RealIdP ./integration/
# 预期：SKIP（"跳过阻塞 device flow"）

# 3. 完整端到端（会阻塞等待人工扫码，200s 超时）
IDAAS_IT_HUMAN_FLOW=on go test -count=1 -tags integration -v \
  -run TestHumanFederatedDeviceFlow_RealIdP ./integration/
```

**完整端到端的验证内容**：
1. 构造 `HumanFederatedOidcTokenProvider` 不 panic
2. `GetCredentialWithContext(ctx)` 在 200s 内完成（需人工扫码）
3. 返回有效 `AccessToken`
4. `~/.cloud_idaas/human-cache/` 目录下有 `.json` 缓存文件写入

**扫码操作**：
- 测试启动后会输出 `verification_uri` 和 `user_code`
- 在另一台设备的浏览器中打开 `verification_uri`，输入 `user_code`，完成登录授权
- SDK 自动轮询 token endpoint 直到授权完成

---


## 八、Factory 公共 API 扩展场景

### TC-22: Factory 其他公共 API

**目的**：验证 Factory 的其余 8 个公共 API（TC-16 已覆盖 Init/GetIDaaSCredentialProvider/GetIDaaSTokenExchangeCredentialProvider/Reset）

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestFactoryOtherApis ./integration/
```

**验证内容**（8 个 API）：
1. `InitWithConfig`：从内存配置初始化（不依赖文件）
2. `GetIDaaSCredentialProviderByScope`：不同 scope 返回不同 provider，同一 scope 返回同一实例（缓存）
3. `GetIDaaSTokenExchangeCredentialProviderByScope`：同上
4. `GetDeveloperApiEndpoint`：返回配置中的 `developerApiEndpoint`
5. `GetOpenApiEndpoint`：返回配置中的 `openApiEndpoint`
6. `GetIDaaSInstanceId`：返回配置中的 `idaasInstanceId`
7. `GetClientId`：返回配置中的 `clientId`
8. `GetHttpConfig`：返回深拷贝，修改返回值不影响原配置

**预期结果**：
```
--- PASS: TestFactoryOtherApis (x.xxxs)
    factory_other_apis_test.go:xx: ✅ InitWithConfig 成功
    factory_other_apis_test.go:xx: ✅ GetIDaaSCredentialProviderByScope 正确区分不同 scope
    factory_other_apis_test.go:xx: ✅ GetIDaaSTokenExchangeCredentialProviderByScope 正确区分不同 scope
    factory_other_apis_test.go:xx: ✅ GetDeveloperApiEndpoint = ...
    factory_other_apis_test.go:xx: ✅ GetOpenApiEndpoint = ...
    factory_other_apis_test.go:xx: ✅ GetIDaaSInstanceId = ...
    factory_other_apis_test.go:xx: ✅ GetClientId = ...
    factory_other_apis_test.go:xx: ✅ GetHttpConfig 返回深拷贝（ConnectTimeout=...）
```

---

## 九、WithContext 方法场景

### TC-23: WithContext 方法（context 支持）

**目的**：验证 provider 的 `GetCredentialWithContext` 方法支持 context 取消

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestGetCredentialWithContext ./integration/
```

**验证内容**：
1. 正常 `context.Background()` 下，行为与不带 context 的版本一致
2. 带 cancel 的 context（不取消），正常完成
3. 已取消的 context，立即返回 `context.Canceled` 错误

**预期结果**：
```
--- PASS: TestGetCredentialWithContext (x.xxxs)
    with_context_test.go:xx: ✅ GetCredentialWithContext(Background) 成功
    with_context_test.go:xx: ✅ GetCredentialWithContext(with cancel) 成功
    with_context_test.go:xx: ✅ 已取消的 context 正确返回错误: context canceled
```

### TC-24: WithContext 方法（deadline 超时）

**目的**：验证 context deadline 超时行为

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestGetCredentialWithDeadline ./integration/
```

**验证内容**：
1. 正常 deadline（30s），成功返回凭证
2. 极短 deadline（1ns），触发超时（可能命中缓存而不触发）

**预期结果**：
```
--- PASS: TestGetCredentialWithDeadline (x.xxxs)
    with_context_test.go:xx: ✅ GetCredentialWithContext(30s timeout) 成功
    with_context_test.go:xx: ✅ 极短 deadline 正确返回超时错误: context deadline exceeded
```

> **注意**：由于缓存机制，第二次调用可能直接返回缓存值而不触发网络请求，因此极短 deadline 测试可能不会触发超时。这是正常行为。

---

## 十、TokenListener 场景

### TC-25: TokenListener 生命周期事件

**目的**：验证 TokenListener 的生命周期回调在正确时机被触发

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestTokenListener ./integration/
```

**验证内容**：
1. 首次 `GetCredential` 成功后，触发 `OnTokenRefreshed`
2. 回调异步执行，不阻塞主链路（2 秒内触发）
3. 回调参数正确（`expiresAt` 在当前时间之后，`scope` 与配置一致）
4. 成功路径下，`OnTokenRefreshFailed`/`OnDegradationEntered`/`OnDegradationExited` 不被触发

**预期结果**：
```
--- PASS: TestTokenListener (x.xxxs)
    token_listener_test.go:xx: ✅ OnTokenRefreshed 被触发 1 次
    token_listener_test.go:xx: ✅ expiresAt 合理: 2026-10-23 xx:xx:xx +0800 CST
    token_listener_test.go:xx: ✅ scope = "..."
```

> **注意**：`OnTokenRefreshFailed`/`OnDegradationEntered`/`OnDegradationExited` 需要模拟失败场景，在集成测试中难以稳定触发，因此本测试只验证成功路径。失败路径的回调由单元测试覆盖。

---

## 十一、StaleValueBehavior 场景

### TC-26: StaleValueBehavior 配置解析

**目的**：验证配置中的 `staleValueBehavior` 字段被正确解析和应用

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestStaleValueBehaviorConfig ./integration/
```

**验证内容**：
1. 配置中未设置 `staleValueBehavior` 时，默认使用 `REFRESH`
2. 显式设置 `BLOCK` 时，provider 正常工作
3. 显式设置 `ALLOW` 时，provider 正常工作
4. 显式设置 `REFRESH` 时，provider 正常工作

**预期结果**：
```
--- PASS: TestStaleValueBehaviorConfig (x.xxxs)
    stale_value_behavior_test.go:xx: ✅ 配置中未设置 staleValueBehavior，将使用默认值 REFRESH
    stale_value_behavior_test.go:xx: ✅ 默认 staleValueBehavior 下 provider 正常工作
    stale_value_behavior_test.go:xx: ✅ BLOCK 模式下 provider 正常工作
    stale_value_behavior_test.go:xx: ✅ ALLOW 模式下 provider 正常工作
    stale_value_behavior_test.go:xx: ✅ REFRESH 模式下 provider 正常工作
    stale_value_behavior_test.go:xx: ✅ 三种 staleValueBehavior 配置均能正常工作（过期行为由单元测试覆盖）
```

> **注意**：真正的过期行为测试需要服务端签发短时效 token（如 10s），在集成测试中难以稳定触发。本测试只验证配置解析和默认行为。过期行为的详细逻辑由单元测试覆盖。

---

## 十二、未实现部署环境场景

### TC-27: 未实现部署环境报错

**目的**：验证配置未实现的部署环境时，SDK 正确返回 `UnsupportedClientDeployEnvironment` 错误

**操作步骤**：

```bash
go test -count=1 -tags integration -v -run TestUnsupportedDeployEnvironment ./integration/
```

**验证内容**（6 个未实现的部署环境）：
1. `COMMON`：返回 `UnsupportedClientDeployEnvironment` 错误
2. `ALIBABA_CLOUD_ECI`：返回 `UnsupportedClientDeployEnvironment` 错误
3. `ALIBABA_CLOUD_ACK`：返回 `UnsupportedClientDeployEnvironment` 错误
4. `AWS_EKS`：返回 `UnsupportedClientDeployEnvironment` 错误
5. `HUAWEI_CLOUD_ECS`：返回 `UnsupportedClientDeployEnvironment` 错误
6. `CUSTOM`：返回 `UnsupportedClientDeployEnvironment` 错误

**预期结果**：
```
--- PASS: TestUnsupportedDeployEnvironment (x.xxxs)
    --- PASS: TestUnsupportedDeployEnvironment/COMMON (x.xxxs)
    --- PASS: TestUnsupportedDeployEnvironment/ALIBABA_CLOUD_ECI (x.xxxs)
    --- PASS: TestUnsupportedDeployEnvironment/ALIBABA_CLOUD_ACK (x.xxxs)
    --- PASS: TestUnsupportedDeployEnvironment/AWS_EKS (x.xxxs)
    --- PASS: TestUnsupportedDeployEnvironment/HUAWEI_CLOUD_ECS (x.xxxs)
    --- PASS: TestUnsupportedDeployEnvironment/CUSTOM (x.xxxs)
```

> **说明**：SDK 定义了 12 个部署环境枚举值，但只实现了 6 个（`COMPUTER`、`KUBERNETES`、`ALIBABA_CLOUD_ECS`、`AWS_EC2`、`GOOGLE_VM`、`AZURE_VM`）。其他 6 个未实现的部署环境在 provider 构造时会返回 `UnsupportedClientDeployEnvironment` 错误。

## 十三、一键运行全部场景

### 8.1 使用逐项矩阵脚本（推荐）

```bash
# 运行全部场景，输出 PASS/SKIP/FAIL 矩阵
./scripts/run-integration-item-by-item.sh

# 只运行某分组
./scripts/run-integration-item-by-item.sh -k M2M      # 只跑 M2M 换票
./scripts/run-integration-item-by-item.sh -k 链路      # 只跑链路场景
./scripts/run-integration-item-by-item.sh -k 安全      # 只跑安全场景
./scripts/run-integration-item-by-item.sh -k 负面      # 只跑负面路径

# 启用浏览器/人工扫码用例
IDAAS_IT_BROWSER=on IDAAS_IT_HUMAN_FLOW=on ./scripts/run-integration-item-by-item.sh
```

**输出示例**：
```
== IDaaS 集成测试逐项矩阵 ==

PASS  [M2M] client_secret_basic
PASS  [M2M] client_secret_post
PASS  [M2M] client_secret_jwt
SKIP  [M2M] private_key_jwt — 凭证缺失
PASS  [M2M] pca
SKIP  [M2M] pkcs7@ECS — 不在阿里云 ECS 上
SKIP  [多云] pkcs7@AWS_EC2 — 不在 AWS EC2 上
...
合计: PASS=12 SKIP=7 FAIL=0
```

### 8.2 使用 go test 一把跑

```bash
# 全部场景
go test -count=1 -tags integration -v ./integration/

# 只编译不发包（验证可编译性）
go test -tags integration -short ./integration/

# 临时关闭
IDAAS_IT=off go test -tags integration ./integration/
```

### 8.3 ECS 专用脚本

```bash
# 在阿里云 ECS 上运行（自动做 IMDS 探活 + 环境检查）
./scripts/run-integration-on-ecs.sh

# 仅跑特定认证方式
./scripts/run-integration-on-ecs.sh -m client_secret_basic

# 跳过 IMDS 探活
./scripts/run-integration-on-ecs.sh -k

# 先拉取最新代码
./scripts/run-integration-on-ecs.sh -u
```

---

## 十四、常见问题排查

### Q1: 所有用例都 SKIP

**原因**：缺少 `-tags integration` 或 `IDAAS_IT=off`

**解决**：
```bash
go test -tags integration -v ./integration/
unset IDAAS_IT
```

### Q2: `DnsLookupFailed` / `no such host`

**原因**：IDaaS 域名无法解析

**排查**：
```bash
nslookup your-instance.example.com
```

### Q3: `invalid_client`

**原因**：凭证错误或应用配置不匹配

**排查**：
1. 确认 `IDAAS_CLIENT_SECRET` / `IDAAS_PRIVATE_KEY` 正确
2. 确认 `clientId` 与 IDaaS 控制台一致
3. 确认 `authnMethod` 与应用配置的认证方式一致

### Q4: `invalid_grant`

**原因**：断言被服务端拒绝

**排查**：
1. PKCS7：确认 `applicationFederatedCredentialName` 与服务端登记一致
2. OIDC：确认 token 的 `iss`/`aud`/`sub` 与 IDaaS 联邦凭证规则匹配
3. Token Exchange：确认实例已开通 `token-exchange` grant 类型

### Q5: 多云用例 SKIP（非对应云环境）

**说明**：这是**设计行为**，不是错误。多云用例在非对应云上会自动 skip。

**解决**：在对应云环境的实例上运行测试。

### Q6: OIDC Token 过期

**原因**：ID Token（JWT）的 `exp` 已过期

**解决**：
```bash
# 检查 token 过期时间（解码 JWT payload）
echo "<jwt-payload-base64>" | base64 -d | python3 -m json.tool | grep exp

# 重新获取 token
# K8s: kubectl create token <sa> --audience=<aud> --output=/tmp/sa.jwt
# COMPUTER: 从 IdP 重新签发
```

### Q7: JWT header `alg` 不符合预期

**说明**：`alg` 反映实际签名路径：
- `client_secret_jwt` -> 期望 `HS256`
- `private_key_jwt` -> 期望 `RS256` 或 `ES256`（取决于私钥类型）
- `pca` -> 期望 `RS256` 或 `ES256`

若不符合预期，检查配置的 `authnMethod` 和凭证类型是否匹配。

### Q8: `TestTokenExchange` 报 `invalid_grant`

**原因**：实例未开通 token-exchange

**解决**：IDaaS 控制台 -> 应用管理 -> 授权类型 -> 添加 `urn:ietf:params:oauth:grant-type:token-exchange`

### Q9: 错误信息中包含 `requestId`

**说明**：`describeError` 会提取服务端返回的 `requestId`，可用于：
1. 提工单时附上
2. 在服务端日志中定位具体请求

---

## 附录

### 附录 A：配置文件字段速查

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|------|
| `idaasInstanceId` | string | 是 | IDaaS 实例 ID |
| `clientId` | string | 是 | 应用客户端 ID |
| `issuer` | string | 是 | OAuth2 Issuer URL |
| `tokenEndpoint` | string | 是 | Token 端点 URL（必须 https） |
| `scope` | string | 推荐 | 授权范围（格式：`audience\|permission`） |
| `deviceAuthorizationEndpoint` | string | HUMAN 必填 | Device Code 端点 |
| `httpConfiguration.connectTimeout` | int | - | 连接超时（ms），默认 5000 |
| `httpConfiguration.readTimeout` | int | - | 读取超时（ms），默认 10000 |
| `httpConfiguration.unsafeIgnoreSslCert` | bool | - | 跳过 TLS 证书校验（仅限调试） |
| `authnConfiguration.identityType` | string | 是 | `CLIENT` 或 `HUMAN` |
| `authnConfiguration.authnMethod` | string | 是 | 认证方式枚举 |
| `authnConfiguration.clientSecretEnvVarName` | string | secret 方式必填 | client_secret 环境变量名 |
| `authnConfiguration.privateKeyEnvVarName` | string | 私钥方式必填 | 私钥环境变量名 |
| `authnConfiguration.applicationFederatedCredentialName` | string | 联邦认证必填 | 联邦凭证名称 |
| `authnConfiguration.clientDeployEnvironment` | string | 联邦认证必填 | 部署环境枚举 |
| `authnConfiguration.pluginName` | string | PLUGIN 必填 | 插件注册名 |
| `authnConfiguration.oidcTokenFilePath` | string | OIDC COMPUTER 推荐 | ID Token 文件路径 |
| `authnConfiguration.oidcTokenFilePathEnvVarName` | string | OIDC COMPUTER 可选 | ID Token 路径的环境变量名 |
| `authnConfiguration.clientX509Certificate` | string | PCA 必填 | 客户端叶子证书 PEM |
| `authnConfiguration.x509CertChains` | string | PCA 可选 | 中间 CA 证书链 PEM |

### 附录 B：认证方式枚举

| authnMethod | 说明 | 所需凭证 |
|-------------|------|----------|
| `CLIENT_SECRET_BASIC` | HTTP Basic Auth | `IDAAS_CLIENT_SECRET` |
| `CLIENT_SECRET_POST` | POST body 传 secret | `IDAAS_CLIENT_SECRET` |
| `CLIENT_SECRET_JWT` | HS256 签名 JWT 断言 | `IDAAS_CLIENT_SECRET` |
| `PRIVATE_KEY_JWT` | RS256/ES256 签名 JWT 断言 | `IDAAS_PRIVATE_KEY` |
| `PCA` | X.509 客户端证书 | `IDAAS_PRIVATE_KEY` + 证书 |
| `PKCS7` | 实例身份文档 PKCS7 签名 | 云实例元数据服务 |
| `OIDC` | OIDC ID Token 断言 | ID Token 文件 / 云元数据 |
| `PLUGIN` | 自定义插件 | 进程内注册 |

### 附录 C：部署环境枚举

| clientDeployEnvironment | 说明 | 运行环境要求 |
|-------------------------|------|--------------|
| `ALIBABA_CLOUD_ECS` | 阿里云 ECS | 阿里云 ECS 实例 |
| `AWS_EC2` | AWS EC2 | AWS EC2 实例 |
| `KUBERNETES` | Kubernetes | 集群内 Pod |
| `GOOGLE_VM` | Google Cloud VM | GCE VM |
| `AZURE_VM` | Azure VM | Azure VM + MI |
| `COMPUTER` | 本地开发 | 任意机器 + ID Token 文件 |

### 附录 D：环境变量速查

| 环境变量 | 用途 | 对应用例 |
|----------|------|----------|
| `IDAAS_CLIENT_SECRET` | client_secret 凭证 | TC-01/02/03/12 |
| `IDAAS_PRIVATE_KEY` | 私钥（PEM 原文或文件路径） | TC-04/05 |
| `IDAAS_REFRESH_TOKEN` | refresh_token 续期 | TC-17 |
| `IDAAS_SUBJECT_TOKEN` | Token Exchange 的 subject token | TC-15 |
| `IDAAS_SUBJECT_TOKEN_TYPE` | subject_token 类型 | TC-15 |
| `IDAAS_EXCHANGE_SCOPE` | Token Exchange 目标 scope | TC-15 |
| `OIDC_TOKEN_FILE_PATH` | OIDC ID Token 文件路径 | TC-08/09/19 |
| `IDAAS_IT` | 集成测试总开关（off=跳过） | 全部 |
| `IDAAS_IT_BROWSER` | 启用浏览器用例（on=弹浏览器） | TC-20 |
| `IDAAS_IT_HUMAN_FLOW` | 启用 Human Device Flow（on=阻塞扫码） | TC-21 |
