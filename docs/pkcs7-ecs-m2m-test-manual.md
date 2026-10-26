# 在 ECS 上测试 PKCS#7 获取 M2M Token —— 实操手册

> 适用仓库：<https://github.com/cloud-idaas/idaas-go-core-sdk>（`main` 分支）
> 被测能力：`authnMethod=PKCS7` + `clientDeployEnvironment=ALIBABA_CLOUD_ECS` 的机器对机器（M2M）换票
> 手册定位：从零开始，每一步都给命令、给期望输出、给失败时的下一步

---

## 0. 先说结论（最短路径）

如果你已经有一台能登录的阿里云 ECS、代码已在机器上，三条命令即可：

```bash
# 1) 确认这台机器真的能访问 ECS 元数据服务（PKCS#7 的唯一硬前提）
curl -s -X PUT -H 'x-aliyun-ecs-metadata-token-ttl-seconds: 60' \
  http://100.100.100.200/latest/api/token && echo

# 2) 跑集成测试（一键脚本：探活 → 检查凭证 → 执行 → 脱敏摘要）
./scripts/run-integration-on-ecs.sh

# 3) 或直接用 go test（注意 -tags integration 不可省）
go test -count=1 -tags integration -v -run TestPkcs7 ./integration/
```

看到 `--- PASS: TestPkcs7` 且日志里有 `✅ 获取成功 token=eyJ... type=Bearer expires_in=...` 即成功。
看到 `--- SKIP: TestPkcs7` 说明**你还没在真正的 ECS 实例上**（见 §3）。

---

## 1. 为什么必须去 ECS

PKCS#7 认证的信任根是**ECS 实例身份文档**，由实例内的元数据服务（IMDS）签发：

| 步骤 | 请求 | 说明 |
| --- | --- | --- |
| 1 | `PUT http://100.100.100.200/latest/api/token` | IMDSv2，先取 metadata token |
| 2 | `GET http://100.100.100.200/latest/dynamic/instance-identity/pkcs7?audience=<URL编码JSON>` | 取实例身份 PKCS#7 签名文档 |
| 3 | `POST <IDaaS tokenEndpoint>` | 用该文档作为 `client_assertion` 换 access token |

`100.100.100.200` 是阿里云 ECS 的链路本地元数据地址，在 SDK 里是**硬编码常量**（`constants/auth_constants.go:17` 与 `:21`），没有环境变量或配置项可以改写。因此：

- 在你的 Mac / 本地 VM / 容器里，第 1、2 步必然失败 → 只能测 `client_secret_*`、`private_key_jwt`、`pca`
- 本仓库的 `TestPkcs7` 会先做 500ms TCP 探活，不通就 `SKIP`（不是 `FAIL`），见 `integration/support_test.go` 的 `skipIfEnvironmentUnavailable`

> **audience 里带 `signingTime`（当前 Unix 秒）**：实例时钟与服务端偏差过大会被拒绝，所以 §2 的校时不是可选项。

---

## 2. 前置条件清单（逐条可校验）

先整段复制执行，全绿再往下走。

```bash
# ---- ① 机器身份：确认是 ECS 实例 ----
cat /sys/class/dmi/id/product_name 2>/dev/null || echo "(非 Linux 或无 DMI)"
curl -s -f -X PUT -H 'x-aliyun-ecs-metadata-token-ttl-seconds: 60' \
  http://100.100.100.200/latest/api/token >/tmp/imds_token && \
  echo "IMDS OK, token len=$(wc -c </tmp/imds_token)" || echo "IMDS 不可达 ❌"

# ---- ② Go 版本：主模块 >= 1.18，若要跑 samples 需 >= 1.21 ----
go version

# ---- ③ 时钟同步（audience.signingTime 依赖）----
date -u && timedatectl 2>/dev/null | sed -n '1,6p'

# ---- ④ IDaaS 实例域名可解析 + 端口可达 ----
curl -s -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n" --max-time 10 \
  https://your-instance.example.com/api/v2/iauths_system/oauth2/token || echo "域名/网络不可达 ❌"

# ---- ⑤ Git 与代理（决定用哪种取码方式）----
git --version 2>/dev/null || echo "(未装 git，走 §5 方式 B)"
```

| 项 | 要求 | 不满足时 |
| --- | --- | --- |
| ECS 实例 | 阿里云 ECS，Linux（Alinux3 / CentOS / Ubuntu 均可） | 换实例，或改测 `client_secret_*` |
| 元数据服务 | `100.100.100.200:80` 可达，且允许 IMDSv2 PUT | 见 §3 |
| Go | ≥ 1.18（推荐 1.22.x） | §4 |
| 时钟 | NTP 开启，UTC 偏差 < 1 分钟 | §4.3 |
| 到 IDaaS 出网 | `your-instance.example.com:443` 可达 | §9 排障矩阵 |
| 服务端配置 | 应用 `app_your_client_id` 上存在名为 `your-federated-credential-name` 的 PKCS#7 联邦凭证，并已信任该 ECS 实例身份 | §6 |

---

## 3. 元数据服务不可达的三种常见原因

```bash
# 看是连不上还是被拒
curl -v -X PUT -H 'x-aliyun-ecs-metadata-token-ttl-seconds: 60' \
  http://100.100.100.200/latest/api/token
```

| 现象 | 根因 | 处置 |
| --- | --- | --- |
| `Connection timed out` / `No route to host` | 不在 ECS 上；或安全组/iptables 拦了 100.100.100.200 | 确认实例；`iptables -L -n` 排查 OUTPUT 链 |
| `403 Forbidden` / 空响应 | 实例开启了「仅加固模式」但请求缺 PUT token 步骤；或元数据访问被实例选项关闭 | 控制台把实例元数据选项设为允许；本 SDK 已按 IMDSv2 走 PUT→GET，无需改代码 |
| 拿到 token 但第 2 步 `404` | 该地域/规格不支持 instance-identity/pkcs7 路径 | 换同地域常规规格验证，或向 IDaaS 管理员（或提交工单）确认支持的部署环境枚举 |

---

## 4. 环境安装

### 4.1 Go（Alinux3 / CentOS）

```bash
sudo dnf install -y golang || {
  # 发行版仓库版本过旧时，直接装官方二进制（1.22 满足主模块 1.18 下限与 samples 的 1.21）
  ver=1.22.5
  curl -fsSL "https://mirrors.aliyun.com/golang/go${ver}.linux-amd64.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
  echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
  source /etc/profile.d/go.sh
}
go version
```

Ubuntu/Debian：`sudo apt-get update && sudo apt-get install -y wget git ca-certificates`，其余同上。

### 4.2 Go 模块代理

```bash
go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
go env -w GONOSUMCHECK=  GONOSUMDB= GOFLAGS=
# 保持 GOSUMDB=sum.golang.org 默认开启，不要 set GOFLAGS=-mod=mod 之外再关掉校验
go env GOPROXY GOSUMDB
```

依赖只有 `github.com/golang-jwt/jwt/v4` 与 `github.com/google/uuid`，走公网镜像即可拉取。

### 4.3 校时

```bash
sudo timedatectl set-ntp true
chronyc sources 2>/dev/null | head -5 || ntpdate -u ntp.cloud.aliyuncs.com
date -u   # 与你的本地 UTC 时间比对，偏差应 < 1 分钟
```

---

## 5. 取代码（两种方式）

分支：`main`，Go module 名：`github.com/cloud-idaas/idaas-go-core-sdk`。

### 方式 A：ECS 上直接 clone（需 git 凭证）

```bash
mkdir -p ~/work && cd ~/work
git clone -b main git@github.com:cloud-idaas/idaas-go-core-sdk.git
cd idaas-go-core-sdk && git log --oneline -1
```

HTTPS 方式（用 access token 而非口令）：

```bash
git clone -b main \
  "https://<用户名>:<access_token>@github.com/cloud-idaas/idaas-go-core-sdk.git"
```

> 不想每次输密码：`git config credential.helper 'cache --timeout=3600'`。

### 方式 B：本地打包上传（ECS 拿不到 git 凭证时，最省事）

在**你的开发机**上执行（已在 ECS 上则跳过）：

```bash
cd <你的 idaas-go-core-sdk 本地路径>
# 只带跟踪文件，排除 .git 与本地凭证目录；vendor 不需要
tar --exclude='.git' --exclude='integration/testdata/.local' \
    -czf /tmp/idaas-go-sdk.tar.gz .
scp /tmp/idaas-go-sdk.tar.gz <user>@<ecs-ip>:/tmp/
```

在**ECS**上：

```bash
mkdir -p ~/work/idaas-go-core-sdk && cd ~/work/idaas-go-core-sdk
tar -xzf /tmp/idaas-go-sdk.tar.gz
go build ./... && echo "代码可用性 OK"
```

> 注意：`integration/testdata/.local/`（client secret / 私钥）**不会**被带上 ECS。PKCS#7 用例本来就不需要它们，所以无需补；只有当你要在 ECS 上顺带跑 `client_secret_*` / `private_key_jwt` / `pca` 时才需要单独创建（见 §8.4）。

---

## 6. IDaaS 控制台确认清单（决定第 3 步能否通过）

这一层在 IDaaS 控制台/服务端，代码无法覆盖。测试前请先按下表逐项确认（列出"要确认什么"与"错了会报什么"）：

| 确认项 | 期望值 | 不匹配时的典型报错 |
| --- | --- | --- |
| 实例 ID `idaasInstanceId` | `idaas_your_instance_id` | `invalid_request` / audience 校验失败 |
| 应用 `clientId` | `app_your_client_id` | `invalid_client` |
| 应用联邦凭证名称 | `your-federated-credential-name`（配置里的 `applicationFederatedCredentialName`） | `invalid_client`、`unauthorized_client` |
| 凭证类型/部署环境 | PKCS#7 + `ALIBABA_CLOUD_ECS`，且信任**这台** ECS 的实例身份 | 断言校验失败 / `invalid_client` |
| 授权 scope | 含 `urn:alibaba:idaas:scope:cloud_account_resource:manage_all`（PAM 前缀见 §7 说明） | `invalid_scope` |
| Token Endpoint | `https://your-instance.example.com/api/v2/iauths_system/oauth2/token` | DNS / 404 |

---

## 7. 配置文件

模板见 `integration/testdata/pkcs7.example.json`，复制到 `integration/testdata/.local/pkcs7.json`（已 gitignore）后替换为真实值：

```json
{
  "idaasInstanceId": "idaas_your_instance_id",
  "clientId": "app_your_client_id",
  "issuer": "https://your-instance.example.com/api/v2/iauths_system/oauth2",
  "tokenEndpoint": "https://your-instance.example.com/api/v2/iauths_system/oauth2/token",
  "scope": "urn:cloud:idaas:pam|urn:alibaba:idaas:scope:cloud_account_resource:manage_all",
  "authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "PKCS7",
    "applicationFederatedCredentialName": "your-federated-credential-name",
    "clientDeployEnvironment": "ALIBABA_CLOUD_ECS"
  },
  "httpConfiguration": { "connectTimeout": 5000, "readTimeout": 10000 }
}
```

字段要点：

- `PKCS7` **不需要** `clientSecretEnvVarName` / `privateKeyEnvVarName`，凭据来自实例身份文档
- `clientDeployEnvironment` 必填且必须是 `ALIBABA_CLOUD_ECS`；当前还支持 `AWS_EC2`（走 `169.254.169.254`）
- `idaasInstanceId` 必填：SDK 把它写进 `audience.aud`（空值报 `IDaaSInstanceIdNotFound`）
- `scope` 里的 `urn:cloud:idaas:pam|` 前缀是 PAM 场景写法；实测（`client_secret_*` 路径）服务端返回的 `scope` 会只保留 `urn:alibaba:idaas:scope:cloud_account_resource:manage_all`，属正常行为，不必当作失败

---

## 8. 执行测试

### 8.1 推荐：一键脚本

```bash
cd ~/work/idaas-go-core-sdk
./scripts/run-integration-on-ecs.sh
```

脚本行为：探活 IMDSv2 → 检查凭证文件（PKCS#7 自动跳过）→ 执行用例 → 打印脱敏摘要 → 失败时按错误特征给下一步提示。

常用参数：

```bash
./scripts/run-integration-on-ecs.sh -m all                      # 全部认证方式
./scripts/run-integration-on-ecs.sh -m client_secret_basic,pca  # 指定多个
./scripts/run-integration-on-ecs.sh -u                          # 先 git pull --ff-only
./scripts/run-integration-on-ecs.sh -n                          # dry-run，只看将执行的命令
./scripts/run-integration-on-ecs.sh -k                          # 跳过探活硬跑（非 ECS 上会失败）
./scripts/run-integration-on-ecs.sh -h                          # 帮助
```

退出码：`0` 通过 / `1` 有用例失败 / `2` 前置条件不满足。
完整日志在 `/tmp/idaas-integration-<时间戳>.log`，**令牌只输出前 8 后 8**，不会整份落盘。

### 8.2 直接 go test

```bash
go test -count=1 -tags integration -v -run TestPkcs7 ./integration/
```

⚠️ `-tags integration` 不能省：整个集成测试包由构建标签门控，不带标签时 `go test ./...` 只会看到 `[no test files]`（这是为了让 CI 不发真实请求）。

### 8.3 成功输出长什么样

```
=== RUN   TestPkcs7
    obtain_token_test.go:45: authnMethod=pkcs7 clientId=app_your_client_id scope=urn:cloud:idaas:pam|urn:alibaba:idaas:scope:cloud_account_resource:manage_all
    obtain_token_test.go:45: 耗时 812ms
    obtain_token_test.go:46: ✅ 获取成功 token=eyJraWQ....HVvb type=Bearer expires_in=14400s scope=urn:alibaba:idaas:scope:cloud_account_resource:manage_all
    obtain_token_test.go:46:    JWT header: alg=RS256 kid=AUTHSKEY...
--- PASS: TestPkcs7 (0.83s)
```

判读三件事：① `PASS`（不是 `SKIP`）；② `expires_in` > 0；③ `scope` 含 `cloud_account_resource:manage_all`。
其中 `JWT header` 是**服务端**签发 access token 的算法与密钥版本，与客户端用什么方式认证无关。

### 8.4 顺带把其它方式也验一遍（可选）

```bash
mkdir -p integration/testdata/.local
cp integration/testdata/credentials.env.example integration/testdata/.local/credentials.env
# 编辑 credentials.env：IDAAS_CLIENT_SECRET=...  IDAAS_PRIVATE_KEY=testdata/.local/xxx.key
chmod 600 integration/testdata/.local/credentials.env   # 该目录已被 .gitignore 忽略
go test -count=1 -tags integration -v ./integration/
```

用完记得在 ECS 上删除，别把密钥留在临时机器：

```bash
shred -u integration/testdata/.local/credentials.env 2>/dev/null || rm -f integration/testdata/.local/credentials.env
rm -f /tmp/idaas-integration-*.log
```

---

## 9. 交叉验证（不依赖 Go 的最小复现）

当 Go 用例失败、需要判断"是 SDK 的问题还是环境/服务端的问题"时，用 curl 手工走一遍同一条链路。

```bash
INSTANCE_ID=idaas_your_instance_id
CLIENT_ID=app_your_client_id
CRED_NAME=your-federated-credential-name
SCOPE='urn:cloud:idaas:pam|urn:alibaba:idaas:scope:cloud_account_resource:manage_all'
TOKEN_EP='https://your-instance.example.com/api/v2/iauths_system/oauth2/token'

# ① IMDSv2 metadata token
MD_TOKEN=$(curl -s -f -X PUT \
  -H 'x-aliyun-ecs-metadata-token-ttl-seconds: 3600' \
  http://100.100.100.200/latest/api/token)
echo "metadata token len=${#MD_TOKEN}"

# ② 实例身份 PKCS#7 文档（audience 为 URL 编码的 JSON）
AUD="{\"aud\":\"${INSTANCE_ID}\",\"signingTime\":$(date +%s)}"
DOC=$(curl -s -f -H "x-aliyun-ecs-metadata-token: ${MD_TOKEN}" \
  --get --data-urlencode "audience=${AUD}" \
  http://100.100.100.200/latest/dynamic/instance-identity/pkcs7)
echo "attested doc len=${#DOC}"; echo "${DOC}" | head -c 120; echo

# ③ 换 access token
curl -sS -X POST "${TOKEN_EP}" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "application_federated_credential_name=${CRED_NAME}" \
  --data-urlencode "client_assertion_type=urn:cloud:idaas:params:oauth:client-assertion-type:pkcs7-bearer" \
  --data-urlencode "client_assertion=${DOC}" \
  --data-urlencode "scope=${SCOPE}" | python3 -m json.tool
```

定位规则：

| 失败步骤 | 结论 |
| --- | --- |
| ① 失败 | 纯环境/元数据问题，与 SDK、IDaaS 无关（回 §3） |
| ② 失败 | 实例不支持该元数据路径或 token 过期，仍属 ECS 侧 |
| ③ 失败 | 服务端/配置问题：联邦凭证名、clientId、scope、实例身份绑定（回 §6） |
| ③ 成功但 Go 用例失败 | 才需要怀疑 SDK 侧，带上 §8.1 的日志一起看 |

> 上面 ③ 的字段与 `oauth2/oauth2_token_util.go` 的 `GetTokenWithPKCS7AttestedDocument` 完全一致（`grant_type=client_credentials` + `client_assertion_type=...pkcs7-bearer` + `client_assertion=<PKCS#7文档>` + `application_federated_credential_name`）。

---

## 10. 排障矩阵

| 症状（日志关键词） | 根因 | 处置 |
| --- | --- | --- |
| `--- SKIP: TestPkcs7` + `需要 ECS 元数据服务 ... 不可达` | 不在 ECS 上 / 元数据被拦 | 回 §3；确认机器后再跑 |
| `[DnsLookupFailed]` / `no such host` | ECS 无法解析 IDaaS 实例域名 | 配 VPC DNS，或临时：`echo "<IP> your-instance.example.com" | sudo tee -a /etc/hosts`（IP 向 IDaaS 管理员获取，属临时手段） |
| `[ConnectTimeOut]`（443 超时） | 出网/安全组/代理限制 | 检查安全组出方向、`curl -v` 看 TLS 阶段 |
| `certificate is not trusted` / TLS 报错 | 实例证书链配置问题 | 先确认为何需要忽略证书；**不要**为了跑通长期设 `unsafeIgnoreSSLCert`（测试代码里有此字段，仅可临时用于联调验证） |
| `HTTP 400 invalid_client` / `unauthorized_client` | 联邦凭证名不匹配 / 实例未被信任 | 核对 `your-federated-credential-name` 与实例身份绑定（§6） |
| `HTTP 400 invalid_scope` / `scope ... not authorized` | 应用未授权该 scope | 在 IDaaS 控制台为应用授权 `cloud_account_resource:manage_all` |
| `audience` / `signingTime` / `expired` 字样 | 时钟漂移 | 回 §4.3 校时后重跑 |
| `IDaaSInstanceIdNotFound` | 配置漏 `idaasInstanceId` | 补 §7 字段 |
| `ApplicationFederatedCredentialNameNotFound` | 配置漏 `applicationFederatedCredentialName` | 补 §7 字段 |
| `UnsupportedClientDeployEnvironment` | `clientDeployEnvironment` 拼写/取值不对 | 必须是 `ALIBABA_CLOUD_ECS`（大小写不敏感，脚本会归一化） |
| `go build` 报 `no required module provides ...` | 依赖代理没配 | 回 §4.2 |
| `undefined: ...` 或 `cannot import .../internal/...` | 用了旧分支/旧 module 路径 | `git pull` 到 `main` 分支；module 为 `github.com/cloud-idaas/idaas-go-core-sdk` |

---

## 11. 安全注意

- 手册与仓库里都不放密钥：PKCS#7 的凭据来自实例身份，本用例**无需**任何 secret
- 令牌只在测试日志里以"前 8 + 后 8"形式出现；完整令牌不落盘、不进 shell 历史
- `integration/testdata/.local/` 已被 `.gitignore` 忽略；ECS 属临时环境，测完按 §8.4 清理
- 本手册使用的测试实例不是生产环境：不要用它验证正式权限策略，也别把生产配置拿来跑本手册

---

## 12. 附录

### 12.1 关键源码位置

| 作用 | 位置 |
| --- | --- |
| 元数据地址常量 | `constants/auth_constants.go:17`（token）、`:21`（pkcs7 模板）、`:28`（默认 TTL 3600） |
| IMDSv2 两步实现 | `internal/implementation/authentication/ecs_attested_document_provider.go` |
| PKCS#7 分支路由 | `internal/implementation/machine_credential_provider.go` 的 `getPkcs7CredentialForDeployEnv` |
| Token 请求表单 | `oauth2/oauth2_token_util.go` 的 `GetTokenWithPKCS7AttestedDocument` |
| 用例与探活 | `integration/obtain_token_test.go` 的 `TestPkcs7`、`integration/support_test.go` 的 `skipIfEnvironmentUnavailable` |
| 一键脚本 | `scripts/run-integration-on-ecs.sh` |

### 12.2 命令速查

```bash
# 探活
curl -s -X PUT -H 'x-aliyun-ecs-metadata-token-ttl-seconds: 60' http://100.100.100.200/latest/api/token

# 跑 PKCS#7
./scripts/run-integration-on-ecs.sh
go test -count=1 -tags integration -v -run TestPkcs7 ./integration/

# 跑全部
./scripts/run-integration-on-ecs.sh -m all
go test -count=1 -tags integration -v ./integration/

# 只编译不发包（验证标签/语法）
go test -tags integration -short ./integration/

# 清理
rm -f /tmp/idaas-integration-*.log
```

### 12.3 结果记录模板

```
测试时间：
ECS 实例 ID / 地域 / 规格：
代码分支与 commit：
Go 版本：
IDaaS 实例 / 应用 / 联邦凭证：
结果：PASS / FAIL / SKIP
expires_in：
返回 scope：
Access Token 前缀（脱敏）：
完整日志路径：
失败时的错误码与首次出现步骤（§9 的 ①②③）：
处置动作 / 待 IDaaS 管理员确认项：
```
