# 多云部署面 M2M 换票 —— 实操手册（AWS EC2 / K8s / Azure VM / GCE VM）

> 被测能力：`authnMethod=PKCS7`+`clientDeployEnvironment=AWS_EC2`，以及 `authnMethod=OIDC`+
> `clientDeployEnvironment=KUBERNETES/AZURE_VM/GOOGLE_VM` 的机器对机器（M2M）换票；
> 另附 refresh_token 续期复测。
> 阿里云 ECS 的 PKCS#7 场景见姊妹篇 [`pkcs7-ecs-m2m-test-manual.md`](./pkcs7-ecs-m2m-test-manual.md)。
> 对应用例：`TestPkcs7AwsEc2` / `TestOidcKubernetes` / `TestOidcAzureVm` / `TestOidcGoogleVm` / `TestRefreshTokenRenewal`（均在 `integration/`，环境探活失败自动 skip）。

---

## 0. 先说结论（各场景最短路径）

```bash
# 公共准备：复制模板 → .local，填入真实 idaasInstanceId/clientId/issuer/tokenEndpoint/联邦凭证名
cd integration/testdata && mkdir -p .local
cp pkcs7_aws_ec2.example.json .local/pkcs7_aws_ec2.json          # 场景 A（示例）
cd ../..

# 场景 A：AWS EC2 PKCS7 —— 在 EC2 实例上
curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
  http://169.254.169.254/latest/api/token && echo   # 有输出=IMDSv2 可用
go test -count=1 -tags integration -v -run TestPkcs7AwsEc2 ./integration/

# 场景 B：K8s SA OIDC —— 在集群内 Pod 中执行（SA token 默认路径可读）
go test -count=1 -tags integration -v -run TestOidcKubernetes ./integration/

# 场景 C：Azure VM MI OIDC —— 在绑定了 MI 的 Azure VM 上
curl -s -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' | head -c 80 && echo
go test -count=1 -tags integration -v -run TestOidcAzureVm ./integration/

# 场景 D：GCE VM OIDC —— 在 GCE VM 上
curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/ -o /dev/null -w '%{http_code}\n'  # 200=在 GCP
go test -count=1 -tags integration -v -run TestOidcGoogleVm ./integration/
```

看到 `--- PASS: TestXxx` 且日志含 `✅ 获取成功 token=... type=Bearer` 即成功；
看到 `--- SKIP: TestXxx` 说明**不在对应云上/探活失败**（这是设计行为，不是代码问题）。

## 1. 公共前置条件

| # | 条件 | 校验命令 |
| --- | --- | --- |
| ① | Go ≥ 1.18 | `go version` |
| ② | 代码在目标机器上且能编译集成包 | `go vet -tags integration ./integration/` |
| ③ | `.local/<场景名>.json` 已按模板填好真实实例值 | 缺失/字段为空会 skip 并提示 |
| ④ | IDaaS 日常/测试域名可解析、token endpoint 可达 | `curl -s -o /dev/null -w '%{http_code}' <tokenEndpoint>` |
| ⑤ | 时钟大致同步（JWT nbf/exp 校验依赖） | `date -u` 与真实 UTC 偏差 < 5min |

## 2. 场景 A：AWS EC2 + PKCS7

**机器身份**：EC2 实例元数据服务签发实例身份文档（PKCS#7 签名），SDK 以其为断言换 M2M token。

1. 确认 IMDSv2 可用（探活逻辑与集成用例一致，见 `support_test.go: awsEc2ImdsReachable`）：

   ```bash
   TOKEN=$(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
     http://169.254.169.254/latest/api/token)
   curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/dynamic/instance-identity/pkcs7 | head -c 60 && echo
   ```

   - 取不到 token：检查实例是否强制 IMDSv2 但走了 v1 路径 / hop limit 是否为 0 / 是否有本地代理劫持 `169.254.169.254`。
2. **IDaaS 侧登记**：应用的联邦凭证（`applicationFederatedCredentialName`）选择 AWS 类型，
   登记的 `aws_account_id` 必须与实例所属账号一致（文档内 `accountId` 字段可用上面第二条命令换 `identity` 文档查看）。
3. 运行：`go test -count=1 -tags integration -v -run TestPkcs7AwsEc2 ./integration/`（注意阿里云 ECS 是另一个用例 `TestPkcs7`）。

## 3. 场景 B：Kubernetes + OIDC

**断言来源**：Pod 挂载的 Service Account JWT（默认 `/var/run/secrets/kubernetes.io/serviceaccount/token`，
路径解析顺序 `oidcTokenFilePath` → 环境变量 → SA 默认路径，与 `fetchOidcToken` KUBERNETES 分支一致）。

1. 在集群内运行测试。两种姿势：

   ```bash
   # 姿势一：把代码 copy 进 Pod，kubectl exec 进去跑 go test（SA 默认路径天然可读）
   kubectl exec -it <pod> -- bash -lc 'cd /path/to/sdk && go test -count=1 -tags integration -v -run TestOidcKubernetes ./integration/'

   # 姿势二：在能访问集群的开发机上，用 kubectl create token 生成 SA token 落盘，
   #         配置 oidcTokenFilePath 指向该文件（注意 projected token 默认 1h 过期）
   kubectl create token <sa> --audience=<IDaaS联邦凭证约定audience> --output=/tmp/sa.jwt
   ```
2. **IDaaS 侧登记**：联邦凭证信任该集群 API Server 的 OIDC issuer
   （`https://oidc.eks.<region>.amazonaws.com/id/<id>` 或 ACK/自建集群的 issuer URL），
   且对 token 的 `aud`/`sub` 有匹配规则。audience 不匹配是此场景最常见的服务端拒绝原因。
3. 失败排查：`kubectl get --raw /.well-known/openid-configuration` 核对 issuer；
   `jwt decode` SA token 核对 `iss/aud/sub` 与 IDaaS 登记规则。

## 4. 场景 C：Azure VM + OIDC（Managed Identity）

SDK 从 Azure IMDS 取 Managed Identity 的 ARM resource token 作为断言。
**集成用例的探活就是真实取一次 MI token**（非 200 即 skip），因此 skip 消息出现时优先怀疑 MI 未绑定。

1. 确认 VM 已分配 MI 且 IMDS 直通：

   ```bash
   curl -s -H 'Metadata: true' \
     'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' \
     | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"][:40])'
   ```
   - 400/500：MI 未绑定或 agent 未就绪；被组织代理劫持 169.254 时返回体不是 JSON，也按不可用处理。
2. **IDaaS 侧登记**：联邦凭证信任 `https://sts.windows.net/<tenant-id>/` issuer，
   subject 规则匹配该 MI 的 `principalId`/`clientId`（token payload 的 `idobj`/`appid` claim）。
3. 运行：`go test -count=1 -tags integration -v -run TestOidcAzureVm ./integration/`。

## 5. 场景 D：GCE VM + OIDC

SDK 请求 GCE 元数据服务签发 ID Token，**audience 固定取配置里 `issuer` 的 origin**
（`scheme://host`，与 `fetchOidcToken` GOOGLE_VM 分支一致）。

1. 确认在 GCE 上且默认 SA 可用：

   ```bash
   curl -s -H 'Metadata-Flavor: Google' \
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=$(python3 -c 'from urllib.parse import urlparse;u=urlparse("<你的issuer URL>");print(u.scheme+"://"+u.netloc)')&format=full" | head -c 40 && echo
   ```
   - `metadata.google.internal` 解析失败：不在 GCP；返回 403：VM 未挂 SA 或访问控制拦截。
2. **IDaaS 侧登记**：联邦凭证信任 `https://accounts.google.com` issuer，
   subject 匹配 VM 挂载的 service account email，audience 与 issuer origin 一致。
3. 运行：`go test -count=1 -tags integration -v -run TestOidcGoogleVm ./integration/`。

## 6. refresh_token 续期复测（半自动）

M2M client_credentials 不下发 refresh_token，`TestRefreshTokenRenewal` 设计为"拿到真实
refresh_token 后一键复测"：

```bash
# 1) 先走一次 device code（samples/device-code 或 TestHumanFederatedDeviceFlow_RealIdP），
#    从响应里保存 refresh_token
export IDAAS_REFRESH_TOKEN='<refresh_token>'
# 2) 复测续期链路（配置复用 .local/client_secret_basic.json）
go test -count=1 -tags integration -v -run TestRefreshTokenRenewal ./integration/
```

未设置 `IDAAS_REFRESH_TOKEN` 时用例 skip。若实例要求 confidential client 携带凭证续期而报
`invalid_client`，属于 `oauth2.OAuth2TokenUtil.RefreshToken` 公共 API 形态（仅带 client_id）
与服务端要求的差异，日志含 requestId 可供服务端排查。

## 7. skip / FAIL 语义速查

| 现象 | 含义 | 下一步 |
| --- | --- | --- |
| SKIP：探活失败 | 不在对应云环境 | 换到对应 VM/Pod 再跑 |
| SKIP：配置/凭证缺失 | `.local` 未准备 | 按提示 `cp` 模板并填值 |
| FAIL：`invalid_client`/联邦凭证校验失败 | 已连通但 IDaaS 侧登记不匹配 | 对照各场景"IDaaS 侧登记"小节核对 issuer/aud/sub |
| FAIL：`DnsLookupFailed`/`ConnectTimeOut` | endpoint 不可达 | 检查网络/安全组/代理 |
| PASS | 端到端全链路可用 | — |

批量回归：`TestAllAuthnMethods` 会逐个跑 11 份配置（未准备 `.local` 的自动跳过），适合在多云机器上
一次看整组兼容性。
