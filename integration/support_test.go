//go:build integration

package integration

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	idaaserrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// 集成测试的运行约定：
//
//	go test -tags integration -v ./integration/                         # 全部认证方式
//	go test -tags integration -v -run TestClientSecretBasic ./integration/  # 只跑某一种
//	go test -tags integration -short ./integration/                     # 跳过（不发真实请求）
//	IDAAS_IT=off go test -tags integration ./integration/               # 同上，临时关掉
//
// 整个包由 `integration` 构建标签门控：不带标签时 go build / go vet / go test ./...
// 都不会编译或运行这些用例，CI（无凭证、无内网）因此不会被拖挂。
//
// 被测环境（endpoint / clientId / scope / 证书）放在 testdata/.local/<authnMethod>.json，
// 仓库里只提交占位模板 testdata/<authnMethod>.example.json；
// 凭证只从环境变量或 testdata/.local/credentials.env 读取。testdata/.local/ 整个目录已被 .gitignore 忽略。

const localEnvFileName = "credentials.env"

var (
	loadLocalOnce sync.Once
	localEnvErr   error
)

// localEnvPath 返回本地凭证文件路径（不存在时返回空字符串）
func localEnvPath() string {
	p := filepath.Join("testdata", ".local", localEnvFileName)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// loadLocalEnv 把 testdata/.local/credentials.env 里的 KEY=VALUE 灌进环境变量。
// 已存在的环境变量优先，方便临时覆盖（如换一把密钥）而不用改文件。
func loadLocalEnv(t *testing.T) {
	t.Helper()
	loadLocalOnce.Do(func() {
		path := localEnvPath()
		if path == "" {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			localEnvErr = err
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			if os.Getenv(key) == "" {
				os.Setenv(key, value)
			}
		}
		localEnvErr = scanner.Err()
	})
	if localEnvErr != nil {
		t.Fatalf("读取本地凭证文件失败: %v", localEnvErr)
	}
}

// skipIfIntegrationDisabled 在 -short 或 IDAAS_IT=off 时跳过
func skipIfIntegrationDisabled(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("跳过集成测试（-short）")
	}
	switch strings.ToLower(os.Getenv("IDAAS_IT")) {
	case "off", "0", "false", "no":
		t.Skip("跳过集成测试（IDAAS_IT=off）")
	}
}

// loadConfig 加载 testdata/.local/<name>.json；不存在时提示从 <name>.example.json 复制并 skip
func loadConfig(t *testing.T, name string) *config.IDaaSClientConfig {
	t.Helper()
	path := filepath.Join("testdata", ".local", name+".json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("环境配置缺失：请执行 cp integration/testdata/%s.example.json integration/%s 并填入真实值", name, path)
	}
	cfg, err := config.NewConfigReader().LoadFromFile(path)
	if err != nil {
		t.Fatalf("加载配置 %s 失败: %v", path, err)
	}
	if cfg.AuthnConfiguration == nil {
		t.Fatalf("配置 %s 缺少 authnConfiguration", path)
	}
	return cfg
}

// ensureCredentials 按配置声明的变量名检查凭证是否就绪；缺失时给出可执行的提示并 skip。
// 私钥允许填 PEM 原文，也允许填文件路径（SDK 的 LoadPrivateKeyMaterial 两种都支持）。
func ensureCredentials(t *testing.T, cfg *config.IDaaSClientConfig) {
	t.Helper()
	loadLocalEnv(t)
	authn := cfg.AuthnConfiguration

	if authn.ClientSecretEnvVarName != "" && os.Getenv(authn.ClientSecretEnvVarName) == "" {
		t.Skipf("凭证缺失：请设置环境变量 %s，或写入 integration/testdata/%s/%s",
			authn.ClientSecretEnvVarName, ".local", localEnvFileName)
	}
	if authn.PrivateKeyEnvVarName != "" {
		material := os.Getenv(authn.PrivateKeyEnvVarName)
		if material == "" {
			t.Skipf("凭证缺失：请设置环境变量 %s（PEM 原文或私钥文件路径），或写入 integration/testdata/%s/%s",
				authn.PrivateKeyEnvVarName, ".local", localEnvFileName)
		}
		if !strings.Contains(material, "-----BEGIN") {
			if _, err := os.Stat(material); err != nil {
				t.Skipf("%s 既不是 PEM 也不是可读文件路径（%v）：请修正凭证配置", authn.PrivateKeyEnvVarName, err)
			}
		}
	}
}

// metadataProbeTimeout 探测 ECS 元数据服务是否真实响应的超时。探活只为决定 skip，
// 不该拖慢测试；取 2s 既能在代理只接受 TCP 却挂起 HTTP 的开发机上快速失败，也能
// 容忍真实 IMDS 偶发的慢响应。
const metadataProbeTimeout = 2 * time.Second

// skipIfEnvironmentUnavailable 检查该认证方式依赖的运行环境是否具备，不具备则 skip 而不是 fail。
//
// PKCS7 + ALIBABA_CLOUD_ECS 依赖 SDK 里硬编码的 ECS 元数据服务（constants.EcsMetadataServiceUrl），
// 只有真正跑在阿里云 ECS 实例上才可达；在开发机上它必然超时，报 FAIL 只会掩盖真实问题。
func skipIfEnvironmentUnavailable(t *testing.T, cfg *config.IDaaSClientConfig) {
	t.Helper()
	authn := cfg.AuthnConfiguration

	if authn.AuthnMethod == enums.TokenAuthnMethodPkcs7 &&
		authn.ClientDeployEnvironment == enums.ClientDeployEnvironmentAlibabaCloudEcs {
		if !imdsReachable() {
			t.Skipf("跳过 PKCS7：需要 ECS 元数据服务 %s 真实响应 IMDSv2 token 请求，当前环境探活失败。请在阿里云 ECS 实例上运行该用例",
				constants.EcsMetadataServiceUrl)
		}
	}

	if authn.AuthnMethod == enums.TokenAuthnMethodOidc {
		switch authn.ClientDeployEnvironment {
		case enums.ClientDeployEnvironmentAzureVm:
			if !azureImdsReachable() {
				t.Skipf("跳过 OIDC/AZURE_VM：Azure IMDS 未返回 Managed Identity token（需 200）。"+
					"请在绑定了 MI 的 Azure VM 上运行该用例，探活 URL: %s", azureImdsProbeUrl())
			}
		case enums.ClientDeployEnvironmentGoogleVm:
			if !gcpMetadataReachable() {
				t.Skip("跳过 OIDC/GOOGLE_VM：metadata.google.internal 不可达（GCP 之外无法解析）。请在 GCE VM 上运行该用例")
			}
		default:
			// COMPUTER / KUBERNETES：OIDC token 来自本地文件（K8s 可回落 SA 默认路径）
			skipIfOidcTokenUnavailable(t, authn)
		}
	}

	if authn.AuthnMethod == enums.TokenAuthnMethodPkcs7 &&
		authn.ClientDeployEnvironment == enums.ClientDeployEnvironmentAwsEc2 {
		if !awsEc2ImdsReachable() {
			t.Skipf("跳过 PKCS7/AWS_EC2：EC2 元数据服务 %s 未响应 IMDSv2 token 请求（探活失败）。"+
				"请在启用 IMDSv2 的 AWS EC2 实例上运行该用例", constants.Ec2MetadataServiceUrl)
		}
	}
}

// skipIfOidcTokenUnavailable 复刻 SDK 的 OIDC token 路径解析顺序，探到可用文件才继续跑。
//
// 解析顺序与 internal/implementation/machine_credential_provider.go 保持一致：
//  1. authnConfiguration.oidcTokenFilePath
//  2. 环境变量 authnConfiguration.oidcTokenFilePathEnvVarName 的值
//  3. 仅 KUBERNETES：回落 constants.K8sServiceAccountTokenPath（COMPUTER 不回落，缺路径直接是配置错误）
func skipIfOidcTokenUnavailable(t *testing.T, authn *config.IdentityAuthenticationConfiguration) {
	t.Helper()

	source := "authnConfiguration.oidcTokenFilePath"
	path := authn.OidcTokenFilePath
	if path == "" && authn.OidcTokenFilePathEnvVarName != "" {
		source = "环境变量 " + authn.OidcTokenFilePathEnvVarName
		path = os.Getenv(authn.OidcTokenFilePathEnvVarName)
	}
	if path == "" && authn.ClientDeployEnvironment == enums.ClientDeployEnvironmentKubernetes {
		source = "K8s 默认 SA 路径"
		path = constants.K8sServiceAccountTokenPath
	}
	if path == "" {
		t.Skipf("跳过 OIDC：oidcTokenFilePath 与 %s 都为空（COMPUTER 模式不会回落默认路径）。"+
			"请先 export %s=/path/to/id-token.jwt",
			orUnset(authn.OidcTokenFilePathEnvVarName, "OIDC_TOKEN_FILE_PATH"),
			orUnset(authn.OidcTokenFilePathEnvVarName, "OIDC_TOKEN_FILE_PATH"))
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("跳过 OIDC：token 文件不可读（%s 解析为 %s：%v）。"+
			"路径需绝对路径，或相对 go test 的工作目录 integration/；K8s 内可用 kubectl create token <sa> 生成",
			source, path, err)
	}
	t.Logf("OIDC token 来源: %s -> %s", source, path)
}

func orUnset(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// imdsReachable 探测 ECS IMDSv2 是否真实响应。
//
// 仅做 TCP 连通性判定会误判：某些开发机/代理会接受到 100.100.100.200:80 的 TCP
// 连接（SYN 被透明转发或本地防火墙代答），但并不真正提供 IMDS 服务，导致后续
// GetCredential 的 PUT /latest/api/token 长时间挂起后超时 FAIL。这里改成发一个短
// 超时的 IMDSv2 token 请求：只有真正返回 2xx 才认为 IMDS 可用。
func imdsReachable() bool {
	client := &nethttp.Client{Timeout: metadataProbeTimeout}
	req, err := nethttp.NewRequest(nethttp.MethodPut, constants.EcsMetadataServiceUrl, nethttp.NoBody)
	if err != nil {
		return false
	}
	req.Header.Set(constants.HeaderXAliyunEcsMetadataTokenTtlSeconds, "5")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// azureImdsProbeUrl 与 SDK 取票同一入口（AzureVmIdentityTokenUrlTemplate + resource=management.azure.com），
// 只有绑定了 Managed Identity 的 Azure VM 才会返回 200——这正是本场景真正的前置条件，
// 4xx/5xx（非 Azure、无 MI、IMDS 被劫持）一律按"环境不具备"处理。
func azureImdsProbeUrl() string {
	return fmt.Sprintf(constants.AzureVmIdentityTokenUrlTemplate,
		url.QueryEscape("https://management.azure.com/"))
}

// azureImdsReachable 探测 Azure IMDS Managed Identity token 是否真实可得（要求 200）。
func azureImdsReachable() bool {
	client := &nethttp.Client{Timeout: metadataProbeTimeout}
	req, err := nethttp.NewRequest(nethttp.MethodGet, azureImdsProbeUrl(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == nethttp.StatusOK
}

// gcpMetadataReachable 探测 GCE 元数据服务。metadata.google.internal 仅 GCP 内可解析，
// 带 Metadata-Flavor: Google 访问根路径返回 200 即认为在 GCE 上。
func gcpMetadataReachable() bool {
	client := &nethttp.Client{Timeout: metadataProbeTimeout}
	req, err := nethttp.NewRequest(nethttp.MethodGet, "http://metadata.google.internal/", nethttp.NoBody)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// awsEc2ImdsReachable 探测 EC2 IMDSv2：PUT /latest/api/token 返回 2xx 才继续。
// 与阿里云探活同理——只做 TCP 连通判定会被代理/防火墙代答误判。
func awsEc2ImdsReachable() bool {
	client := &nethttp.Client{Timeout: metadataProbeTimeout}
	req, err := nethttp.NewRequest(nethttp.MethodPut, constants.Ec2MetadataServiceUrl, nethttp.NoBody)
	if err != nil {
		return false
	}
	req.Header.Set(constants.HeaderXAwsEc2MetadataTokenTtlSeconds, "5")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// newHttpClientFromConfig 按配置组装 HTTP 客户端（超时/SSL 开关取自 httpConfiguration）。
// 供 newProvider 与 token-exchange 等需要裸 httpClient 的用例共用，保证与真实用户配置一致。
func newHttpClientFromConfig(cfg *config.IDaaSClientConfig) http.HttpClient {
	if cfg.HttpConfiguration != nil {
		return http.NewDefaultHttpClientWithOptions(
			cfg.HttpConfiguration.ConnectTimeout,
			cfg.HttpConfiguration.ReadTimeout,
			cfg.HttpConfiguration.UnsafeIgnoreSSLCert,
		)
	}
	return http.NewDefaultHttpClient(0, 0)
}

// newProvider 按配置组装机器凭证提供者。
//
// staleValueBehavior 规范化与 factory.effectiveStaleValueBehavior 对齐：空值回退 REFRESH，
// .local 配置里显式声明时按其生效（此前硬编码 REFRESH 会静默忽略配置项，集成行为与用户入口不一致）。
func newProvider(cfg *config.IDaaSClientConfig) provider.IDaaSCredentialProvider {
	stale := enums.StaleValueBehaviorRefresh
	if cfg.StaleValueBehavior != "" {
		stale = cfg.StaleValueBehavior
	}
	return implementation.NewIDaaSMachineCredentialProvider(cfg, stale, newHttpClientFromConfig(cfg))
}

// obtainToken 走完整链路取 Token；失败时把 authnMethod 和耗时一起报出来
func obtainToken(t *testing.T, name string) (credential.IDaaSCredential, *config.IDaaSClientConfig) {
	t.Helper()
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, name)
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)
	t.Logf("authnMethod=%s clientId=%s scope=%s", cfg.AuthnConfiguration.AuthnMethod, cfg.ClientId, cfg.Scope)

	started := time.Now()
	cred, err := newProvider(cfg).GetCredential()
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("获取 Token 失败 (authnMethod=%s, 耗时 %v): %v\n%s",
			cfg.AuthnConfiguration.AuthnMethod, elapsed.Round(time.Millisecond), err, describeError(err))
	}
	t.Logf("耗时 %v", elapsed.Round(time.Millisecond))
	return cred, cfg
}

// describeError 把 SDK 的结构化错误摊平成一行可定位信息：错误码 | 服务端描述 | requestId。
//
// 为什么还要额外打一遍：t.Fatalf("%v") 只调用 Error()，而 OAuth2Error.Error() 刻意不带
// RawBody（日志安全考虑）。排查联邦凭证类失败（PKCS7/PCA/OIDC）时，服务端在响应体里给的
// error_description 往往才是唯一线索，所以这里走 ErrorMessage()——它在描述为空时回落到 RawBody。
// 打印前先 scrubSecrets 定向洗掉可能被回显的凭证（JWT / 长随机串），再截断，
// 避免超大响应体刷屏。不用 logger.Redact：它对任何 >6 字符的串都整体遮蔽，
// 会把 error_description 这种唯一线索糊成一团，反而失去这段诊断的意义。
func describeError(err error) string {
	if err == nil {
		return ""
	}
	idErr, ok := idaaserrors.AsIDaaSError(err)
	if !ok {
		return "detail=" + truncate(scrubSecrets(err.Error()), 400)
	}

	parts := []string{"code=" + idErr.ErrorCode()}
	if msg := strings.TrimSpace(idErr.ErrorMessage()); msg != "" {
		parts = append(parts, "detail="+truncate(scrubSecrets(msg), 400))
	}
	if id := idaaserrors.RequestIdOf(err); id != "" {
		parts = append(parts, "requestId="+id+"（提工单/查服务端日志用这个）")
	}
	return strings.Join(parts, " | ")
}

// jwtLikeRe 匹配三段式 JWT（header.payload.signature）。
var jwtLikeRe = regexp.MustCompile(`[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)

// longOpaqueRe 只认纯字母数字的长随机串（client_secret、base64 大块），
// 因此不会误伤 URL，也不会把带下划线的资源 ID（idaas_xxx / app_xxx）洗掉。
var longOpaqueRe = regexp.MustCompile(`[A-Za-z0-9]{32,}`)

func scrubSecrets(s string) string {
	s = jwtLikeRe.ReplaceAllString(s, "<jwt>")
	return longOpaqueRe.ReplaceAllString(s, "<opaque>")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("...(共 %d 字节，已截断)", len(s))
}

// assertCredential 校验返回凭证的基本字段，并打印 JWT 头部（alg/kid 能反映实际走的签名路径）
func assertCredential(t *testing.T, cred credential.IDaaSCredential, wantScopeContains string) {
	t.Helper()

	if cred.GetAccessToken() == "" {
		t.Error("AccessToken 为空")
	}
	if got := cred.GetTokenType(); got != "Bearer" {
		t.Errorf("TokenType = %q, 期望 Bearer", got)
	}
	if cred.GetExpiresIn() <= 0 {
		t.Errorf("ExpiresIn 无效: %d", cred.GetExpiresIn())
	}
	if wantScopeContains != "" && !strings.Contains(cred.GetScope(), wantScopeContains) {
		t.Errorf("Scope = %q, 期望包含 %q", cred.GetScope(), wantScopeContains)
	}

	t.Logf("✅ 获取成功 token=%s... type=%s expires_in=%ds scope=%s",
		preview(cred.GetAccessToken()), cred.GetTokenType(), cred.GetExpiresIn(), cred.GetScope())
	if header := jwtHeader(t, cred.GetAccessToken()); header != "" {
		t.Logf("   JWT header: %s", header)
	}
}

// preview 屏蔽中间内容，避免日志里出现完整令牌
func preview(token string) string {
	if len(token) <= 16 {
		return "***"
	}
	return token[:8] + "..." + token[len(token)-8:]
}

// jwtHeader 解出 access token 的 JOSE 头，便于确认签名算法与密钥版本
func jwtHeader(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Logf("解码 JWT header 失败: %v", err)
		return ""
	}
	var head map[string]interface{}
	if err := json.Unmarshal(raw, &head); err != nil {
		return ""
	}
	keys := make([]string, 0, len(head))
	for _, k := range []string{"alg", "kid", "typ"} {
		if v, ok := head[k]; ok {
			keys = append(keys, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(keys, " ")
}
