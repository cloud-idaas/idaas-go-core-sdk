//go:build integration

// Package integration 集成测试:跨 host 重定向剥离 Authorization、元数据 token
// 不泄漏等安全处理在真实环境下的端到端验证。
//
// 这组测试与单元/boundary 测试的区别:它们依赖真实运行环境(真实 OIDC token 文件、
// 真实 IdP 端点),由 //go:build integration 标签门控,CI(无凭证、无内网)不跑。
// 运行约定见 support_test.go 头部注释。
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	idhttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation/authentication"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// capturingLogger 记录 Warn 调用,供安全修复集成测试断言。
// 与 authentication 包测试里的 capturingLogger 同构,因跨包无法复用,这里内联一份。
type capturingLogger struct {
	mu    sync.Mutex
	warns []string // 每条 Warn 的 flat kv,便于 Contains 断言
}

func (c *capturingLogger) Debug(context.Context, string, ...interface{}) {}
func (c *capturingLogger) Info(context.Context, string, ...interface{})  {}
func (c *capturingLogger) Warn(_ context.Context, _ string, kv ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warns = append(c.warns, flattenKVIntegration(kv))
}
func (c *capturingLogger) Error(_ context.Context, msg string, kv ...interface{}) {}

func flattenKVIntegration(kv []interface{}) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string)
		b.WriteString(k)
		b.WriteByte('=')
		fmt.Fprintf(&b, "%v", kv[i+1])
		b.WriteByte(' ')
	}
	return b.String()
}

// withCapturingLogger 注入 capturingLogger 作为包级 default,返回 logger 与恢复函数。
func withCapturingLogger(t *testing.T) (*capturingLogger, func()) {
	t.Helper()
	orig := logger.Default()
	cl := &capturingLogger{}
	logger.SetDefault(cl)
	return cl, func() { logger.SetDefault(orig) }
}

// resolveOidcTokenPath 复刻 SDK 的 OIDC token 路径解析顺序,用于在集成测试里
// 定位真实 token 文件以 stat 其权限。与 support_test.go 的 skipIfOidcTokenUnavailable
// 同源,但这里不 skip——前置的 skipIfEnvironmentUnavailable 已保证文件存在。
func resolveOidcTokenPath(authn *config.IdentityAuthenticationConfiguration) string {
	if path := authn.OidcTokenFilePath; path != "" {
		return path
	}
	if name := authn.OidcTokenFilePathEnvVarName; name != "" {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	if authn.ClientDeployEnvironment == enums.ClientDeployEnvironmentKubernetes {
		return constants.K8sServiceAccountTokenPath
	}
	return ""
}

// TestFileOidcPermissionCheck_RealTokenFile 端到端验证 #1 权限校验在真实 OIDC token 文件下:
//
//  1. 走完整 machine provider 链路(config → NewIDaaSMachineCredentialProvider →
//     内部构造 FileOidcTokenProvider → 读真实 token 文件 → JWT 解析 → 返回 token);
//  2. 注入 capturingLogger 捕获权限校验的 Warn;
//  3. 按真实 token 文件的实际权限断言:
//     - 0600(secure)→ 不打 Warn;
//     - group/other 可读 → 打一条 insecure_permission Warn。
//
// 核心契约:warn-only 不阻断——无论权限是否安全,GetCredential 必须成功返回 token。
// 这条测试比单元测试更进一步:验证权限校验在真实 SDK 装配(machine provider → file provider)
// 链路里被正确触发,而非仅是 FileOidcTokenProvider 单元行为。
func TestFileOidcPermissionCheck_RealTokenFile(t *testing.T) {
	skipIfIntegrationDisabled(t)

	cfg := loadConfig(t, "oidc_computer")
	ensureCredentials(t, cfg)
	skipIfEnvironmentUnavailable(t, cfg)

	tokenPath := resolveOidcTokenPath(cfg.AuthnConfiguration)
	if tokenPath == "" {
		t.Fatal("OIDC token 路径解析失败,但 skipIfEnvironmentUnavailable 未 skip——逻辑不一致")
	}
	t.Logf("真实 OIDC token 文件: %s", tokenPath)

	info, statErr := os.Stat(tokenPath)
	insecure := statErr == nil && info.Mode().Perm()&0o077 != 0
	if statErr != nil {
		t.Logf("无法 stat token 文件(%v),按 secure 基线断言(不期望 Warn)", statErr)
	} else {
		t.Logf("token 文件权限: %s (insecure=%v)", info.Mode().String(), insecure)
	}

	cl, restore := withCapturingLogger(t)
	defer restore()

	cred, err := newProvider(cfg).GetCredential()
	// 核心 beta 契约:warn-only 不阻断——无论权限是否安全,真实链路必须成功
	if err != nil {
		t.Fatalf("权限校验不应阻断 GetCredential: %v\n%s", err, describeError(err))
	}
	if cred.GetAccessToken() == "" {
		t.Fatal("AccessToken 为空")
	}
	t.Logf("✅ 真实链路成功 token=%s...", preview(cred.GetAccessToken()))

	// 权限告警行为断言
	warnCount := 0
	for _, w := range cl.warns {
		if strings.Contains(w, "status=insecure_permission") {
			warnCount++
		}
	}
	if insecure {
		if warnCount == 0 {
			t.Errorf("token 文件 group/other 可读(perm=%s)但未触发 insecure_permission Warn", info.Mode().String())
		} else {
			t.Logf("✅ 检测到不安全权限并打 Warn %d 条", warnCount)
		}
	} else {
		if warnCount > 0 {
			t.Errorf("token 文件权限安全(perm=%s)却触发了 insecure_permission Warn: %v", info.Mode().String(), cl.warns)
		}
	}
}

// TestOpenBrowser_RealSubprocess_NoUserCodeLeak #3 真实子进程集成测试。
//
// 与 util 包内 TestOpenBrowser_NoUserCodeLeak(普通 _test.go,跑在 CI)的区别:
// 这里走真实 xdg-open/open 子进程路径——CI 上 xdg-open 缺失时退化为 cmd.Start 失败,
// 与普通测试同路径;但在有 GUI 的开发机/容器上 xdg-open 存在时,会真起浏览器进程,
// 验证 cmd.Start 成功路径 + 真实 stderr 捕获下仍不泄漏 user_code。
//
// 因会真实弹出浏览器(若 xdg-open 存在),用 IDAAS_IT_BROWSER=on 显式 opt-in,
// 避免在非预期环境弹窗。-short / IDAAS_IT=off 同样跳过。
func TestOpenBrowser_RealSubprocess_NoUserCodeLeak(t *testing.T) {
	skipIfIntegrationDisabled(t)
	if strings.ToLower(os.Getenv("IDAAS_IT_BROWSER")) != "on" {
		t.Skip("跳过:需 IDAAS_IT_BROWSER=on 显式启用(会真实尝试弹出浏览器)")
	}

	// 捕获 stdlib log(OpenBrowser 在 cmd.Start 失败时打 [DEBUG] 行)
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	// 伪 user_code 嵌在 query 里——无论成功/失败都不得出现在 error 或 stdlib log
	leakyURL := "https://device.example.com/device?user_code=SECRET-INTEGRATION-1234"
	err := util.OpenBrowser(leakyURL)

	if err != nil {
		if strings.Contains(err.Error(), "SECRET-INTEGRATION-1234") {
			t.Errorf("error 泄漏 user_code: %s", err.Error())
		}
		if strings.Contains(err.Error(), "/device?user_code=") {
			t.Errorf("error 泄漏 path+query: %s", err.Error())
		}
	}
	if strings.Contains(logBuf.String(), "SECRET-INTEGRATION-1234") {
		t.Errorf("stdlib log 泄漏 user_code: %s", logBuf.String())
	}
	if err != nil {
		t.Logf("OpenBrowser 失败(预期:无 xdg-open 或浏览器启动失败),error: %s", err.Error())
	} else {
		t.Logf("✅ OpenBrowser 成功启动真实浏览器进程(无 user_code 泄漏)")
	}
}

// humanFederatedConfig 是 human federated device flow 集成测试的原始配置形状。
// 不走 IDaaSClientConfig(human federated 不在 8 个 M2M authnMethod 里),
// 直接用构造函数参数对应的字段,便于指向真实 IdP。
type humanFederatedConfig struct {
	InstanceId                  string `json:"instanceId"`
	ClientId                    string `json:"clientId"`
	TokenEndpoint               string `json:"tokenEndpoint"`
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint"`
}

// loadHumanFederatedConfig 加载 testdata/.local/human_federated.json;不存在则 skip。
// 这条链路需要人工扫码完成授权,CI 无 .local 配置 → skip,仅作为人工集成验证入口。
func loadHumanFederatedConfig(t *testing.T) *humanFederatedConfig {
	t.Helper()
	path := filepath.Join("testdata", ".local", "human_federated.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("环境配置缺失:请执行 cp integration/testdata/human_federated.example.json integration/%s 并填入真实值(需人工扫码,仅作人工集成验证入口)", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	// 剥离 _comment* 字段后再 unmarshal(json 忽略未知字段,注释字段是 string 可直接解)
	var cfg humanFederatedConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	if cfg.ClientId == "" || cfg.TokenEndpoint == "" || cfg.DeviceAuthorizationEndpoint == "" {
		t.Skipf("配置 %s 缺少 clientId/tokenEndpoint/deviceAuthorizationEndpoint,跳过", path)
	}
	return &cfg
}

// TestHumanFederatedDeviceFlow_RealIdP #2 human federated 真实 IdP 集成入口。
//
// 两段式:
//  1. 自动段(无配置则 skip,有配置则跑):用真实 IdP 配置构造 HumanFederatedOidcTokenProvider。
//     构造内部会跑 sanitizeCacheSegment + base-dir 包含校验(对真实 instanceId/clientId),
//     但 localHumanCachePath 是未导出字段,跨包无法断言其值——这部分由包内
//     TestBoundary_HumanProvider_FullFlow_MaliciousInstanceId 覆盖。这里构造仅为让真实配置
//     过一遍构造函数,确保不 panic、GetClientId 等可访问字段正常。
//  2. 阻塞段(需 IDAAS_IT_HUMAN_FLOW=on):调 GetCredentialWithContext 走完整 device flow,
//     期间测试者须在浏览器里扫码完成授权(MaxWaitInterval=180s);成功后断言 token 返回
//     + 缓存目录(~/.cloud_idaas/human-cache/)下有 .json 缓存文件写入。
//     这一段是真正端到端的人工集成验证,CI 永不跑(env 未设)。
//
// 设计理由:device flow 必须人工交互,无法 CI 自动化;但保留这个入口让有真实 human IdP 环境
// 的同学可以一键跑通端到端(含 sanitize/cache/HTTP/轮询/缓存写入全链路),而不是只能跑 mock。
func TestHumanFederatedDeviceFlow_RealIdP(t *testing.T) {
	skipIfIntegrationDisabled(t)
	cfg := loadHumanFederatedConfig(t)

	// 用真实 IdP 配置构造——构造内部会跑 sanitizeCacheSegment + base-dir 包含校验
	// 超时单位是毫秒（NewDefaultHttpClient(connectTimeoutMs, readTimeoutMs)）；
	// device flow 含人工授权等待，给 30s 连接/读超时。
	httpClient := idhttp.NewDefaultHttpClient(30000, 30000)
	p := authentication.NewHumanFederatedOidcTokenProvider(
		cfg.InstanceId,
		cfg.ClientId,
		cfg.TokenEndpoint,
		cfg.DeviceAuthorizationEndpoint,
		enums.StaleValueBehaviorRefresh,
		"", // scope: 空 → DefaultScope
		httpClient,
	)
	t.Logf("构造完成 clientId=%s tokenEndpoint=%s", p.GetClientId(), p.GetTokenEndpoint())

	// 阻塞段:opt-in,需要人工扫码。
	if strings.ToLower(os.Getenv("IDAAS_IT_HUMAN_FLOW")) != "on" {
		t.Skip("跳过阻塞 device flow:需 IDAAS_IT_HUMAN_FLOW=on 且测试期间人工扫码完成授权(端到端人工验证入口);构造+sanitize 已由包内 boundary 测试覆盖")
	}

	// 真实端到端:200s 内须人工扫码;超时则失败。
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()
	cred, err := p.GetCredentialWithContext(ctx)
	if err != nil {
		t.Fatalf("device flow 失败(是否在 200s 内扫码?): %v", err)
	}
	if cred.GetAccessToken() == "" {
		t.Fatal("AccessToken 为空")
	}
	t.Logf("✅ human device flow 端到端成功 token=%s...", preview(cred.GetAccessToken()))

	// 缓存目录下应有 .json 缓存文件写入(localHumanCachePath 未导出,改走目录列举)。
	homeDir, hdErr := os.UserHomeDir()
	if hdErr != nil {
		homeDir = "."
	}
	cacheDir := filepath.Join(homeDir, ".cloud_idaas", "human-cache")
	entries, lErr := os.ReadDir(cacheDir)
	if lErr != nil {
		t.Errorf("缓存目录应已创建并可读: %v (dir=%q)", lErr, cacheDir)
	} else {
		jsonCount := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") && !e.IsDir() {
				jsonCount++
			}
		}
		if jsonCount == 0 {
			t.Errorf("缓存目录 %q 下应至少有一个 .json 缓存文件,实际 %d", cacheDir, jsonCount)
		}
	}
}
