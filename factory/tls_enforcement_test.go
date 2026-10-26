package factory

import (
	"context"
	stderrors "errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
)

// recordingLogger 记录所有日志调用(线程安全),用于断言 Initialize 期的
// 安全降级 WARN 是否经注入的 logger 走(而非 logger.Default 刷屏)。
type recordingLogger struct {
	mu     sync.Mutex
	warns  []string
	infos  []string
	errors []string
	debugs []string
}

func (r *recordingLogger) Debug(ctx context.Context, msg string, kv ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.debugs = append(r.debugs, msg)
}
func (r *recordingLogger) Info(ctx context.Context, msg string, kv ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.infos = append(r.infos, msg)
}
func (r *recordingLogger) Warn(ctx context.Context, msg string, kv ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warns = append(r.warns, msg)
}
func (r *recordingLogger) Error(ctx context.Context, msg string, kv ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, msg)
}

func (r *recordingLogger) warnCount(sub string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := 0
	for _, w := range r.warns {
		if strings.Contains(w, sub) {
			c++
		}
	}
	return c
}

// TestInitialize_UnsafeIgnoreSSLCert_LogsWarn 验证:Initialize
// 检测 unsafeIgnoreSslCert=true 时经注入的 logger(Warn)记一条 security_downgrade
// WARN;且 WARN 在每次真正 Initialize 仅一次(幂等 init 不重复记)。
func TestInitialize_UnsafeIgnoreSSLCert_LogsWarn(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	cfg.HttpConfiguration = &config.HttpConfiguration{
		ConnectTimeout:      5000,
		ReadTimeout:         10000,
		UnsafeIgnoreSSLCert: true,
	}

	rec := &recordingLogger{}
	f := GetInstance().WithLogger(rec)

	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize should succeed (no enforcement), got: %v", err)
	}
	if c := rec.warnCount("TLS certificate verification is DISABLED"); c != 1 {
		t.Errorf("expected exactly 1 unsafeIgnoreSslCert WARN, got %d", c)
	}

	// 幂等 init 不重复记 WARN。
	_ = f.Initialize(cfg)
	if c := rec.warnCount("TLS certificate verification is DISABLED"); c != 1 {
		t.Errorf("idempotent re-init must not re-log WARN; got %d total", c)
	}
}

// TestInitialize_WithTLSEnforcement_RejectsInsecure 验证:启用
// WithTLSEnforcement() 后,unsafeIgnoreSslCert=true 被硬拒(InsecureTLSDisallowed),
// httpClient 不构造、factory 不进入 initialized。
func TestInitialize_WithTLSEnforcement_RejectsInsecure(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	cfg.HttpConfiguration = &config.HttpConfiguration{
		ConnectTimeout:      5000,
		ReadTimeout:         10000,
		UnsafeIgnoreSSLCert: true,
	}

	f := GetInstance().WithTLSEnforcement()
	err := f.Initialize(cfg)
	if err == nil {
		t.Fatal("expected InsecureTLSDisallowed error, got nil")
	}
	var ce interface{ ErrorCode() string }
	if !stderrors.As(err, &ce) || ce.ErrorCode() != constants.InsecureTLSDisallowed {
		t.Errorf("error code = %v, want %s", err, constants.InsecureTLSDisallowed)
	}
	if f.IsInitialized() {
		t.Error("factory must NOT be initialized after TLS enforcement rejection")
	}
}

// TestInitialize_WithTLSEnforcement_AllowsSecure 验证 WithTLSEnforcement 默认
// 不误伤正常(unsafeIgnoreSslCert=false/未设)配置:零回归。
func TestInitialize_WithTLSEnforcement_AllowsSecure(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	cfg := validTestConfig()
	cfg.HttpConfiguration = &config.HttpConfiguration{
		ConnectTimeout: 5000,
		ReadTimeout:    10000,
		// UnsafeIgnoreSSLCert 默认 false
	}

	f := GetInstance().WithTLSEnforcement()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("enforcement mode must allow secure config, got: %v", err)
	}
	if !f.IsInitialized() {
		t.Error("factory should be initialized with secure config under enforcement")
	}
}

// TestUnsafeIgnoreSSLCert_NotReadFromEnv 验证:UnsafeIgnoreSSLCert
// 仅由配置 JSON 赋值,无 env var 读取路径(防生产被 env 静默降级关闭 TLS)。
// 设与不设任意 env,Initialize 不据此翻转 UnsafeIgnoreSSLCert:仅看 cfg 字段。
func TestUnsafeIgnoreSSLCert_NotReadFromEnv(t *testing.T) {
	Reset()
	defer Reset()

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")
	defer os.Unsetenv("CLOUD_IDAAS_CLIENT_SECRET")

	// 尝试用各种"可能"的 env 名诱导 SDK 读 env 关 TLS;均应无效。
	for _, ev := range []string{
		"IDAAS_UNSAFE_IGNORE_SSL_CERT",
		"CLOUD_IDAAS_UNSAFE_IGNORE_SSL_CERT",
		"UNSAFE_IGNORE_SSL_CERT",
		"IDAAS_UNSAFE_IGNORE_SSLCERT",
	} {
		t.Setenv(ev, "true") // 自动在用例结束时恢复,替代循环内 defer(避免堆积)
	}

	cfg := validTestConfig()
	cfg.HttpConfiguration = &config.HttpConfiguration{
		ConnectTimeout: 5000,
		ReadTimeout:    10000,
		// 字段未设(false);env 即便设了 true 也不应生效。
	}

	rec := &recordingLogger{}
	f := GetInstance().WithLogger(rec)
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if c := rec.warnCount("TLS certificate verification is DISABLED"); c != 0 {
		t.Errorf("UnsafeIgnoreSSLCert must not be read from env; got %d TLS-disable WARN(s)", c)
	}
}
