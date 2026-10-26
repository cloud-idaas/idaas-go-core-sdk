package authentication

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

// makeFakeJwtForFile builds a JWT with the given exp (unix seconds).
func makeFakeJwtForFile(exp int64) string {
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := fmt.Sprintf(`{"exp":%d,"iss":"test-issuer"}`, exp)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return headerB64 + "." + payloadB64 + "." + signature
}

func TestNewFileOidcTokenProvider_WithPath(t *testing.T) {
	p := NewFileOidcTokenProvider("/custom/path/token")
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.tokenPath != "/custom/path/token" {
		t.Errorf("expected '/custom/path/token', got '%s'", p.tokenPath)
	}
}

func TestNewFileOidcTokenProvider_EmptyPath(t *testing.T) {
	p := NewFileOidcTokenProvider("")
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.tokenPath == "" {
		t.Error("expected default path for empty input")
	}
}

func TestFileOidcTokenProvider_TokenPath(t *testing.T) {
	p := NewFileOidcTokenProvider("/some/token/path")
	if p.TokenPath() != "/some/token/path" {
		t.Errorf("expected '/some/token/path', got '%s'", p.TokenPath())
	}
}

func TestFileOidcTokenProvider_GetOidcToken_Success(t *testing.T) {
	// Build a JWT with future expiration
	exp := time.Now().Add(1 * time.Hour).Unix()
	jwt := makeFakeJwtForFile(exp)

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenFile, []byte(jwt), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	p := NewFileOidcTokenProvider(tokenFile)
	token, err := p.GetOidcToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != jwt {
		t.Errorf("expected token to match file content")
	}
}

func TestFileOidcTokenProvider_GetOidcToken_Cache(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	jwt := makeFakeJwtForFile(exp)

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenFile, []byte(jwt), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	p := NewFileOidcTokenProvider(tokenFile)

	// First call reads from file
	token1, err := p.GetOidcToken()
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if token1 != jwt {
		t.Error("first call token mismatch")
	}

	// Delete the file - second call should use cache
	os.Remove(tokenFile)

	token2, err := p.GetOidcToken()
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if token2 != jwt {
		t.Error("second call should return cached token")
	}
}

func TestFileOidcTokenProvider_GetOidcToken_FileNotFound(t *testing.T) {
	p := NewFileOidcTokenProvider("/nonexistent/path/token")
	_, err := p.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestFileOidcTokenProvider_GetOidcToken_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "empty-token")
	if err := os.WriteFile(tokenFile, []byte("   "), 0o600); err != nil {
		t.Fatalf("failed to write empty token file: %v", err)
	}

	p := NewFileOidcTokenProvider(tokenFile)
	_, err := p.GetOidcToken()
	if err == nil {
		t.Fatal("expected error for empty token file")
	}
}

func TestFileOidcTokenProvider_GetOidcToken_InvalidJwt(t *testing.T) {
	// Write a non-JWT token to file - should still return the token
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "bad-jwt")
	if err := os.WriteFile(tokenFile, []byte("not-a-jwt-token"), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	p := NewFileOidcTokenProvider(tokenFile)
	token, err := p.GetOidcToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "not-a-jwt-token" {
		t.Errorf("expected 'not-a-jwt-token', got '%s'", token)
	}
	// The token should be cached with expiresAt=0, so next call should re-read file
	// and since willSoonExpire returns true for expiresAt=0, it'll re-read
}

func TestFileOidcTokenProvider_WillSoonExpire_Zero(t *testing.T) {
	p := &FileOidcTokenProvider{
		expiresAt: 0,
	}
	if !p.willSoonExpire() {
		t.Error("expected willSoonExpire=true for expiresAt=0")
	}
}

func TestFileOidcTokenProvider_WillSoonExpire_FarFuture(t *testing.T) {
	p := &FileOidcTokenProvider{
		expiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	if p.willSoonExpire() {
		t.Error("expected willSoonExpire=false for far future expiration")
	}
}

func TestFileOidcTokenProvider_WillSoonExpire_Soon(t *testing.T) {
	p := &FileOidcTokenProvider{
		expiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	if !p.willSoonExpire() {
		t.Error("expected willSoonExpire=true for soon expiration")
	}
}

func TestParseJwtExpiration_Success(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	jwt := makeFakeJwtForFile(exp)
	parsedExp, err := parseJwtExpiration(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Allow small drift
	if parsedExp < exp-2 || parsedExp > exp+2 {
		t.Errorf("expected ~%d, got %d", exp, parsedExp)
	}
}

func TestParseJwtExpiration_InvalidFormat(t *testing.T) {
	_, err := parseJwtExpiration("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid JWT format")
	}
}

func TestParseJwtExpiration_TwoParts(t *testing.T) {
	_, err := parseJwtExpiration("a.b")
	if err == nil {
		t.Fatal("expected error for 2-part JWT")
	}
}

func TestParseJwtExpiration_NoExp(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"test"}`))
	jwt := header + "." + payload + ".sig"
	_, err := parseJwtExpiration(jwt)
	if err == nil {
		t.Fatal("expected error for missing exp claim")
	}
}

func TestParseJwtExpiration_StandardBase64(t *testing.T) {
	// Build JWT with standard base64 (with padding)
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := fmt.Sprintf(`{"exp":%d}`, time.Now().Add(1*time.Hour).Unix())
	headerB64 := base64.URLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.URLEncoding.EncodeToString([]byte(payload))
	jwt := headerB64 + "." + payloadB64 + "." + base64.URLEncoding.EncodeToString([]byte("sig"))

	exp, err := parseJwtExpiration(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp <= 0 {
		t.Error("expected positive exp")
	}
}

func TestParseJwtExpiration_InvalidBase64(t *testing.T) {
	jwt := "header.!!!invalid-base64!!!.sig"
	_, err := parseJwtExpiration(jwt)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseJwtExpiration_InvalidJson(t *testing.T) {
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	jwt := headerB64 + "." + payloadB64 + ".sig"
	_, err := parseJwtExpiration(jwt)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- 权限校验(beta warn-only)回归 ---
//
// 凭证文件权限校验是 beta 阶段的 warn-only 纵深防御:group/other 可读时打 Warn,
// 但绝不阻断 GetOidcToken 返回 token(运维误配 0644 不应让联邦认证链路整体失败)。
// 这组测试用 capturingLogger 注入 logger.Default() 捕获 Warn 调用,断言三件事:
//  1. 0600(secure)→ 不打 Warn;
//  2. 0644(insecure)→ 打一条 Warn(status=insecure_permission,path/mode 正确),且 token 正常返回;
//  3. os.Stat 失败(悬挂符号链接)→ 不 panic,perm 校验静默跳过,流程继续(由 ReadFile 报错)。

// capturingLogger 记录 Warn/Error 调用,供权限校验回归断言。
// 不使用 t.Parallel():logger.SetDefault 是包级全局,并行测试会相互串扰;
// 同一进程内的顺序测试通过 save/restore 隔离。
type capturingLogger struct {
	mu     sync.Mutex
	warns  [][2]string // 每条 (msg, kv-flat) 用于断言
	errors [][2]string
}

func (c *capturingLogger) Debug(context.Context, string, ...interface{}) {}
func (c *capturingLogger) Info(context.Context, string, ...interface{})  {}
func (c *capturingLogger) Warn(_ context.Context, msg string, kv ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warns = append(c.warns, [2]string{msg, flattenKV(kv)})
}
func (c *capturingLogger) Error(_ context.Context, msg string, kv ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, [2]string{msg, flattenKV(kv)})
}

// flattenKV 把交替 kv 列平铺成 "k1=v1 k2=v2" 便于 Contains 断言。
func flattenKV(kv []interface{}) string {
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
func withCapturingLogger(t *testing.T) (cl *capturingLogger, restore func()) {
	t.Helper()
	orig := logger.Default()
	cl = &capturingLogger{}
	logger.SetDefault(cl)
	return cl, func() { logger.SetDefault(orig) }
}

func TestFileOidcTokenProvider_PermissionCheck_SecureNoWarn(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	jwt := makeFakeJwtForFile(exp)

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenFile, []byte(jwt), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	cl, restore := withCapturingLogger(t)
	defer restore()

	p := NewFileOidcTokenProvider(tokenFile)
	token, err := p.GetOidcToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != jwt {
		t.Errorf("token mismatch")
	}
	if len(cl.warns) != 0 {
		t.Errorf("0600 文件不应触发 Warn,实际捕获 %d 条: %+v", len(cl.warns), cl.warns)
	}
}

func TestFileOidcTokenProvider_PermissionCheck_InsecureWarns(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	jwt := makeFakeJwtForFile(exp)

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	// 0644:group/other 可读 → 触发 warn-only 权限告警
	if err := os.WriteFile(tokenFile, []byte(jwt), 0o644); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	cl, restore := withCapturingLogger(t)
	defer restore()

	p := NewFileOidcTokenProvider(tokenFile)
	token, err := p.GetOidcToken()
	// 核心 beta 契约:warn-only 不阻断——即使权限不安全也要返回 token
	if err != nil {
		t.Fatalf("warn-only 权限校验不应阻断 GetOidcToken: %v", err)
	}
	if token != jwt {
		t.Errorf("token mismatch")
	}
	if len(cl.warns) != 1 {
		t.Fatalf("0644 文件应触发恰好 1 条 Warn,实际 %d: %+v", len(cl.warns), cl.warns)
	}
	flat := cl.warns[0][1]
	if !strings.Contains(flat, "status=insecure_permission") {
		t.Errorf("Warn 缺 status=insecure_permission: %s", flat)
	}
	if !strings.Contains(flat, "path="+tokenFile) {
		t.Errorf("Warn 缺 path=%s: %s", tokenFile, flat)
	}
	if !strings.Contains(flat, "mode=-rw-r--r--") {
		t.Errorf("Warn mode 应为 0644(-rw-r--r--): %s", flat)
	}
}

// TestFileOidcTokenProvider_PermissionCheck_StatFailureNoPanic 验证 os.Stat 失败时
// perm 校验静默跳过、不 panic。悬挂符号链接 → os.Stat(跟随)返回 ENOENT,
// perm 块 `statErr == nil` 不满足直接跳过;随后 util.ReadFile 也失败,
// 返回 ReadFailed 错误。这条路径覆盖 TOCTOU(symlink swap)的 beta 行为基线。
func TestFileOidcTokenProvider_PermissionCheck_StatFailureNoPanic(t *testing.T) {
	tmpDir := t.TempDir()
	dangling := filepath.Join(tmpDir, "dangling-link")
	// 指向不存在的目标 → os.Stat 跟随后返回 ENOENT
	if err := os.Symlink(filepath.Join(tmpDir, "does-not-exist"), dangling); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	cl, restore := withCapturingLogger(t)
	defer restore()

	p := NewFileOidcTokenProvider(dangling)
	_, err := p.GetOidcToken()
	if err == nil {
		t.Fatal("expected ReadFailed error for dangling symlink")
	}
	// stat 失败不应触发 perm Warn(块被跳过)
	if len(cl.warns) != 0 {
		t.Errorf("stat 失败不应触发 Warn: %+v", cl.warns)
	}
}

// ~/ path expansion: os.Stat must use the same expanded path as util.ReadFile.
// Otherwise os.Stat uses the raw ~/token path (literal tilde), fails with ENOENT,
// and the permission check is silently skipped even if the real file is world-readable.
// This test creates a file under the home directory with 0644 permissions and uses the
// ~/ prefix path, verifying the insecure-permission Warn fires (stat hit the real file).
func TestFileOidcTokenProvider_PermissionCheck_TildePath_ExpandedForStat(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}

	exp := time.Now().Add(1 * time.Hour).Unix()
	jwt := makeFakeJwtForFile(exp)

	// Use a unique filename to avoid collisions with other tests/files.
	tokenFile := filepath.Join(homeDir, ".idaas-test-tilde-token-"+t.Name())
	// Cleanup after test.
	defer os.Remove(tokenFile)

	if err := os.WriteFile(tokenFile, []byte(jwt), 0o644); err != nil {
		t.Fatalf("failed to write token file with 0644: %v", err)
	}
	// Ensure 0644 even if umask changed it.
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatalf("failed to chmod 0644: %v", err)
	}

	cl, restore := withCapturingLogger(t)
	defer restore()

	// Use ~/ prefix path — stat must use the expanded path.
	tildePath := "~/" + filepath.Base(tokenFile)
	p := NewFileOidcTokenProvider(tildePath)
	token, err := p.GetOidcToken()
	if err != nil {
		t.Fatalf("expected token read via ~/ path, got error: %v", err)
	}
	if token != jwt {
		t.Errorf("token mismatch")
	}
	// The key assertion: stat ran against the real file (expanded ~), so the
	// insecure-permission Warn should fire for the 0644 file.
	if len(cl.warns) != 1 {
		t.Fatalf("0644 file via ~/ path should trigger exactly 1 Warn (stat must use expanded path), got %d: %+v",
			len(cl.warns), cl.warns)
	}
	flat := cl.warns[0][1]
	if !strings.Contains(flat, "status=insecure_permission") {
		t.Errorf("Warn missing status=insecure_permission: %s", flat)
	}
}
