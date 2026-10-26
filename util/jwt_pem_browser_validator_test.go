package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// ---------------------------------------------------------------------------
// JWT util tests
// ---------------------------------------------------------------------------

func TestBuildJwtClaims(t *testing.T) {
	issuer := "test-issuer"
	subject := "test-subject"
	audience := "test-audience"
	expiresIn := 3600 * time.Second

	claims := BuildJwtClaims(issuer, subject, audience, expiresIn)

	if claims["iss"] != issuer {
		t.Errorf("expected iss=%s, got %v", issuer, claims["iss"])
	}
	if claims["sub"] != subject {
		t.Errorf("expected sub=%s, got %v", subject, claims["sub"])
	}
	if claims["aud"] != audience {
		t.Errorf("expected aud=%s, got %v", audience, claims["aud"])
	}

	exp, ok := claims["exp"].(int64)
	if !ok {
		t.Fatalf("exp is not int64: %T", claims["exp"])
	}
	now := time.Now()
	if exp < now.Unix() {
		t.Errorf("exp should be in the future, got %d (now=%d)", exp, now.Unix())
	}
	expectedExp := now.Add(expiresIn).Unix()
	// Allow 2-second drift for test execution time
	if exp < expectedExp-2 || exp > expectedExp+2 {
		t.Errorf("exp should be ~%d, got %d", expectedExp, exp)
	}

	iat, ok := claims["iat"].(int64)
	if !ok {
		t.Fatalf("iat is not int64: %T", claims["iat"])
	}
	if iat < now.Unix()-5 || iat > now.Unix()+5 {
		t.Errorf("iat should be close to now, got %d (now=%d)", iat, now.Unix())
	}

	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		t.Error("jti should be a non-empty string")
	}

	// Two calls should produce different jti values
	claims2 := BuildJwtClaims(issuer, subject, audience, expiresIn)
	if claims2["jti"] == jti {
		t.Error("jti should be unique per call")
	}
}

func TestSignJwtHS256(t *testing.T) {
	claims := BuildJwtClaims("iss", "sub", "aud", 3600*time.Second)
	// SignJwtHS256 用毕即 ClearBytes(secret),故验签须用独立副本,
	// 不能复用入参切片(签名返回后已被清零)。
	secret := []byte("test-secret-key")
	verifyKey := append([]byte(nil), secret...)

	tokenStr, err := SignJwtHS256(claims, secret)
	if err != nil {
		t.Fatalf("SignJwtHS256 failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("token string is empty")
	}

	// 入参 secret 应已被清零(契约)
	for i, b := range secret {
		if b != 0 {
			t.Errorf("secret[%d]=%d, want 0 (cleared after sign)", i, b)
		}
	}

	// Parse and verify the token(用独立副本验签)
	parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return verifyKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !parsedToken.Valid {
		t.Fatal("token is not valid")
	}

	parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to cast claims to MapClaims")
	}
	if parsedClaims["iss"] != "iss" {
		t.Errorf("expected iss=iss, got %v", parsedClaims["iss"])
	}
}

func TestSignJwtHS256_EmptySecret(t *testing.T) {
	claims := jwt.MapClaims{"iss": "test"}
	tokenStr, err := SignJwtHS256(claims, []byte(""))
	// An empty secret is still valid for HS256 (it's a valid HMAC key)
	if err != nil {
		t.Fatalf("SignJwtHS256 with empty secret should not error: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("token string should not be empty")
	}
}

func TestSignJwtRS256(t *testing.T) {
	privKey := generateTestRSAKey(t, 2048)

	claims := BuildJwtClaims("iss", "sub", "aud", 3600*time.Second)
	tokenStr, err := SignJwtRS256(claims, privKey)
	if err != nil {
		t.Fatalf("SignJwtRS256 failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("token string is empty")
	}

	// Parse and verify
	parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return &privKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !parsedToken.Valid {
		t.Fatal("token is not valid")
	}
}

func TestSignJwtES256(t *testing.T) {
	privKey := generateTestECDSAKey(t, elliptic.P256())

	claims := BuildJwtClaims("iss", "sub", "aud", 3600*time.Second)
	tokenStr, err := SignJwtES256(claims, privKey)
	if err != nil {
		t.Fatalf("SignJwtES256 failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("token string is empty")
	}

	// Parse and verify
	parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return &privKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !parsedToken.Valid {
		t.Fatal("token is not valid")
	}
}

// ---------------------------------------------------------------------------
// PEM util tests
// ---------------------------------------------------------------------------

func TestLoadPrivateKeyMaterial_EmptyString(t *testing.T) {
	_, err := LoadPrivateKeyMaterial("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty, got: %s", err.Error())
	}

	// Whitespace-only
	_, err = LoadPrivateKeyMaterial("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only string")
	}
}

func TestLoadPrivateKeyMaterial_PEMText(t *testing.T) {
	privKey := generateTestRSAKey(t, 2048)
	pemData := encodeRSAKeyPKCS8PEM(t, privKey)

	// Direct PEM text — LoadPrivateKeyMaterial trims whitespace, so compare trimmed
	result, err := LoadPrivateKeyMaterial(string(pemData))
	if err != nil {
		t.Fatalf("LoadPrivateKeyMaterial failed for PEM text: %v", err)
	}
	if string(result) != strings.TrimSpace(string(pemData)) {
		t.Errorf("result does not match trimmed input PEM")
	}
}

func TestLoadPrivateKeyMaterial_PEMTextWithLiteralNewlines(t *testing.T) {
	privKey := generateTestRSAKey(t, 2048)
	pemData := encodeRSAKeyPKCS8PEM(t, privKey)

	// Replace real newlines with literal \n to simulate shell/json escaping
	literalStr := strings.ReplaceAll(string(pemData), "\n", `\n`)
	result, err := LoadPrivateKeyMaterial(literalStr)
	if err != nil {
		t.Fatalf("LoadPrivateKeyMaterial failed for literal \\n PEM: %v", err)
	}
	// Should have converted \n back to real newlines
	if !strings.Contains(string(result), "-----BEGIN") {
		t.Errorf("result should contain PEM header")
	}
	// Verify it can be parsed as a key
	_, err = ParsePrivateKeyFromPEM(result)
	if err != nil {
		t.Errorf("ParsePrivateKeyFromPEM failed on fixed PEM: %v", err)
	}
}

func TestLoadPrivateKeyMaterial_FilePath(t *testing.T) {
	privKey := generateTestRSAKey(t, 2048)
	pemData := encodeRSAKeyPKCS8PEM(t, privKey)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(tmpFile, pemData, 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	result, err := LoadPrivateKeyMaterial(tmpFile)
	if err != nil {
		t.Fatalf("LoadPrivateKeyMaterial failed for file path: %v", err)
	}
	if !bytes.Equal(result, pemData) {
		t.Errorf("result does not match file content")
	}
}

func TestLoadPrivateKeyMaterial_TildeFilePath(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	privKey := generateTestRSAKey(t, 2048)
	pemData := encodeRSAKeyPKCS8PEM(t, privKey)

	tmpFile := filepath.Join(homeDir, "mykey.pem")
	if err := os.WriteFile(tmpFile, pemData, 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	result, err := LoadPrivateKeyMaterial("~/mykey.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKeyMaterial failed for tilde path: %v", err)
	}
	if !bytes.Equal(result, pemData) {
		t.Errorf("result does not match file content")
	}
}

func TestLoadPrivateKeyMaterial_InvalidInput(t *testing.T) {
	// Not PEM, not a file path
	_, err := LoadPrivateKeyMaterial("not-a-pem-not-a-file-path-12345")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
	if !strings.Contains(err.Error(), "neither") {
		t.Errorf("error should mention 'neither', got: %s", err.Error())
	}
}

func TestLoadPrivateKeyMaterial_DirectoryAsPath(t *testing.T) {
	// Passing a directory path: file "exists" but can't be read as a file
	// This triggers the !os.IsNotExist(err) branch
	tmpDir := t.TempDir()
	_, err := LoadPrivateKeyMaterial(tmpDir)
	if err == nil {
		t.Fatal("expected error for directory path")
	}
	if !strings.Contains(err.Error(), "failed to read") {
		t.Errorf("error should mention 'failed to read', got: %s", err.Error())
	}
}

func TestParsePrivateKeyFromPEM_PKCS8RSA(t *testing.T) {
	privKey := generateTestRSAKey(t, 2048)
	pemData := encodeRSAKeyPKCS8PEM(t, privKey)

	parsed, err := ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM failed for PKCS8 RSA: %v", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit RSA key, got %d", rsaKey.N.BitLen())
	}
}

func TestParsePrivateKeyFromPEM_PKCS1RSA(t *testing.T) {
	privKey := generateTestRSAKey(t, 2048)
	pemData := encodeRSAKeyPKCS1PEM(t, privKey)

	parsed, err := ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM failed for PKCS1 RSA: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyFromPEM_EC(t *testing.T) {
	privKey := generateTestECDSAKey(t, elliptic.P256())
	pemData := encodeECDSAKeyPEM(t, privKey)

	parsed, err := ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM failed for EC key: %v", err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Error("expected P256 curve")
	}
}

func TestParsePrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	// Not PEM at all
	_, err := ParsePrivateKeyFromPEM([]byte("not a pem block at all"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM") {
		t.Errorf("error should mention PEM decode failure, got: %s", err.Error())
	}
}

func TestParsePrivateKeyFromPEM_UnsupportedFormat(t *testing.T) {
	// Create a PEM block with garbage data
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage data that is not a key")}
	pemData := pem.EncodeToMemory(block)

	_, err := ParsePrivateKeyFromPEM(pemData)
	if err == nil {
		t.Fatal("expected error for unsupported key format")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error should mention 'unsupported', got: %s", err.Error())
	}
}

func TestGetKeyType(t *testing.T) {
	rsaKey := generateTestRSAKey(t, 2048)
	if got := GetKeyType(rsaKey); got != "RSA" {
		t.Errorf("GetKeyType(rsa) = %s, want RSA", got)
	}

	ecKey := generateTestECDSAKey(t, elliptic.P256())
	if got := GetKeyType(ecKey); got != "EC" {
		t.Errorf("GetKeyType(ec) = %s, want EC", got)
	}

	if got := GetKeyType("random"); got != "Unknown" {
		t.Errorf("GetKeyType(unknown) = %s, want Unknown", got)
	}
}

// ---------------------------------------------------------------------------
// Browser util tests
// ---------------------------------------------------------------------------

func TestOpenBrowser(t *testing.T) {
	// OpenBrowser is platform-dependent. On linux it uses xdg-open.
	// In test environments xdg-open typically doesn't exist, so we expect
	// either nil (if it exists) or an error. We just verify it doesn't panic
	// and returns the expected types.
	url := "http://localhost/test"
	err := OpenBrowser(url)

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		// On supported platforms, either nil or error is acceptable.
		// 安全约束:失败时 error 不得含完整 URL(真实场景下 url 是 IdP 返回的
		// verification_uri_complete,带一次性 user_code;宿主可能把 error 写进
		// 日志绕过 RedactKV)。只保留 scheme://host 用于排障。
		if err != nil {
			if !strings.Contains(err.Error(), "http://localhost") {
				t.Errorf("error should mention scheme+host http://localhost, got: %s", err.Error())
			}
			if strings.Contains(err.Error(), "/test") {
				t.Errorf("error must not contain URL path/query (leaks user_code), got: %s", err.Error())
			}
		}
	}
	// On unsupported platforms, err is nil (silent ignore)
}

// TestOpenBrowser_NoUserCodeLeak 回归:verification_uri_complete 中的 user_code
// 不得出现在失败 error 或 stdlib log 输出里(会绕过 RedactKV 被 central collector
// 或本机其他用户读到,抢在合法用户前完成 device 授权)。
func TestOpenBrowser_NoUserCodeLeak(t *testing.T) {
	// 捕获 stdlib log 输出(OpenBrowser 在 cmd.Start 失败时打 [DEBUG] 行)。
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	// 真实 IdP 返回形态:https://device.example.com/device?user_code=SECRET-CODE-1234
	leakyURL := "https://device.example.com/device?user_code=SECRET-CODE-1234"
	err := OpenBrowser(leakyURL)

	// error 不得含 user_code 值
	if err != nil && strings.Contains(err.Error(), "SECRET-CODE-1234") {
		t.Errorf("error leaked user_code: %s", err.Error())
	}
	// stdlib log 不得含 user_code 值
	if strings.Contains(logBuf.String(), "SECRET-CODE-1234") {
		t.Errorf("stdlib log leaked user_code: %s", logBuf.String())
	}
	// 仍应含 scheme+host 便于排障
	if err != nil && !strings.Contains(err.Error(), "device.example.com") {
		t.Errorf("error should mention host device.example.com, got: %s", err.Error())
	}
}

// --- OpenBrowser 边界场景 ---
//
// 这组覆盖 OpenBrowser 入口的拒绝路径:危险 scheme、空 URL、不可解析 URL。
// 共同断言:失败 error 不得含完整 rawURL(真实场景 rawURL 带一次性 user_code,
// 进 error 字符串会绕过 RedactKV 的 "error" key 被 central collector 读到)。

// TestOpenBrowser_DisallowedSchemes 断言非 http/https scheme 被拒绝,
// 且 error 只含 scheme 名本身,不含 URL 的 path/query(那里藏着 user_code)。
func TestOpenBrowser_DisallowedSchemes(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		scheme string // 期望 error 中出现的 scheme 名
		leaky  string // 期望 error 中不出现的敏感片段
	}{
		{
			name:   "file scheme 读本地文件",
			url:    "file:///etc/passwd",
			scheme: "file",
			leaky:  "/etc/passwd",
		},
		{
			name:   "javascript scheme 执行脚本",
			url:    "javascript:alert(1)",
			scheme: "javascript",
			leaky:  "alert(1)",
		},
		{
			name:   "ftp scheme",
			url:    "ftp://device.example.com/device?user_code=SECRET-FTP",
			scheme: "ftp",
			leaky:  "SECRET-FTP",
		},
		{
			name:   "data scheme",
			url:    "data:text/html,<script>steal()</script>",
			scheme: "data",
			leaky:  "steal()",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := OpenBrowser(tt.url)
			if err == nil {
				t.Fatal("危险 scheme 应被拒绝并返回 error")
			}
			errStr := err.Error()
			if !strings.Contains(errStr, "unsupported scheme") {
				t.Errorf("error 应说明 unsupported scheme: %s", errStr)
			}
			if !strings.Contains(errStr, tt.scheme) {
				t.Errorf("error 应含 scheme 名 %q: %s", tt.scheme, errStr)
			}
			// path/query 中的敏感片段不得泄漏
			if tt.leaky != "" && strings.Contains(errStr, tt.leaky) {
				t.Errorf("error 泄漏 URL 敏感片段 %q: %s", tt.leaky, errStr)
			}
		})
	}
}

// TestOpenBrowser_EmptyURL 空串 URL 必须直接拒绝,不得交给 shell 造成歧义。
func TestOpenBrowser_EmptyURL(t *testing.T) {
	err := OpenBrowser("")
	if err == nil {
		t.Fatal("空 URL 应返回 error")
	}
	if !strings.Contains(err.Error(), "empty url") {
		t.Errorf("error 应说明 empty url: %s", err.Error())
	}
}

// TestOpenBrowser_InvalidURL 不可解析 URL(含控制字符)必须返回 error,
// 且 error 不得泄漏完整 rawURL(其中 query 含 user_code)。
func TestOpenBrowser_InvalidURL(t *testing.T) {
	// 0x7f 控制字符让 url.Parse 失败;query 段塞一个伪 user_code 验证不泄漏
	leakyURL := "https://device.example.com/device?user_code=SECRET-INVALID\x7f"
	err := OpenBrowser(leakyURL)
	if err == nil {
		t.Fatal("不可解析 URL 应返回 error")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "invalid url") {
		t.Errorf("error 应说明 invalid url: %s", errStr)
	}
	if strings.Contains(errStr, "SECRET-INVALID") {
		t.Errorf("error 泄漏 user_code: %s", errStr)
	}
	if strings.Contains(errStr, "/device?user_code=") {
		t.Errorf("error 泄漏完整 path+query: %s", errStr)
	}
}

// TestOpenBrowser_HostOnlyNoUserCode 断言:URL 只有 scheme+host、无 path/query
// 时,即便 cmd.Start 失败,error 也只含 scheme+host(无 path 可剥离时与输入一致,
// 但不应额外构造出敏感内容)。这是一次 user_code 场景的对照基线。
func TestOpenBrowser_HostOnlyNoUserCode(t *testing.T) {
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	// 只有 scheme+host,没有 path/query——无 user_code 可泄漏
	hostOnly := "https://device.example.com"
	err := OpenBrowser(hostOnly)
	if err != nil {
		// error 含 scheme+host 是允许的(host 本身不敏感)
		if !strings.Contains(err.Error(), "device.example.com") {
			t.Errorf("error 应含 host: %s", err.Error())
		}
	}
	// log 不得额外构造 path
	if strings.Contains(logBuf.String(), "/device") {
		t.Errorf("log 不应含未提供的 path: %s", logBuf.String())
	}
}

// ---------------------------------------------------------------------------
// Validator util tests
// ---------------------------------------------------------------------------

func TestValidateLocalToken(t *testing.T) {
	// Valid token
	err := ValidateLocalToken("some-token-value")
	if err != nil {
		t.Errorf("expected no error for non-empty token, got: %v", err)
	}

	// Empty token
	err = ValidateLocalToken("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention 'empty', got: %s", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Helper functions for key generation and PEM encoding
// ---------------------------------------------------------------------------

func generateTestRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func generateTestECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return key
}

func encodeRSAKeyPKCS8PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func encodeRSAKeyPKCS1PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func encodeECDSAKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
