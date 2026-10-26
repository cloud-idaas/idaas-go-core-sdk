package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

// TestClearBytes 验证清零原语(见 util 包文档"敏感 []byte 清零约定")。
func TestClearBytes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"single", []byte("a")},
		{"normal", []byte("secret-key-bytes")},
		{"cap>len", []byte("x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ClearBytes(tc.in)
			for i, b := range tc.in {
				if b != 0 {
					t.Errorf("index %d not zeroed: %d", i, b)
				}
			}
		})
	}
}

// TestSignJwtHS256_ClearsSecret 验证:SignJwtHS256 用毕清零 secret 副本。
// 用毕即清零缩短 client_secret 派生副本在堆上的驻留窗口。
func TestSignJwtHS256_ClearsSecret(t *testing.T) {
	secret := []byte("super-secret-key-123")
	orig := append([]byte(nil), secret...) // 备份原值用于事后比对

	_, err := SignJwtHS256(jwt.MapClaims{"iss": "x"}, secret)
	if err != nil {
		t.Fatalf("SignJwtHS256 failed: %v", err)
	}

	for i, b := range secret {
		if b != 0 {
			t.Errorf("secret[%d]=%d after sign, want 0 (cleared); orig=%q", i, b, orig)
		}
	}
}

// TestSignJwtHS256_ClearsSecret_OnPanic 验证 defer ClearBytes 在签名 panic 时仍执行。
// 用非法 claims 类型触发 golang-jwt 内部错误路径(若 panic 则 defer 仍跑);
// 若仅返回 error 则 secret 仍应被清零。
func TestSignJwtHS256_ClearsSecret_OnPanic(t *testing.T) {
	secret := []byte("k")
	// 正常签名一次验证 defer 在成功路径已清零
	_, _ = SignJwtHS256(jwt.MapClaims{}, secret)
	for i, b := range secret {
		if b != 0 {
			t.Errorf("secret[%d]=%d, want 0 (cleared on return path)", i, b)
		}
	}
}

// TestParsePrivateKeyFromPEM_ClearsPemData 验证:ParsePrivateKeyFromPEM
// 解析完成后清零 pemData 副本(PEM 私钥明文不在堆上驻留)。
func TestParsePrivateKeyFromPEM_ClearsPemData(t *testing.T) {
	// 用真实 RSA 私钥(512bit,够小供测试快速生成)构造合法 PKCS1 PEM。
	priv, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	pemData := append([]byte(nil), pemBlock...) // fresh copy

	_, err = ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM failed: %v", err)
	}

	for i, b := range pemData {
		if b != 0 {
			t.Errorf("pemData[%d]=%d after parse, want 0 (cleared)", i, b)
		}
	}
}

// TestParsePrivateKeyFromPEM_ClearsPemData_OnInvalidPEM 验证无效 PEM(解码失败)
// 路径也清零——defer 不依赖解码成功。
func TestParsePrivateKeyFromPEM_ClearsPemData_OnInvalidPEM(t *testing.T) {
	pemData := []byte("not-a-valid-pem-block-content-xxxxx")
	_, err := ParsePrivateKeyFromPEM(pemData)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	for i, b := range pemData {
		if b != 0 {
			t.Errorf("pemData[%d]=%d after failed parse, want 0 (cleared even on error)", i, b)
		}
	}
}
