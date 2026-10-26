package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// DefaultClientAssertionTTL 是客户端 JWT 断言(client_assertion)的默认有效期。
//
// 取值 600s(10min),与同源的 Python SDK 保持一致。
// 5min(300s) 在客户端/服务端时钟漂移较大的部署下容易让断言还未送达就被判过期,
// 600s 给签名/网络/服务端校验留出更宽裕的窗口;Token 本身的有效期远大于断言,
// 缩短断言寿命不会因此提升安全性,因此对齐到兄弟 SDK 的更宽口径。
const DefaultClientAssertionTTL = 600 * time.Second

// BuildJwtClaims 构建 JWT claims
func BuildJwtClaims(issuer, subject, audience string, expiresIn time.Duration) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"exp": now.Add(expiresIn).Unix(),
		"iat": now.Unix(),
		"jti": uuid.New().String(),
	}
}

// SignJwtHS256 使用 HS256 签名 JWT。
//
// secret 是 HMAC 密钥副本(通常由调用方 `[]byte(clientSecret)` 派生)。
// 签名完成后立即 ClearBytes 清零该副本,缩短敏感明文在堆上的驻留窗口
// (golang-jwt 的 hmac.New 内部已拷贝 key,签名返回后 secret 切片不再被引用)。
// 源 string 仍待 GC(见 util 包文档"敏感 []byte 清零约定")。
func SignJwtHS256(claims jwt.MapClaims, secret []byte) (string, error) {
	defer ClearBytes(secret) // 用毕即清,无论签名成功或 panic
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// SignJwtRS256 使用 RS256 签名 JWT
func SignJwtRS256(claims jwt.MapClaims, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// SignJwtES256 使用 ES256 签名 JWT
func SignJwtES256(claims jwt.MapClaims, privateKey *ecdsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(privateKey)
}
