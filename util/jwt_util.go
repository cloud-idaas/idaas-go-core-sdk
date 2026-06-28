package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// BuildJwtClaims 构建 JWT claims (§5.3)
func BuildJwtClaims(issuer string, subject string, audience string, expiresIn time.Duration) jwt.MapClaims {
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

// SignJwtHS256 使用 HS256 签名 JWT (§5.3)
func SignJwtHS256(claims jwt.MapClaims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// SignJwtRS256 使用 RS256 签名 JWT (§5.4)
func SignJwtRS256(claims jwt.MapClaims, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// SignJwtES256 使用 ES256 签名 JWT (§5.4)
func SignJwtES256(claims jwt.MapClaims, privateKey *ecdsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(privateKey)
}
