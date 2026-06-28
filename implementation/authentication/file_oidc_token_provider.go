package authentication

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/util"
)

// FileOidcTokenProvider 文件型 OIDC Token 提供者
//
// 与阿里云 Java SDK FileOidcTokenProvider 对齐：
//  1. 从指定文件路径读取 OIDC token（典型场景为 K8s Service Account Token）
//  2. 通过 JWT payload 解析 exp 字段，缓存 token；距离过期 10 分钟内主动重新读取文件
//  3. 适用场景：authnMethod = OIDC、clientDeployEnvironment = KUBERNETES
type FileOidcTokenProvider struct {
	tokenPath string

	mu          sync.Mutex
	cachedToken string
	expiresAt   int64 // unix 秒
}

// NewFileOidcTokenProvider 创建 FileOidcTokenProvider
//
// tokenPath 为空时使用 K8s 默认 SA Token 路径 /var/run/secrets/kubernetes.io/serviceaccount/token
func NewFileOidcTokenProvider(tokenPath string) *FileOidcTokenProvider {
	if tokenPath == "" {
		tokenPath = constants.K8sServiceAccountTokenPath
	}
	return &FileOidcTokenProvider{
		tokenPath: tokenPath,
	}
}

// GetOidcToken 获取 OIDC Token（带轻量缓存，过期前 10 分钟刷新）
func (p *FileOidcTokenProvider) GetOidcToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cachedToken != "" && !p.willSoonExpire() {
		return p.cachedToken, nil
	}

	data, err := util.ReadFile(p.tokenPath)
	if err != nil {
		return "", errors.NewCredentialError(
			"OidcTokenFileReadFailed",
			fmt.Sprintf("Failed to read OIDC token file %s: %s", p.tokenPath, err.Error()),
			err,
		)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.NewCredentialError(
			"OidcTokenFileEmpty",
			fmt.Sprintf("OIDC token file %s is empty", p.tokenPath),
			nil,
		)
	}

	exp, err := parseJwtExpiration(token)
	if err != nil {
		// JWT 解析失败不阻断使用：缓存 token 但禁用 exp 缓存策略（每次都重新读文件）
		p.cachedToken = token
		p.expiresAt = 0
		return token, nil
	}

	p.cachedToken = token
	p.expiresAt = exp
	return token, nil
}

// TokenPath 返回当前 OIDC token 文件路径
func (p *FileOidcTokenProvider) TokenPath() string {
	return p.tokenPath
}

// willSoonExpire 判断 token 是否即将在 10 分钟内过期（与 Java SDK 行为一致）
func (p *FileOidcTokenProvider) willSoonExpire() bool {
	if p.expiresAt <= 0 {
		// 未解析出 exp 时视为始终需要刷新（保守策略）
		return true
	}
	now := time.Now().Unix()
	return (p.expiresAt - now) < int64(10*time.Minute/time.Second)
}

// parseJwtExpiration 从 JWT payload 中解析 exp（unix 秒）
// 不做签名校验，仅解析 payload 中的 "exp" 字段
func parseJwtExpiration(jwtToken string) (int64, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid JWT format: expected 3 segments, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// 兼容部分实现用标准 base64（含 padding）
		payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return 0, fmt.Errorf("failed to base64-decode JWT payload: %w", err)
		}
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return 0, fmt.Errorf("failed to unmarshal JWT payload JSON: %w", err)
	}
	switch v := claims["exp"].(type) {
	case float64:
		return int64(v), nil
	case int64:
		return v, nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("invalid exp number: %w", err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("exp claim missing or not a number")
	}
}
