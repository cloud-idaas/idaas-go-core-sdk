package authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// FileOidcTokenProvider 文件型 OIDC Token 提供者
//
// 与阿里云 Java SDK FileOidcTokenProvider 对齐：
// 1. 从指定文件路径读取 OIDC token（典型场景为 K8s Service Account Token）
// 2. 通过 JWT payload 解析 exp 字段，缓存 token；距离过期 10 分钟内主动重新读取文件
// 3. 适用场景：authnMethod = OIDC、clientDeployEnvironment = KUBERNETES
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
	return p.GetOidcTokenWithContext(context.Background())
}

// GetOidcTokenWithContext 获取 OIDC Token,带 context。
// File OIDC 从本地文件读取,文件 IO 通常很快,不主动检查 ctx 取消;
// 但 ctx 透传到日志调用以保留 trace/request-id 关联。
func (p *FileOidcTokenProvider) GetOidcTokenWithContext(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cachedToken != "" && !p.willSoonExpire() {
		return p.cachedToken, nil
	}

	// 展开 ~/ 路径,确保 read 和 stat 使用同一个真实文件路径。
	// util.ReadFile 内部也会展开 ~/,但 os.Stat 直接使用原始路径,
	// 对 ~/token 这样的配置会导致 stat 失败而跳过权限校验,即使真实文件是 world-readable。
	expandedPath := p.tokenPath
	if strings.HasPrefix(expandedPath, "~/") {
		if homeDir, herr := os.UserHomeDir(); herr == nil {
			expandedPath = filepath.Join(homeDir, expandedPath[2:])
		}
	}

	data, err := util.ReadFile(p.tokenPath)
	if err != nil {
		return "", errors.NewCredentialError(
			"OidcTokenFileReadFailed",
			fmt.Sprintf("Failed to read OIDC token file %s: %s", p.tokenPath, err.Error()),
			err,
		)
	}

	// 凭证文件权限校验(beta 阶段 warn-only,不阻断调用)。
	// K8s 默认 SA token 由 kubelet 以 0600 挂载;若用户自配路径对 group/other 可读,
	// 本机其他 principal 可直接读取同一 OIDC token 冒用身份。使用展开后的路径 stat,
	// 跟随 symlink 校验最终目标权限(符号链接 swap 的 TOCTOU 风险留待 GA 处理)。
	if info, statErr := os.Stat(expandedPath); statErr == nil {
		if info.Mode().Perm()&0o077 != 0 {
			logger.Default().Warn(ctx,
				"OIDC token file is readable by group or other (expected 0600)",
				"event", "file_oidc.read", "status", "insecure_permission",
				"path", p.tokenPath, "mode", info.Mode().String())
		}
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
	// json.Unmarshal into map[string]interface{} always decodes JSON numbers
	// as float64, so only the float64 case is reachable. If future code uses
	// json.Decoder with UseNumber(), exp would come as json.Number instead.
	switch v := claims["exp"].(type) {
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("exp claim missing or not a number")
	}
}
