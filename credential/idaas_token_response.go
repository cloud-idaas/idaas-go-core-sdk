package credential

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

type IDaaSTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`

	// ReceivedAt 记录接收时间，用于计算是否即将过期
	ReceivedAt time.Time `json:"-"`
}

// MarshalJSON 自定义序列化：time.Time 零值 .Unix() 会产生大负数，零值时省略
// received_at 字段，由 UnmarshalJSON 回退到 time.Now()。
func (r *IDaaSTokenResponse) MarshalJSON() ([]byte, error) {
	type Alias IDaaSTokenResponse
	var receivedAt int64
	if !r.ReceivedAt.IsZero() {
		receivedAt = r.ReceivedAt.Unix()
	}
	return json.Marshal(&struct {
		*Alias
		ReceivedAt int64 `json:"received_at,omitempty"`
	}{
		Alias:      (*Alias)(r),
		ReceivedAt: receivedAt,
	})
}

// UnmarshalJSON 自定义 JSON 反序列化
func (r *IDaaSTokenResponse) UnmarshalJSON(data []byte) error {
	type Alias IDaaSTokenResponse
	aux := &struct {
		*Alias
		ReceivedAt int64 `json:"received_at,omitempty"`
	}{
		Alias: (*Alias)(r),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if aux.ReceivedAt > 0 {
		r.ReceivedAt = time.Unix(aux.ReceivedAt, 0)
	} else {
		r.ReceivedAt = time.Now()
	}

	return nil
}

// WillSoonExpire 判断令牌是否即将过期
// threshold: 提前多少秒认为即将过期
func (r *IDaaSTokenResponse) WillSoonExpire(thresholdSeconds int64) bool {
	if r.ExpiresIn <= 0 {
		return true
	}
	// SE与 cache.NewRefreshResult 一致,超大 expires_in 在 int64 纳秒乘法下会溢出
	// 回绕为负值。这里用 util.DurationFromSeconds 钳位换算,避免 expiryTime 计算错误。
	expiryTime := r.ReceivedAt.Add(util.DurationFromSeconds(r.ExpiresIn))
	thresholdTime := time.Now().Add(util.DurationFromSeconds(thresholdSeconds))
	return expiryTime.Before(thresholdTime)
}

func (r *IDaaSTokenResponse) GetAccessToken() string {
	return r.AccessToken
}

func (r *IDaaSTokenResponse) GetTokenType() string {
	return r.TokenType
}

func (r *IDaaSTokenResponse) GetExpiresIn() int64 {
	return r.ExpiresIn
}

func (r *IDaaSTokenResponse) GetScope() string {
	return r.Scope
}

func (r *IDaaSTokenResponse) GetRefreshToken() string {
	return r.RefreshToken
}

// ValidateLocalToken 校验 token endpoint 响应的基本完整性：
// access_token 非空（RFC 6749）、token_type 必须为 Bearer（SDK 不支持其他类型）。
// refresh_token / id_token 可选，不强制非空。
func (r *IDaaSTokenResponse) ValidateLocalToken() error {
	if r.AccessToken == "" {
		return errors.NewCredentialError(
			constants.AccessTokenNotFound,
			"access_token is missing or empty in token response",
			nil,
		)
	}
	if !strings.EqualFold(r.TokenType, "Bearer") {
		return errors.NewCredentialError(
			constants.InvalidTokenType,
			"token_type must be \"Bearer\", got: \""+r.TokenType+"\"",
			nil,
		)
	}
	// expires_in 非正数会导致退化缓存（立即过期 → 刷新风暴）。
	// 在本地校验阶段拦截，避免退化值进入缓存层。
	if r.ExpiresIn <= 0 {
		return errors.NewCredentialError(
			constants.InvalidExpiresIn,
			"expires_in must be a positive integer, got: "+strconv.FormatInt(r.ExpiresIn, 10),
			nil,
		)
	}
	return nil
}

// String 返回脱敏摘要，避免 %v/fmt.Println 把凭证明文落日志。
// 只保留前缀 + 长度 + SHA256 前 8 位，可定位凭证又不泄露原文。
//
// TokenType/Scope 来自服务端响应,若含换行/控制字符会伪造额外日志行
// (log injection)。sanitizeForLog 将控制字符替换为可视转义,防止行注入。
func (r *IDaaSTokenResponse) String() string {
	return "IDaaSCredential{type=" + sanitizeForLog(r.TokenType) +
		", tok=" + logger.Redact(r.AccessToken) +
		", rtok=" + logger.Redact(r.RefreshToken) +
		", exp=" + strconv.FormatInt(r.ExpiresIn, 10) +
		", scope=" + sanitizeForLog(r.Scope) + "}"
}

// sanitizeForLog 把字符串中的控制字符（换行、制表符、其他 C0 控制字符）替换为
// 可视转义形式,防止服务端响应中的恶意控制字符伪造额外日志行(log injection)。
// 返回的值只用于日志/错误消息摘要,不参与协议逻辑。
func sanitizeForLog(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			b.WriteString("?")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
