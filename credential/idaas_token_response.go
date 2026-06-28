package credential

import (
	"encoding/json"
	"time"
)

// IDaaSTokenResponse 结构体 (§3.2)
// OAuth2 Token Endpoint 的响应
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

// MarshalJSON 自定义 JSON 序列化。
//
// 注意：time.Time 的零值（year 1）调用 .Unix() 会返回 -6795364578871 这样的大负数，
// 序列化出去后下次 Unmarshal 会得到一个奇怪的远古时间。这里显式判 IsZero，
// 零值时省略 received_at 字段，由 UnmarshalJSON 回退到 time.Now()。
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

// WillSoonExpire 判断令牌是否即将过期 (§3.2)
// threshold: 提前多少秒认为即将过期
func (r *IDaaSTokenResponse) WillSoonExpire(thresholdSeconds int64) bool {
	if r.ExpiresIn <= 0 {
		return true
	}
	expiryTime := r.ReceivedAt.Add(time.Duration(r.ExpiresIn) * time.Second)
	thresholdTime := time.Now().Add(time.Duration(thresholdSeconds) * time.Second)
	return expiryTime.Before(thresholdTime)
}

// GetAccessToken 实现 IDaaSCredential 接口
func (r *IDaaSTokenResponse) GetAccessToken() string {
	return r.AccessToken
}

// GetTokenType 实现 IDaaSCredential 接口
func (r *IDaaSTokenResponse) GetTokenType() string {
	return r.TokenType
}

// GetExpiresIn 实现 IDaaSCredential 接口
func (r *IDaaSTokenResponse) GetExpiresIn() int64 {
	return r.ExpiresIn
}

// GetScope 实现 IDaaSCredential 接口
func (r *IDaaSTokenResponse) GetScope() string {
	return r.Scope
}

// GetRefreshToken 实现 IDaaSCredential 接口
func (r *IDaaSTokenResponse) GetRefreshToken() string {
	return r.RefreshToken
}
