package authentication

import (
	"testing"
	"time"
)

// allowedDelta 允许的时间断言误差，覆盖 time.Now() 在被测函数内外两次取值的间隔。
const allowedDelta = 2 * time.Second

// TestResolveDeviceCodeDeadline_FutureExpiresAtTakesPriority 验证：当 expires_at 是未来的
// 绝对时间戳时，直接采用它，且优先级高于 expires_in。
func TestResolveDeviceCodeDeadline_FutureExpiresAtTakesPriority(t *testing.T) {
	expectedDeadline := time.Now().Add(300 * time.Second)
	expiresAt := expectedDeadline.Unix()
	expiresIn := int64(600)

	deadline := resolveDeviceCodeDeadline(expiresAt, expiresIn)

	if deadline.Unix() != expiresAt {
		t.Errorf("expected deadline to equal expires_at %d, got %d", expiresAt, deadline.Unix())
	}
}

// TestResolveDeviceCodeDeadline_PastExpiresAtFallsBackToExpiresIn 验证修复点：当服务端返回
// 过去的 expires_at（时钟漂移 / 异常）时，必须忽略它并回退到 expires_in，否则会一次轮询都
// 不进入就立即超时。
func TestResolveDeviceCodeDeadline_PastExpiresAtFallsBackToExpiresIn(t *testing.T) {
	pastExpiresAt := time.Now().Add(-1 * time.Hour).Unix()
	expiresIn := int64(600)

	before := time.Now()
	deadline := resolveDeviceCodeDeadline(pastExpiresAt, expiresIn)

	expectedMin := before.Add(time.Duration(expiresIn) * time.Second)
	if deadline.Before(expectedMin.Add(-allowedDelta)) || deadline.After(expectedMin.Add(allowedDelta)) {
		t.Errorf("expected deadline ~%v (now + expires_in), got %v", expectedMin, deadline)
	}
	if !deadline.After(time.Now()) {
		t.Errorf("deadline must be in the future so polling can run, got %v", deadline)
	}
}

// TestResolveDeviceCodeDeadline_PastExpiresAtNoExpiresInFallsBackToMax 验证：过去的 expires_at
// 且没有 expires_in 时，回退到默认等待上限 MaxWaitIntervalSeconds。
func TestResolveDeviceCodeDeadline_PastExpiresAtNoExpiresInFallsBackToMax(t *testing.T) {
	pastExpiresAt := time.Now().Add(-1 * time.Hour).Unix()

	before := time.Now()
	deadline := resolveDeviceCodeDeadline(pastExpiresAt, 0)

	expectedMin := before.Add(MaxWaitIntervalSeconds * time.Second)
	if deadline.Before(expectedMin.Add(-allowedDelta)) || deadline.After(expectedMin.Add(allowedDelta)) {
		t.Errorf("expected deadline ~%v (now + max), got %v", expectedMin, deadline)
	}
}

// TestResolveDeviceCodeDeadline_OnlyExpiresIn 验证：没有 expires_at 时使用 expires_in。
func TestResolveDeviceCodeDeadline_OnlyExpiresIn(t *testing.T) {
	expiresIn := int64(120)

	before := time.Now()
	deadline := resolveDeviceCodeDeadline(0, expiresIn)

	expectedMin := before.Add(time.Duration(expiresIn) * time.Second)
	if deadline.Before(expectedMin.Add(-allowedDelta)) || deadline.After(expectedMin.Add(allowedDelta)) {
		t.Errorf("expected deadline ~%v (now + expires_in), got %v", expectedMin, deadline)
	}
}

// TestResolveDeviceCodeDeadline_NoServerHints 验证：expires_at 和 expires_in 都缺失时，
// 回退到默认等待上限 MaxWaitIntervalSeconds。
func TestResolveDeviceCodeDeadline_NoServerHints(t *testing.T) {
	before := time.Now()
	deadline := resolveDeviceCodeDeadline(0, 0)

	expectedMin := before.Add(MaxWaitIntervalSeconds * time.Second)
	if deadline.Before(expectedMin.Add(-allowedDelta)) || deadline.After(expectedMin.Add(allowedDelta)) {
		t.Errorf("expected deadline ~%v (now + max), got %v", expectedMin, deadline)
	}
}

// TestResolveDeviceCodeDeadline_NegativeExpiresInFallsBackToMax 验证：expires_in 为负值
// （异常输入）时同样回退到默认上限，不会产生早于当前时间的 deadline。
func TestResolveDeviceCodeDeadline_NegativeExpiresInFallsBackToMax(t *testing.T) {
	before := time.Now()
	deadline := resolveDeviceCodeDeadline(0, -10)

	expectedMin := before.Add(MaxWaitIntervalSeconds * time.Second)
	if deadline.Before(expectedMin.Add(-allowedDelta)) || deadline.After(expectedMin.Add(allowedDelta)) {
		t.Errorf("expected deadline ~%v (now + max), got %v", expectedMin, deadline)
	}
}
