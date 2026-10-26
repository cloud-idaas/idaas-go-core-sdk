package metrics

import (
	"context"
	"testing"
	"time"
)

// TestNoopRecorderImplementsInterface 确保 noopRecorder 满足 Recorder 接口。
func TestNoopRecorderImplementsInterface(t *testing.T) {
	var _ Recorder = NoopRecorder()
}

// TestNoopRecorderIsSafeToCall 确保所有方法可安全调用,不 panic、不返回 error。
func TestNoopRecorderIsSafeToCall(t *testing.T) {
	r := NoopRecorder()
	ctx := context.Background()

	// 不应 panic
	r.RecordTokenRefresh(ctx, true, 100*time.Millisecond)
	r.RecordTokenRefresh(ctx, false, 50*time.Millisecond)
	r.RecordTokenPrefetch(ctx, true, 200*time.Millisecond)
	r.RecordCacheHit(ctx, "test-key")
	r.RecordCacheMiss(ctx, "test-key")
	r.RecordDegradation(ctx, true)
	r.RecordDegradation(ctx, false)
	r.RecordHttpRequest(ctx, "POST", "https://example.com/token", 200, 300*time.Millisecond)
}
