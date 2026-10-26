package metrics

import (
	"context"
	"testing"
	"time"
)

// TestNoopRecorder_AllMethodsCovered 全面测试所有 Recorder 方法。
func TestNoopRecorder_AllMethodsCovered(t *testing.T) {
	r := NoopRecorder()
	ctx := context.Background()

	// 所有方法都不应 panic，不应返回 error
	r.RecordTokenRefresh(ctx, true, 100*time.Millisecond)
	r.RecordTokenRefresh(ctx, false, 50*time.Millisecond)
	r.RecordTokenPrefetch(ctx, true, 200*time.Millisecond)
	r.RecordTokenPrefetch(ctx, false, 150*time.Millisecond)
	r.RecordCacheHit(ctx, "cache-key-1")
	r.RecordCacheHit(ctx, "cache-key-2")
	r.RecordCacheMiss(ctx, "cache-key-1")
	r.RecordCacheMiss(ctx, "cache-key-2")
	r.RecordDegradation(ctx, true)
	r.RecordDegradation(ctx, false)
	r.RecordHttpRequest(ctx, "GET", "https://example.com/token", 200, 300*time.Millisecond)
	r.RecordHttpRequest(ctx, "POST", "https://example.com/token", 500, 500*time.Millisecond)
	r.RecordHttpRequest(ctx, "PUT", "https://example.com/resource", 404, 10*time.Millisecond)
}

// TestNoopRecorder_ReturnsNewInstance 每次调用返回新实例。
func TestNoopRecorder_ReturnsNewInstance(t *testing.T) {
	r1 := NoopRecorder()
	r2 := NoopRecorder()
	// noopRecorder 是值类型，不同调用返回不同实例（但行为相同）
	var _ Recorder = r1
	var _ Recorder = r2
}

// TestNoopRecorder_ConcurrentAccess 并发调用不应 panic。
func TestNoopRecorder_ConcurrentAccess(t *testing.T) {
	r := NoopRecorder()
	ctx := context.Background()

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			r.RecordTokenRefresh(ctx, true, 10*time.Millisecond)
			r.RecordCacheHit(ctx, "k")
			r.RecordDegradation(ctx, true)
			r.RecordHttpRequest(ctx, "GET", "/", 200, 10*time.Millisecond)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestNoopRecorder_SatisfiesInterface 确保 noopRecorder 满足 Recorder 接口。
func TestNoopRecorder_SatisfiesInterface(t *testing.T) {
	var _ Recorder = noopRecorder{}
	var _ Recorder = NoopRecorder()
}

// TestNoopRecorder_RecordTokenRefresh 单独测试 RecordTokenRefresh。
func TestNoopRecorder_RecordTokenRefresh(t *testing.T) {
	r := NoopRecorder()
	r.RecordTokenRefresh(context.Background(), true, 0)
	r.RecordTokenRefresh(context.Background(), false, 0)
}

// TestNoopRecorder_RecordTokenPrefetch 单独测试 RecordTokenPrefetch。
func TestNoopRecorder_RecordTokenPrefetch(t *testing.T) {
	r := NoopRecorder()
	r.RecordTokenPrefetch(context.Background(), true, 0)
	r.RecordTokenPrefetch(context.Background(), false, 0)
}

// TestNoopRecorder_RecordCacheHit 单独测试 RecordCacheHit。
func TestNoopRecorder_RecordCacheHit(t *testing.T) {
	r := NoopRecorder()
	r.RecordCacheHit(context.Background(), "test-key")
}

// TestNoopRecorder_RecordCacheMiss 单独测试 RecordCacheMiss。
func TestNoopRecorder_RecordCacheMiss(t *testing.T) {
	r := NoopRecorder()
	r.RecordCacheMiss(context.Background(), "test-key")
}

// TestNoopRecorder_RecordDegradation 单独测试 RecordDegradation。
func TestNoopRecorder_RecordDegradation(t *testing.T) {
	r := NoopRecorder()
	r.RecordDegradation(context.Background(), true)
	r.RecordDegradation(context.Background(), false)
}

// TestNoopRecorder_RecordHttpRequest 单独测试 RecordHttpRequest。
func TestNoopRecorder_RecordHttpRequest(t *testing.T) {
	r := NoopRecorder()
	r.RecordHttpRequest(context.Background(), "GET", "/api", 200, 100*time.Millisecond)
}
