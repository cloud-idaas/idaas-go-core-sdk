package slog

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	sdklog "github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

// newTestLogger 创建一个输出到 buffer 的 slog.Logger 及其 buffer,
// 方便断言适配器转发的日志内容。
func newTestLogger(t *testing.T, level slog.Level) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})
	return slog.New(handler), &buf
}

func TestAdapterImplementsInterfaces(t *testing.T) {
	var _ sdklog.Logger = (*Adapter)(nil)
	var _ sdklog.LevelEnabler = (*Adapter)(nil)
}

func TestNewNilFallsBackToDefault(t *testing.T) {
	// New(nil) 不应 panic,回退到 slog.Default()。
	a := New(nil)
	if a == nil {
		t.Fatal("New(nil) returned nil")
	}
}

func TestLevelMapping(t *testing.T) {
	cases := []struct {
		sdk  sdklog.Level
		want slog.Level
	}{
		{sdklog.LevelDebug, slog.LevelDebug},
		{sdklog.LevelInfo, slog.LevelInfo},
		{sdklog.LevelWarn, slog.LevelWarn},
		{sdklog.LevelError, slog.LevelError},
	}
	for _, c := range cases {
		if got := toSlogLevel(c.sdk); got != c.want {
			t.Errorf("toSlogLevel(%d) = %v, want %v", c.sdk, got, c.want)
		}
	}
}

func TestDebugForwardsMessage(t *testing.T) {
	sl, buf := newTestLogger(t, slog.LevelDebug)
	a := New(sl)
	ctx := context.Background()
	a.Debug(ctx, "hello", "key", "value")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}
	if entry["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", entry["msg"])
	}
	if entry["level"] != "DEBUG" {
		t.Errorf("level = %v, want DEBUG", entry["level"])
	}
	if entry["key"] != "value" {
		t.Errorf("key = %v, want value", entry["key"])
	}
}

func TestErrorForwardsMessage(t *testing.T) {
	sl, buf := newTestLogger(t, slog.LevelError)
	a := New(sl)
	ctx := context.Background()
	a.Error(ctx, "boom", "error_code", "X")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}
	if entry["msg"] != "boom" {
		t.Errorf("msg = %v, want boom", entry["msg"])
	}
	if entry["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", entry["level"])
	}
}

func TestLevelFiltered(t *testing.T) {
	// 设 INFO 级别,Debug 应被过滤。
	sl, buf := newTestLogger(t, slog.LevelInfo)
	a := New(sl)
	ctx := context.Background()
	a.Debug(ctx, "should-not-appear")
	if buf.Len() > 0 {
		t.Errorf("Debug should be filtered at INFO level, got: %s", buf.String())
	}
	a.Info(ctx, "should-appear")
	if buf.Len() == 0 {
		t.Error("Info should appear at INFO level")
	}
}

func TestEnabledMethod(t *testing.T) {
	sl, _ := newTestLogger(t, slog.LevelWarn)
	a := New(sl)
	ctx := context.Background()
	if a.Enabled(ctx, sdklog.LevelDebug) {
		t.Error("LevelDebug should be disabled at WARN threshold")
	}
	if !a.Enabled(ctx, sdklog.LevelWarn) {
		t.Error("LevelWarn should be enabled at WARN threshold")
	}
	if !a.Enabled(ctx, sdklog.LevelError) {
		t.Error("LevelError should be enabled at WARN threshold")
	}
}

func TestRedactsSensitiveKeys(t *testing.T) {
	sl, buf := newTestLogger(t, slog.LevelDebug)
	a := New(sl)
	ctx := context.Background()

	// access_token 是敏感 key,应被 RedactKV 脱敏。
	a.Warn(ctx, "token refresh", "access_token", "eyJhbGciOiJSUzI1NiJ9.secret.payload")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}

	redacted, ok := entry["access_token"].(string)
	if !ok {
		t.Fatalf("access_token missing or wrong type: %v", entry["access_token"])
	}
	if strings.Contains(redacted, "secret.payload") {
		t.Errorf("access_token not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "***(len=") {
		t.Errorf("access_token redaction format unexpected: %s", redacted)
	}
}

func TestOddKVDoesNotPanic(t *testing.T) {
	sl, buf := newTestLogger(t, slog.LevelDebug)
	a := New(sl)
	ctx := context.Background()

	// 奇数长度 kv 不应 panic,NormalizeKV 补 !BADKEY。
	a.Info(ctx, "test", "key1", "value1", "key2")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}
	if _, ok := entry["!BADKEY"]; !ok {
		t.Errorf("expected !BADKEY placeholder for odd kv, got: %v", entry)
	}
}

func TestToSlogArgsEmpty(t *testing.T) {
	if got := toSlogArgs(nil); got != nil {
		t.Errorf("toSlogArgs(nil) = %v, want nil", got)
	}
	if got := toSlogArgs([]interface{}{}); got != nil {
		t.Errorf("toSlogArgs(empty) = %v, want nil", got)
	}
}

func TestToSlogArgsNonEmpty(t *testing.T) {
	kv := []interface{}{"a", 1, "b", "two"}
	got := toSlogArgs(kv)
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	if got[0] != "a" || got[1] != 1 || got[2] != "b" || got[3] != "two" {
		t.Errorf("toSlogArgs = %v, want [a 1 b two]", got)
	}
}

// TestSlogAdapter_DoesNotRejectCanceledCtx 验证:
// 适配器不得因 ctx.Err()!=nil 拒记——否则 logger.WithoutCancel polyfill
// (其 Err() 返 nil)的语义前提被破坏。
//
// 适配器实现(Debug/Warn/...)仅把 ctx 透传给 slog.Logger.*Context,
// 不在适配器层检查 ctx.Err();底层 slog.JSONHandler 同样不拒记。
// 用一个已 cancel 的 ctx 走完整 Info 链路,断言 buffer 有落盘即可证明。
func TestSlogAdapter_DoesNotRejectCanceledCtx(t *testing.T) {
	sl, buf := newTestLogger(t, slog.LevelDebug)
	a := New(sl)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	if err := ctx.Err(); err == nil {
		t.Fatal("test setup invariant: ctx should be canceled")
	}

	a.Info(ctx, "msg-after-cancel", "k", "v")

	out := buf.Bytes()
	if !strings.Contains(string(out), "msg-after-cancel") {
		t.Errorf("adapter dropped log on canceled ctx; buf=%q", out)
	}
	if !strings.Contains(string(out), `"k":"v"`) {
		t.Errorf("kv missing on canceled-ctx log; buf=%q", out)
	}
}

// TestSlogAdapter_DoesNotRejectPolyfillCtx 验证 polyfill ctx(Err()=nil,
// Done()=nil)经适配器链路正常落盘——这是新 worker 日志 ctx 的端到端断言
// (runRefreshAndCommit / runAzureFetch 的日志走这条路)。
func TestSlogAdapter_DoesNotRejectPolyfillCtx(t *testing.T) {
	sl, buf := newTestLogger(t, slog.LevelDebug)
	a := New(sl)

	// 模拟 worker 场景:parent 被取消,但日志 ctx 用 polyfill 派生。
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	logCtx := sdklog.WithoutCancel(parent)

	if err := logCtx.Err(); err != nil {
		t.Fatalf("polyfill Err() must be nil, got %v", err)
	}

	a.Warn(logCtx, "worker-refresh-failed", "err", "boom")

	out := buf.Bytes()
	if !strings.Contains(string(out), "worker-refresh-failed") {
		t.Errorf("polyfill-ctx log dropped; buf=%q", out)
	}
	if !strings.Contains(string(out), `"err":"boom"`) {
		t.Errorf("kv missing on polyfill-ctx log; buf=%q", out)
	}
}
