package logger

import (
	"context"
	"testing"
)

// TestNop_ReturnsNonNil Nop() 返回非 nil Logger。
func TestNop_ReturnsNonNil(t *testing.T) {
	l := Nop()
	if l == nil {
		t.Fatal("Nop() should not return nil")
	}
}

// TestNop_AllMethodsSilent 所有方法都不 panic。
func TestNop_AllMethodsSilent(t *testing.T) {
	l := Nop()
	ctx := context.Background()

	// 不应 panic
	l.Debug(ctx, "debug msg", "key", "val")
	l.Info(ctx, "info msg", "key", "val")
	l.Warn(ctx, "warn msg", "key", "val")
	l.Error(ctx, "error msg", "key", "val")
}

// TestNop_Debug 测试 Debug 方法。
func TestNop_Debug(t *testing.T) {
	l := Nop()
	l.Debug(context.Background(), "msg", "k", "v")
}

// TestNop_Info 测试 Info 方法。
func TestNop_Info(t *testing.T) {
	l := Nop()
	l.Info(context.Background(), "msg", "k", "v")
}

// TestNop_Warn 测试 Warn 方法。
func TestNop_Warn(t *testing.T) {
	l := Nop()
	l.Warn(context.Background(), "msg", "k", "v")
}

// TestNop_Error 测试 Error 方法。
func TestNop_Error(t *testing.T) {
	l := Nop()
	l.Error(context.Background(), "msg", "k", "v")
}

// TestNop_Enabled 恒为 false。
func TestNop_Enabled(t *testing.T) {
	l := Nop()
	ctx := context.Background()
	levels := []Level{LevelDebug, LevelInfo, LevelWarn, LevelError}
	for _, lv := range levels {
		if l.(LevelEnabler).Enabled(ctx, lv) {
			t.Errorf("Nop().Enabled(%s) = true, want false", lv.String())
		}
	}
}

// TestNop_SameInstance 多次调用返回的实例应相同（单例）。
func TestNop_SameInstance(t *testing.T) {
	l1 := Nop()
	l2 := Nop()
	// 底层是同一个 nopLogger 值类型，比较应相等
	if l1 != l2 {
		t.Error("Nop() should return the same instance")
	}
}

// TestNop_ImplementsLogger 确保 Nop 满足 Logger 接口。
func TestNop_ImplementsLogger(t *testing.T) {
	var _ Logger = Nop()
}
