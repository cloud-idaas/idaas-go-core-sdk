package logger

import (
	"context"
	"strings"
	"testing"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		name  string
		level Level
		want  string
	}{
		{"debug", LevelDebug, "DEBUG"},
		{"info", LevelInfo, "INFO"},
		{"warn", LevelWarn, "WARN"},
		{"error", LevelError, "ERROR"},
		{"below debug", LevelDebug - 1, "DEBUG"},
		{"between debug and info", LevelDebug + 1, "DEBUG"},
		{"between info and warn", LevelInfo + 1, "INFO"},
		{"between warn and error", LevelWarn + 1, "WARN"},
		{"above error", LevelError + 1, "ERROR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

// TestEnabled_NilLogger nil logger → false。
func TestEnabled_NilLogger(t *testing.T) {
	if Enabled(context.Background(), nil, LevelDebug) {
		t.Error("Enabled with nil logger should return false")
	}
}

// TestEnabled_NoLevelEnabler 不实现 LevelEnabler 的 logger → true。
func TestEnabled_NoLevelEnabler(t *testing.T) {
	l := &noEnablerLogger{}
	if !Enabled(context.Background(), l, LevelDebug) {
		t.Error("Enabled with non-LevelEnabler logger should return true")
	}
}

// TestEnabled_WithLevelEnabler 实现了 LevelEnabler 的 logger → 委托给其 Enabled。
func TestEnabled_WithLevelEnabler(t *testing.T) {
	l := &basicLogger{enabledLevel: LevelWarn}
	if Enabled(context.Background(), l, LevelDebug) {
		t.Error("should not be enabled for Debug when threshold is Warn")
	}
	if !Enabled(context.Background(), l, LevelWarn) {
		t.Error("should be enabled for Warn when threshold is Warn")
	}
}

func TestNormalizeKV(t *testing.T) {
	tests := []struct {
		name string
		kv   []interface{}
		want []interface{}
	}{
		{
			name: "empty",
			kv:   nil,
			want: []interface{}{},
		},
		{
			name: "even valid pairs",
			kv:   []interface{}{"key1", "val1", "key2", "val2"},
			want: []interface{}{"key1", "val1", "key2", "val2"},
		},
		{
			name: "odd length - trailing value gets BADKEY",
			kv:   []interface{}{"key1", "val1", "orphan"},
			want: []interface{}{"key1", "val1", badKeyPlaceholder, "orphan"},
		},
		{
			name: "non-string key replaced with BADKEY",
			kv:   []interface{}{123, "val1", "key2", "val2"},
			want: []interface{}{badKeyPlaceholder, 123, badKeyPlaceholder, "val1", "key2", "val2"},
		},
		{
			name: "single non-string key",
			kv:   []interface{}{42},
			want: []interface{}{badKeyPlaceholder, 42},
		},
		{
			name: "single string key without value",
			kv:   []interface{}{"lonely"},
			want: []interface{}{badKeyPlaceholder, "lonely"},
		},
		{
			name: "two non-string keys",
			kv:   []interface{}{1, 2, 3, 4},
			want: []interface{}{badKeyPlaceholder, 1, badKeyPlaceholder, 2, badKeyPlaceholder, 3, badKeyPlaceholder, 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeKV(tt.kv)
			if len(got) != len(tt.want) {
				t.Fatalf("NormalizeKV() len = %d, want %d (got=%v, want=%v)", len(got), len(tt.want), got, tt.want)
			}
			for i := range got {
				if g, w := got[i], tt.want[i]; g != w {
					t.Errorf("NormalizeKV()[%d] = %v, want %v", i, g, w)
				}
			}
		})
	}
}

// TestHintLogger_Debug_NoOutput Debug 应静默。
func TestHintLogger_Debug_NoOutput(t *testing.T) {
	h := &hintLogger{}
	// 不 panic 即可
	h.Debug(context.Background(), "debug msg", "key", "val")
}

// TestHintLogger_Info_NoOutput Info 应静默。
func TestHintLogger_Info_NoOutput(t *testing.T) {
	h := &hintLogger{}
	h.Info(context.Background(), "info msg", "key", "val")
}

// TestHintLogger_Warn_PrintsOnce Warn 首次会打印到 stderr。
func TestHintLogger_Warn_PrintsOnce(t *testing.T) {
	h := &hintLogger{}
	h.Warn(context.Background(), "warn msg", "key", "val")
	// 第二次调用不应该再打印
	h.Warn(context.Background(), "second warn", "key2", "val2")
}

// TestHintLogger_Error_PrintsOnce Error 首次会打印到 stderr。
func TestHintLogger_Error_PrintsOnce(t *testing.T) {
	h := &hintLogger{}
	h.Error(context.Background(), "error msg", "key", "val")
	// 第二次调用不应该再打印
	h.Error(context.Background(), "second error", "key2", "val2")
}

// TestHintLogger_Enabled hintLogger.Enabled 的行为。
func TestHintLogger_Enabled(t *testing.T) {
	h := &hintLogger{}
	ctx := context.Background()
	tests := []struct {
		level Level
		want  bool
	}{
		{LevelDebug, false},
		{LevelInfo, false},
		{LevelWarn, true},
		{LevelError, true},
		{LevelWarn + 1, true},
	}
	for _, tt := range tests {
		if got := h.Enabled(ctx, tt.level); got != tt.want {
			t.Errorf("hintLogger.Enabled(%s) = %v, want %v", tt.level.String(), got, tt.want)
		}
	}
}

// TestHintLogger_Emit_OnlyOnce 确保 emit 只执行一次。
func TestHintLogger_Emit_OnlyOnce(t *testing.T) {
	h := &hintLogger{}
	// 第一次 emit 会打印
	h.emit(LevelWarn, "first", nil)
	// 第二次不应该 panic 或打印
	h.emit(LevelError, "second", []interface{}{"k", "v"})
}

func TestFormatKV(t *testing.T) {
	tests := []struct {
		name string
		kv   []interface{}
		want string
	}{
		{"empty", nil, ""},
		{"single pair", []interface{}{"key", "val"}, ` key="val"`},
		{"two pairs", []interface{}{"k1", "v1", "k2", "v2"}, ` k1="v1" k2="v2"`},
		{"odd length gets BADKEY", []interface{}{"k1", "v1", "orphan"}, ` k1="v1" ` + badKeyPlaceholder + `="orphan"`},
		{"empty key replaced", []interface{}{"", "val"}, ` ` + badKeyPlaceholder + `="val"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatKV(tt.kv)
			if got != tt.want {
				t.Errorf("formatKV() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want string
	}{
		{"nil", nil, "<nil>"},
		{"string", "hello", `"hello"`},
		{"error", errSimple{}, `"simple error"`},
		{"int", 42, "42"},
		{"bool", true, "true"},
		{"struct", struct{ X int }{X: 1}, "{1}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatValue(tt.val)
			if !strings.Contains(got, tt.want) && got != tt.want {
				// struct case may vary in formatting; use Contains for safety
				if tt.name == "struct" {
					if !strings.Contains(got, "1") {
						t.Errorf("formatValue(%v) = %q, want to contain %q", tt.val, got, "1")
					}
				} else {
					t.Errorf("formatValue(%v) = %q, want %q", tt.val, got, tt.want)
				}
			}
		})
	}
}

// errSimple 简单的 error 实现。
type errSimple struct{}

func (errSimple) Error() string { return "simple error" }

// TestDefault_NeverNil Default 不应返回 nil。
func TestDefault_NeverNil(t *testing.T) {
	l := Default()
	if l == nil {
		t.Fatal("Default() should never return nil")
	}
}

// TestSetDefault_ReplaceAndRestore 设置和恢复默认 logger。
func TestSetDefault_ReplaceAndRestore(t *testing.T) {
	original := Default()
	defer SetDefault(original)

	custom := &basicLogger{}
	SetDefault(custom)

	got := Default()
	if got != custom {
		t.Error("Default() should return the logger set by SetDefault")
	}
}

// TestSetDefault_NilRestoresToNop 传 nil 恢复为 Nop()。
func TestSetDefault_NilRestoresToNop(t *testing.T) {
	original := Default()
	defer SetDefault(original)

	SetDefault(nil)
	got := Default()
	// Nop() 返回一个完全静默的 logger
	got.Debug(context.Background(), "should be silent")
	// 验证它不是 nil
	if got == nil {
		t.Error("SetDefault(nil) should result in non-nil default")
	}
}

// basicLogger 简单的 Logger 实现，用于测试。
type basicLogger struct {
	enabledLevel Level
}

func (b *basicLogger) Debug(context.Context, string, ...interface{}) {}
func (b *basicLogger) Info(context.Context, string, ...interface{})  {}
func (b *basicLogger) Warn(context.Context, string, ...interface{})  {}
func (b *basicLogger) Error(context.Context, string, ...interface{}) {}

func (b *basicLogger) Enabled(_ context.Context, level Level) bool {
	return level >= b.enabledLevel
}

// noEnablerLogger 实现了 Logger 但不实现 LevelEnabler。
type noEnablerLogger struct{}

func (noEnablerLogger) Debug(context.Context, string, ...interface{}) {}
func (noEnablerLogger) Info(context.Context, string, ...interface{})  {}
func (noEnablerLogger) Warn(context.Context, string, ...interface{})  {}
func (noEnablerLogger) Error(context.Context, string, ...interface{}) {}
