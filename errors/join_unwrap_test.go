//go:build go1.20

package errors

import (
	stderrors "errors"
	"io"
	"testing"
)

// errors.Join 是 Go 1.20+ API,且 Go 1.18 的 go vet(stdmethods 检查)不识别
// Unwrap() []error 方法签名,无法在下限作业中通过静态检查。本文件用构建标签
// 隔离:Go 1.18 下限作业自动跳过整个文件,1.20+ 工具链(含 CI 覆盖率作业)
// 正常编译运行,被测的 Unwrap() []error 多路展开逻辑覆盖不受影响。

// ---------------------------------------------------------------------------
// HasCode and requestIdFromChain handle errors.Join (Unwrap() []error)
// ---------------------------------------------------------------------------

// TestHasCode_Join errors.Join wraps an SDK error; HasCode must find its code
// through the Unwrap() []error path.
func TestHasCode_Join(t *testing.T) {
	inner := NewClientError("X", "msg", nil)
	joined := stderrors.Join(io.EOF, inner)
	if !HasCode(joined, "X") {
		t.Errorf("HasCode should find code X in errors.Join")
	}
}

// TestHasCode_JoinNoMatch errors.Join without the target code returns false.
func TestHasCode_JoinNoMatch(t *testing.T) {
	inner := NewClientError("X", "msg", nil)
	joined := stderrors.Join(io.EOF, inner)
	if HasCode(joined, "Y") {
		t.Errorf("HasCode should not find code Y in errors.Join")
	}
}

// TestRequestIdFromChain_Join errors.Join wraps an SDK error with requestId;
// requestIdFromChain must find it through the Unwrap() []error path.
func TestRequestIdFromChain_Join(t *testing.T) {
	inner := NewClientError("code", "msg", nil).WithRequestId("rid-join")
	joined := stderrors.Join(io.EOF, inner)
	if got := requestIdFromChain(joined); got != "rid-join" {
		t.Errorf("requestIdFromChain(joined) = %q, want %q", got, "rid-join")
	}
}

// TestRequestIdOf_Join RequestIdOf on a joined error finds the SDK error's requestId.
func TestRequestIdOf_Join(t *testing.T) {
	inner := NewClientError("code", "msg", nil).WithRequestId("rid-join-of")
	joined := stderrors.Join(io.EOF, inner)
	if got := RequestIdOf(joined); got != "rid-join-of" {
		t.Errorf("RequestIdOf(joined) = %q, want %q", got, "rid-join-of")
	}
}
