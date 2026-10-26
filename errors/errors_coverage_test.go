package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// requestIdError is a minimal error that implements RequestId() but not full
// IDaaSError — used to test the loose interface assertion in requestIdFromChain.
type requestIdError struct {
	msg       string
	requestID string
	next      error // for Unwrap
}

func (e *requestIdError) Error() string { return e.msg }
func (e *requestIdError) RequestId() string {
	if e.requestID != "" {
		return e.requestID
	}
	return requestIdFromChain(e.next)
}
func (e *requestIdError) Unwrap() error { return e.next }

// circularError returns itself from Unwrap, creating an infinite loop.
// It does NOT implement RequestId() so requestIdFromChain will keep walking
// until the maxDepth guard kicks in.
type circularError struct{}

func (e *circularError) Error() string { return "circular" }
func (e *circularError) Unwrap() error { return e }

// plainError is the simplest possible error without any extra methods.
type plainError struct{ msg string }

func (e *plainError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// requestIdFromChain (base.go)
// ---------------------------------------------------------------------------

func TestRequestIdFromChain_NilError(t *testing.T) {
	if got := requestIdFromChain(nil); got != "" {
		t.Errorf("requestIdFromChain(nil) = %q, want empty", got)
	}
}

func TestRequestIdFromChain_DirectRequestId(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "rid-123"}
	if got := requestIdFromChain(cause); got != "rid-123" {
		t.Errorf("requestIdFromChain = %q, want %q", got, "rid-123")
	}
}

func TestRequestIdFromChain_NestedChain(t *testing.T) {
	inner := &requestIdError{msg: "inner", requestID: "deep-rid"}
	middle := &requestIdError{msg: "middle", requestID: "", next: inner}
	outer := &requestIdError{msg: "outer", requestID: "", next: middle}

	if got := requestIdFromChain(outer); got != "deep-rid" {
		t.Errorf("requestIdFromChain = %q, want %q", got, "deep-rid")
	}
}

func TestRequestIdFromChain_PlainErrorNoRequestId(t *testing.T) {
	e := &plainError{msg: "no rid"}
	if got := requestIdFromChain(e); got != "" {
		t.Errorf("requestIdFromChain on plain error = %q, want empty", got)
	}
}

func TestRequestIdFromChain_CircularGuard(t *testing.T) {
	// A self-referencing Unwrap chain must terminate at maxDepth (64)
	// rather than infinitely recursing.
	e := &circularError{}
	// Should not hang or panic; returns "" because circularError has no RequestId().
	if got := requestIdFromChain(e); got != "" {
		t.Errorf("requestIdFromChain(circular) = %q, want empty", got)
	}
}

func TestRequestIdFromChain_EmptyRequestIdSkipped(t *testing.T) {
	// If the first error in chain has empty requestId, walk to the next.
	inner := &requestIdError{msg: "inner", requestID: "found"}
	outer := &requestIdError{msg: "outer", requestID: "", next: inner}
	if got := requestIdFromChain(outer); got != "found" {
		t.Errorf("requestIdFromChain = %q, want %q", got, "found")
	}
}

// ---------------------------------------------------------------------------
// AsIDaaSError (base.go)
// ---------------------------------------------------------------------------

func TestAsIDaaSError_Direct(t *testing.T) {
	err := NewClientError("code", "msg", nil)
	ie, ok := AsIDaaSError(err)
	if !ok {
		t.Fatalf("AsIDaaSError returned ok=false for *ClientError")
	}
	if ie.ErrorCode() != "code" {
		t.Errorf("ErrorCode = %q, want %q", ie.ErrorCode(), "code")
	}
}

func TestAsIDaaSError_Wrapped(t *testing.T) {
	inner := NewServerError("code", "msg", 500, nil)
	wrapped := fmt.Errorf("outer: %w", inner)
	ie, ok := AsIDaaSError(wrapped)
	if !ok {
		t.Fatalf("AsIDaaSError returned ok=false for wrapped *ServerError")
	}
	if ie.ErrorCode() != "code" {
		t.Errorf("ErrorCode = %q, want %q", ie.ErrorCode(), "code")
	}
}

func TestAsIDaaSError_NotIDaaSError(t *testing.T) {
	ie, ok := AsIDaaSError(&plainError{msg: "plain"})
	if ok {
		t.Fatalf("AsIDaaSError returned ok=true for plain error, got %+v", ie)
	}
	if ie != nil {
		t.Errorf("AsIDaaSError returned non-nil interface for plain error: %+v", ie)
	}
}

func TestAsIDaaSError_Nil(t *testing.T) {
	ie, ok := AsIDaaSError(nil)
	if ok {
		t.Fatalf("AsIDaaSError(nil) returned ok=true")
	}
	if ie != nil {
		t.Errorf("AsIDaaSError(nil) returned non-nil: %+v", ie)
	}
}

// ---------------------------------------------------------------------------
// HasCode (base.go)
// ---------------------------------------------------------------------------

func TestHasCode_DirectMatch(t *testing.T) {
	err := NewClientError("MyCode", "msg", nil)
	if !HasCode(err, "MyCode") {
		t.Errorf("HasCode = false, want true for matching code")
	}
}

func TestHasCode_NoMatch(t *testing.T) {
	err := NewClientError("MyCode", "msg", nil)
	if HasCode(err, "OtherCode") {
		t.Errorf("HasCode = true, want false for non-matching code")
	}
}

func TestHasCode_NilError(t *testing.T) {
	if HasCode(nil, "anything") {
		t.Errorf("HasCode(nil) = true, want false")
	}
}

func TestHasCode_WrappedMatch(t *testing.T) {
	inner := NewServerError("InnerCode", "msg", 500, nil)
	wrapped := fmt.Errorf("outer: %w", inner)
	if !HasCode(wrapped, "InnerCode") {
		t.Errorf("HasCode on wrapped error = false, want true")
	}
}

func TestHasCode_ChainWithDifferentCodes(t *testing.T) {
	inner := NewClientError("InnerCode", "inner", nil)
	outer := NewCredentialError("OuterCode", "outer", inner)
	if !HasCode(outer, "InnerCode") {
		t.Errorf("HasCode should find InnerCode in chain")
	}
	if !HasCode(outer, "OuterCode") {
		t.Errorf("HasCode should find OuterCode at top level")
	}
	if HasCode(outer, "MissingCode") {
		t.Errorf("HasCode should not find MissingCode")
	}
}

// ---------------------------------------------------------------------------
// RequestIdOf (base.go)
// ---------------------------------------------------------------------------

func TestRequestIdOf_Nil(t *testing.T) {
	if got := RequestIdOf(nil); got != "" {
		t.Errorf("RequestIdOf(nil) = %q, want empty", got)
	}
}

func TestRequestIdOf_IDaaSError(t *testing.T) {
	err := NewClientError("code", "msg", nil).WithRequestId("rid-001")
	if got := RequestIdOf(err); got != "rid-001" {
		t.Errorf("RequestIdOf = %q, want %q", got, "rid-001")
	}
}

func TestRequestIdOf_WrappedNonIDaaS(t *testing.T) {
	inner := NewServerError("code", "msg", 500, nil).WithRequestId("rid-002")
	wrapped := fmt.Errorf("context: %w", inner)
	// wrapped itself does not implement IDaaSError, so RequestIdOf falls
	// through to requestIdFromChain(Unwrap(wrapped)) → inner.
	if got := RequestIdOf(wrapped); got != "rid-002" {
		t.Errorf("RequestIdOf(wrapped) = %q, want %q", got, "rid-002")
	}
}

func TestRequestIdOf_PlainError(t *testing.T) {
	if got := RequestIdOf(&plainError{msg: "x"}); got != "" {
		t.Errorf("RequestIdOf(plain) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// ClientError: WithRequestId, RequestId, Unwrap
// ---------------------------------------------------------------------------

func TestClientError_WithRequestId(t *testing.T) {
	err := NewClientError("code", "msg", nil)
	returned := err.WithRequestId("rid-client")
	if returned != err {
		t.Errorf("WithRequestId should return the same *ClientError for chaining")
	}
	if got := err.requestId; got != "rid-client" {
		t.Errorf("internal requestId = %q, want %q", got, "rid-client")
	}
}

func TestClientError_RequestId_Own(t *testing.T) {
	err := NewClientError("code", "msg", nil).WithRequestId("own-rid")
	if got := err.RequestId(); got != "own-rid" {
		t.Errorf("RequestId = %q, want %q", got, "own-rid")
	}
}

func TestClientError_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cause-rid"}
	err := NewClientError("code", "msg", cause)
	if got := err.RequestId(); got != "cause-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "cause-rid")
	}
}

func TestClientError_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewClientError("code", "msg", nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestClientError_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewClientError("code", "msg", cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	// nil cause
	errNil := NewClientError("code", "msg", nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// ServerError: WithRequestId, RequestId, Unwrap
// ---------------------------------------------------------------------------

func TestServerError_WithRequestId(t *testing.T) {
	err := NewServerError("code", "msg", 500, nil)
	returned := err.WithRequestId("rid-server")
	if returned != err {
		t.Errorf("WithRequestId should return the same *ServerError for chaining")
	}
	if got := err.requestId; got != "rid-server" {
		t.Errorf("internal requestId = %q, want %q", got, "rid-server")
	}
}

func TestServerError_RequestId_Own(t *testing.T) {
	err := NewServerError("code", "msg", 500, nil).WithRequestId("own-rid")
	if got := err.RequestId(); got != "own-rid" {
		t.Errorf("RequestId = %q, want %q", got, "own-rid")
	}
}

func TestServerError_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cause-rid"}
	err := NewServerError("code", "msg", 500, cause)
	if got := err.RequestId(); got != "cause-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "cause-rid")
	}
}

func TestServerError_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewServerError("code", "msg", 500, nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestServerError_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewServerError("code", "msg", 500, cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	errNil := NewServerError("code", "msg", 500, nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// HttpError: Error (cause branch), WithRequestId, RequestId, Unwrap
// ---------------------------------------------------------------------------

func TestHttpError_ErrorWithCause(t *testing.T) {
	cause := &plainError{msg: "connection reset"}
	err := NewHttpError("HttpErr", "request failed", 502, cause)
	want := "[HttpErr] request failed (HTTP 502): connection reset"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestHttpError_WithRequestId(t *testing.T) {
	err := NewHttpError("code", "msg", 400, nil)
	returned := err.WithRequestId("rid-http")
	if returned != err {
		t.Errorf("WithRequestId should return the same *HttpError for chaining")
	}
	if got := err.requestId; got != "rid-http" {
		t.Errorf("internal requestId = %q, want %q", got, "rid-http")
	}
}

func TestHttpError_RequestId_Own(t *testing.T) {
	err := NewHttpError("code", "msg", 400, nil).WithRequestId("own-rid")
	if got := err.RequestId(); got != "own-rid" {
		t.Errorf("RequestId = %q, want %q", got, "own-rid")
	}
}

func TestHttpError_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cause-rid"}
	err := NewHttpError("code", "msg", 400, cause)
	if got := err.RequestId(); got != "cause-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "cause-rid")
	}
}

func TestHttpError_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewHttpError("code", "msg", 400, nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestHttpError_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewHttpError("code", "msg", 400, cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	errNil := NewHttpError("code", "msg", 400, nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// OAuth2Error: Error, ErrorCode, ErrorMessage, RequestId, WithRequestId,
//               Unwrap, NewOAuth2Error
// ---------------------------------------------------------------------------

func TestNewOAuth2Error(t *testing.T) {
	cause := &plainError{msg: "http error"}
	err := NewOAuth2Error(400, "invalid_grant", "bad code", "raw body", cause)
	if err.HTTPStatus != 400 {
		t.Errorf("HTTPStatus = %d, want 400", err.HTTPStatus)
	}
	if err.OAuthCode != "invalid_grant" {
		t.Errorf("OAuthCode = %q, want %q", err.OAuthCode, "invalid_grant")
	}
	if err.OAuthDescription != "bad code" {
		t.Errorf("OAuthDescription = %q, want %q", err.OAuthDescription, "bad code")
	}
	if err.RawBody != "raw body" {
		t.Errorf("RawBody = %q, want %q", err.RawBody, "raw body")
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestOAuth2Error_Error_WithDescription(t *testing.T) {
	err := NewOAuth2Error(400, "invalid_grant", "the grant is invalid", "", nil)
	want := "[OAuth2 invalid_grant] (HTTP 400): the grant is invalid"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestOAuth2Error_Error_LongDescriptionTruncated(t *testing.T) {
	longDesc := strings.Repeat("A", 600)
	err := NewOAuth2Error(500, "server_error", longDesc, "", nil)
	got := err.Error()
	// The error_description portion must be truncated to 512 + suffix
	wantDesc := strings.Repeat("A", 512) + "...(truncated)"
	want := "[OAuth2 server_error] (HTTP 500): " + wantDesc
	if got != want {
		t.Errorf("Error() not truncated properly:\n got len=%d\nwant len=%d", len(got), len(want))
	}
	// FullDescription must still return the complete untruncated text
	if got := err.FullDescription(); got != longDesc {
		t.Errorf("FullDescription() len = %d, want %d", len(got), len(longDesc))
	}
	// ErrorMessage must still return the complete untruncated text
	if got := err.ErrorMessage(); got != longDesc {
		t.Errorf("ErrorMessage() len = %d, want %d", len(got), len(longDesc))
	}
}

func TestOAuth2Error_Error_DescriptionExactly512NotTruncated(t *testing.T) {
	desc := strings.Repeat("B", 512)
	err := NewOAuth2Error(400, "invalid_grant", desc, "", nil)
	got := err.Error()
	want := "[OAuth2 invalid_grant] (HTTP 400): " + desc
	if got != want {
		t.Errorf("Error() should not truncate at exactly 512 bytes")
	}
}

func TestOAuth2Error_Error_WithoutDescription(t *testing.T) {
	err := NewOAuth2Error(401, "invalid_client", "", "", nil)
	want := "[OAuth2 invalid_client] (HTTP 401)"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestOAuth2Error_ErrorCode_WithOAuthCode(t *testing.T) {
	err := NewOAuth2Error(400, "invalid_grant", "desc", "", nil)
	if got := err.ErrorCode(); got != "invalid_grant" {
		t.Errorf("ErrorCode() = %q, want %q", got, "invalid_grant")
	}
}

func TestOAuth2Error_ErrorCode_Fallback(t *testing.T) {
	// Empty OAuthCode → falls back to constants.OAuth2Failed
	err := NewOAuth2Error(400, "", "desc", "", nil)
	if got := err.ErrorCode(); got != constants.OAuth2Failed {
		t.Errorf("ErrorCode() = %q, want %q", got, constants.OAuth2Failed)
	}
}

func TestOAuth2Error_ErrorMessage_WithDescription(t *testing.T) {
	err := NewOAuth2Error(400, "invalid_grant", "the grant is invalid", "", nil)
	if got := err.ErrorMessage(); got != "the grant is invalid" {
		t.Errorf("ErrorMessage() = %q, want %q", got, "the grant is invalid")
	}
}

func TestOAuth2Error_ErrorMessage_FallbackToRawBody(t *testing.T) {
	// Empty OAuthDescription → falls back to RawBody
	err := NewOAuth2Error(400, "invalid_grant", "", "fallback body", nil)
	if got := err.ErrorMessage(); got != "fallback body" {
		t.Errorf("ErrorMessage() = %q, want %q", got, "fallback body")
	}
}

func TestOAuth2Error_WithRequestId(t *testing.T) {
	err := NewOAuth2Error(400, "code", "desc", "", nil)
	returned := err.WithRequestId("rid-oauth")
	if returned != err {
		t.Errorf("WithRequestId should return the same *OAuth2Error for chaining")
	}
	if got := err.requestId; got != "rid-oauth" {
		t.Errorf("internal requestId = %q, want %q", got, "rid-oauth")
	}
}

func TestOAuth2Error_RequestId_Own(t *testing.T) {
	err := NewOAuth2Error(400, "code", "desc", "", nil).WithRequestId("own-rid")
	if got := err.RequestId(); got != "own-rid" {
		t.Errorf("RequestId = %q, want %q", got, "own-rid")
	}
}

func TestOAuth2Error_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cause-rid"}
	err := NewOAuth2Error(400, "code", "desc", "", cause)
	if got := err.RequestId(); got != "cause-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "cause-rid")
	}
}

func TestOAuth2Error_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewOAuth2Error(400, "code", "desc", "", nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestOAuth2Error_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewOAuth2Error(400, "code", "desc", "", cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	errNil := NewOAuth2Error(400, "code", "desc", "", nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// EncodingError: Error (both branches), WithRequestId, RequestId, Unwrap
// ---------------------------------------------------------------------------

func TestEncodingError_ErrorWithoutCause(t *testing.T) {
	err := NewEncodingError("EncCode", "decode failed", nil)
	want := "[EncCode] decode failed"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestEncodingError_ErrorWithCause(t *testing.T) {
	cause := &plainError{msg: "json: invalid"}
	err := NewEncodingError("EncCode", "decode failed", cause)
	want := "[EncCode] decode failed: json: invalid"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestEncodingError_WithRequestId(t *testing.T) {
	err := NewEncodingError("code", "msg", nil)
	returned := err.WithRequestId("rid-enc")
	if returned != err {
		t.Errorf("WithRequestId should return the same *EncodingError for chaining")
	}
	if got := err.requestId; got != "rid-enc" {
		t.Errorf("internal requestId = %q, want %q", got, "rid-enc")
	}
}

func TestEncodingError_RequestId_Own(t *testing.T) {
	err := NewEncodingError("code", "msg", nil).WithRequestId("own-rid")
	if got := err.RequestId(); got != "own-rid" {
		t.Errorf("RequestId = %q, want %q", got, "own-rid")
	}
}

func TestEncodingError_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cause-rid"}
	err := NewEncodingError("code", "msg", cause)
	if got := err.RequestId(); got != "cause-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "cause-rid")
	}
}

func TestEncodingError_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewEncodingError("code", "msg", nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestEncodingError_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewEncodingError("code", "msg", cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	errNil := NewEncodingError("code", "msg", nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// CredentialError: Error (both branches), RequestId, Unwrap
// ---------------------------------------------------------------------------

func TestCredentialError_ErrorWithoutCause(t *testing.T) {
	err := NewCredentialError("CredCode", "credential failed", nil)
	want := "[CredCode] credential failed"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCredentialError_ErrorWithCause(t *testing.T) {
	cause := &plainError{msg: "token expired"}
	err := NewCredentialError("CredCode", "credential failed", cause)
	want := "[CredCode] credential failed: token expired"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCredentialError_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cred-rid"}
	err := NewCredentialError("code", "msg", cause)
	if got := err.RequestId(); got != "cred-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "cred-rid")
	}
}

func TestCredentialError_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewCredentialError("code", "msg", nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestCredentialError_WithRequestId(t *testing.T) {
	err := NewCredentialError("code", "msg", nil)
	returned := err.WithRequestId("rid-cred")
	if returned != err {
		t.Errorf("WithRequestId should return the same *CredentialError for chaining")
	}
	if got := err.requestId; got != "rid-cred" {
		t.Errorf("internal requestId = %q, want %q", got, "rid-cred")
	}
}

func TestCredentialError_RequestId_Own(t *testing.T) {
	err := NewCredentialError("code", "msg", nil).WithRequestId("own-cred-rid")
	if got := err.RequestId(); got != "own-cred-rid" {
		t.Errorf("RequestId = %q, want %q", got, "own-cred-rid")
	}
}

func TestCredentialError_RequestId_OwnTakesPrecedenceOverCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cause-rid"}
	err := NewCredentialError("code", "msg", cause).WithRequestId("own-rid")
	if got := err.RequestId(); got != "own-rid" {
		t.Errorf("RequestId = %q, want %q (own should take precedence)", got, "own-rid")
	}
}

func TestCredentialError_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewCredentialError("code", "msg", cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	errNil := NewCredentialError("code", "msg", nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// CacheError: Error (both branches), RequestId, Unwrap
// ---------------------------------------------------------------------------

func TestCacheError_ErrorWithoutCause(t *testing.T) {
	err := NewCacheError("CacheCode", "cache miss", nil)
	want := "[CacheCode] cache miss"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCacheError_ErrorWithCause(t *testing.T) {
	cause := &plainError{msg: "redis down"}
	err := NewCacheError("CacheCode", "cache miss", cause)
	want := "[CacheCode] cache miss: redis down"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCacheError_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "cache-rid"}
	err := NewCacheError("code", "msg", cause)
	if got := err.RequestId(); got != "cache-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "cache-rid")
	}
}

func TestCacheError_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewCacheError("code", "msg", nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestCacheError_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewCacheError("code", "msg", cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	errNil := NewCacheError("code", "msg", nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// IDaaSUnexpectedError: Error (cause branch), RequestId, Unwrap
// ---------------------------------------------------------------------------

func TestUnexpectedError_ErrorWithCause(t *testing.T) {
	cause := &plainError{msg: "nil pointer"}
	err := NewUnexpectedError("something broke", cause)
	want := "[" + constants.UnexpectedError + "] something broke: nil pointer"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestUnexpectedError_RequestId_FromCause(t *testing.T) {
	cause := &requestIdError{msg: "cause", requestID: "unexp-rid"}
	err := NewUnexpectedError("msg", cause)
	if got := err.RequestId(); got != "unexp-rid" {
		t.Errorf("RequestId = %q, want %q (from cause)", got, "unexp-rid")
	}
}

func TestUnexpectedError_RequestId_EmptyWhenNoCause(t *testing.T) {
	err := NewUnexpectedError("msg", nil)
	if got := err.RequestId(); got != "" {
		t.Errorf("RequestId = %q, want empty", got)
	}
}

func TestUnexpectedError_Unwrap(t *testing.T) {
	cause := &plainError{msg: "cause"}
	err := NewUnexpectedError("msg", cause)
	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
	errNil := NewUnexpectedError("msg", nil)
	if unwrapped := errNil.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

// ---------------------------------------------------------------------------
// Integration: errors.Is / errors.As work through Unwrap chain
// ---------------------------------------------------------------------------

func TestErrorsAsThroughUnwrapChain(t *testing.T) {
	cause := NewServerError("server-code", "server msg", 500, nil)
	wrapped := NewCredentialError("cred-code", "cred msg", cause)

	var target *ServerError
	if !stderrors.As(wrapped, &target) {
		t.Fatalf("errors.As should find *ServerError in Unwrap chain")
	}
	if target.ErrorCode() != "server-code" {
		t.Errorf("target.ErrorCode() = %q, want %q", target.ErrorCode(), "server-code")
	}
}

func TestErrorsIsThroughUnwrapChain(t *testing.T) {
	sentinel := &plainError{msg: "sentinel"}
	err := NewClientError("code", "msg", sentinel)
	if !stderrors.Is(err, sentinel) {
		t.Errorf("errors.Is should find sentinel in Unwrap chain")
	}
}

// ---------------------------------------------------------------------------
// RequestIdOf must check err itself, not skip to Unwrap(err)
// ---------------------------------------------------------------------------

// TestRequestIdOf_ThirdPartyRequestIdNoUnwrap A third-party error that implements
// RequestId() string but not IDaaSError and not Unwrap — previously its requestId
// was lost because RequestIdOf called requestIdFromChain(Unwrap(err)) = (nil).
func TestRequestIdOf_ThirdPartyRequestIdNoUnwrap(t *testing.T) {
	e := &requestIdError{msg: "third-party", requestID: "rid-third"}
	if got := RequestIdOf(e); got != "rid-third" {
		t.Errorf("RequestIdOf = %q, want %q", got, "rid-third")
	}
}

// ---------------------------------------------------------------------------
// cyclic Cause chain must not stack-overflow
// ---------------------------------------------------------------------------

// TestRequestId_CyclicCauseDoesNotPanic e.Cause = e creates a cycle.
// e.RequestId() → requestIdFromChain(e.Cause) → requestIdFromChain(e)
// must terminate via the visited set, not infinite-recurse.
func TestRequestId_CyclicCauseDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RequestId panicked on cyclic Cause: %v", r)
		}
	}()

	e := NewClientError("x", "x", nil)
	e.Cause = e // cyclic
	id := e.RequestId()
	if id != "" {
		t.Errorf("RequestId on cyclic cause = %q, want empty", id)
	}
}

// TestRequestIdFromChain_CyclicCauseDirect calling requestIdFromChain directly
// on a cyclic SDK error must also terminate.
func TestRequestIdFromChain_CyclicCauseDirect(t *testing.T) {
	e := NewClientError("x", "x", nil)
	e.Cause = e
	if got := requestIdFromChain(e); got != "" {
		t.Errorf("requestIdFromChain(cyclic) = %q, want empty", got)
	}
}

// TestHasCode_CyclicCauseDoesNotPanic HasCode must also handle cyclic chains.
func TestHasCode_CyclicCauseDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("HasCode panicked on cyclic Cause: %v", r)
		}
	}()

	e := NewClientError("X", "x", nil)
	e.Cause = e
	// Should find the code on the first node before hitting the cycle.
	if !HasCode(e, "X") {
		t.Errorf("HasCode should find X on cyclic error")
	}
	// Should not find a non-matching code, and should not hang.
	if HasCode(e, "Y") {
		t.Errorf("HasCode should not find Y on cyclic error")
	}
}
