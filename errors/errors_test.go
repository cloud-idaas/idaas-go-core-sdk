package errors

import "testing"

func TestClientError(t *testing.T) {
	err := NewClientError("TestCode", "Test message", nil)

	if err.ErrorCode() != "TestCode" {
		t.Errorf("Expected ErrorCode to be 'TestCode', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}

	expectedError := "[TestCode] Test message"
	if err.Error() != expectedError {
		t.Errorf("Expected Error() to be '%s', got '%s'", expectedError, err.Error())
	}
}

func TestClientErrorWithCause(t *testing.T) {
	cause := &testError{"cause error"}
	err := NewClientError("TestCode", "Test message", cause)

	expectedError := "[TestCode] Test message: cause error"
	if err.Error() != expectedError {
		t.Errorf("Expected Error() to be '%s', got '%s'", expectedError, err.Error())
	}
}

func TestServerError(t *testing.T) {
	err := NewServerError("TestCode", "Test message", 500, nil)

	if err.ErrorCode() != "TestCode" {
		t.Errorf("Expected ErrorCode to be 'TestCode', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}

	expectedError := "[TestCode] Test message (HTTP 500)"
	if err.Error() != expectedError {
		t.Errorf("Expected Error() to be '%s', got '%s'", expectedError, err.Error())
	}
}

func TestServerErrorWithCause(t *testing.T) {
	cause := &testError{"cause error"}
	err := NewServerError("TestCode", "Test message", 500, cause)

	expectedError := "[TestCode] Test message (HTTP 500): cause error"
	if err.Error() != expectedError {
		t.Errorf("Expected Error() to be '%s', got '%s'", expectedError, err.Error())
	}
}

func TestConfigError(t *testing.T) {
	err := NewConfigError("TestCode", "Test message", nil)

	if err.ErrorCode() != "TestCode" {
		t.Errorf("Expected ErrorCode to be 'TestCode', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}
}

func TestConcurrentOperationError(t *testing.T) {
	err := NewConcurrentOperationError("Test message", nil)

	if err.ErrorCode() != "ConcurrentOperationFailed" {
		t.Errorf("Expected ErrorCode to be 'ConcurrentOperationFailed', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}
}

func TestCacheError(t *testing.T) {
	err := NewCacheError("TestCode", "Test message", nil)

	if err.ErrorCode() != "TestCode" {
		t.Errorf("Expected ErrorCode to be 'TestCode', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}
}

func TestCredentialError(t *testing.T) {
	err := NewCredentialError("TestCode", "Test message", nil)

	if err.ErrorCode() != "TestCode" {
		t.Errorf("Expected ErrorCode to be 'TestCode', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}
}

func TestEncodingError(t *testing.T) {
	err := NewEncodingError("TestCode", "Test message", nil)

	if err.ErrorCode() != "TestCode" {
		t.Errorf("Expected ErrorCode to be 'TestCode', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}
}

func TestHttpError(t *testing.T) {
	err := NewHttpError("TestCode", "Test message", 400, nil)

	if err.ErrorCode() != "TestCode" {
		t.Errorf("Expected ErrorCode to be 'TestCode', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}

	expectedError := "[TestCode] Test message (HTTP 400)"
	if err.Error() != expectedError {
		t.Errorf("Expected Error() to be '%s', got '%s'", expectedError, err.Error())
	}
}

func TestUnexpectedError(t *testing.T) {
	err := NewUnexpectedError("Test message", nil)

	if err.ErrorCode() != "UnexpectedError" {
		t.Errorf("Expected ErrorCode to be 'UnexpectedError', got %s", err.ErrorCode())
	}

	if err.ErrorMessage() != "Test message" {
		t.Errorf("Expected ErrorMessage to be 'Test message', got %s", err.ErrorMessage())
	}

	expectedError := "[UnexpectedError] Test message"
	if err.Error() != expectedError {
		t.Errorf("Expected Error() to be '%s', got '%s'", expectedError, err.Error())
	}
}

// testError is a simple error implementation for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
