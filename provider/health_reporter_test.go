package provider

import (
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// mockHealthReporter 用于编译期验证 HealthReporter 接口可被实现。
type mockHealthReporter struct{}

func (mockHealthReporter) Healthy() bool                { return true }
func (mockHealthReporter) TokenState() enums.TokenState { return enums.TokenStateHealthy }
func (mockHealthReporter) LastRefreshTime() time.Time   { return time.Time{} }
func (mockHealthReporter) LastRefreshError() error      { return nil }
func (mockHealthReporter) ExpiresAt() time.Time         { return time.Time{} }

func TestHealthReporterInterfaceCompiles(t *testing.T) {
	var _ HealthReporter = mockHealthReporter{}
}
