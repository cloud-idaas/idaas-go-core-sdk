package config

import (
	"encoding/json"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// scenario13HumanConfigJSON 为《SDK 业务场景配置示例全量文档》场景 13 的 HUMAN 配置原样：
// 不设置 authnMethod。
const scenario13HumanConfigJSON = `{
    "idaasInstanceId": "idaas_xxx",
    "clientId": "app_xxx",
    "issuer": "https://your-instance.example.com/api/v2/iauths_system/oauth2",
    "tokenEndpoint": "https://your-instance.example.com/api/v2/iauths_system/oauth2/token",
    "deviceAuthorizationEndpoint": "https://your-instance.example.com/api/v2/iauths_system/oauth2/device_authorization",
    "scope": "api://api.xxxxx.com|read:file",
    "authnConfiguration": {
        "identityType": "HUMAN",
        "humanAuthenticateClientId": "iap_developer"
    }
}`

func humanBaseConfig(t *testing.T) *IDaaSClientConfig {
	t.Helper()
	var cfg IDaaSClientConfig
	if err := json.Unmarshal([]byte(scenario13HumanConfigJSON), &cfg); err != nil {
		t.Fatalf("unmarshal scenario 13 config: %v", err)
	}
	return &cfg
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %s, got nil", code)
	}
	if !sdkerrors.HasCode(err, code) {
		t.Fatalf("expected error code %s, got: %v", code, err)
	}
}

// 场景 13：HUMAN 不设 authnMethod 必须通过校验（与 Java/Python 对齐）。
func TestValidate_Human_WithoutAuthnMethod_Passes(t *testing.T) {
	cfg := humanBaseConfig(t)
	if cfg.AuthnConfiguration.AuthnMethod != "" {
		t.Fatalf("precondition: authnMethod should be empty, got %q", cfg.AuthnConfiguration.AuthnMethod)
	}
	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("scenario 13 HUMAN config should pass validation, got: %v", err)
	}
}

// humanAuthenticateClientId 留空时由 factory 回落默认值，不应在校验阶段拦截。
func TestValidate_Human_WithoutHumanClientId_Passes(t *testing.T) {
	cfg := humanBaseConfig(t)
	cfg.AuthnConfiguration.HumanAuthenticateClientId = ""
	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("expected pass with default humanAuthenticateClientId fallback, got: %v", err)
	}
}

// HUMAN 缺 deviceAuthorizationEndpoint 必须在 init 校验阶段失败，而不是延迟到取凭证时。
func TestValidate_Human_MissingDeviceAuthorizationEndpoint_Fails(t *testing.T) {
	for _, v := range []string{"", "   "} {
		cfg := humanBaseConfig(t)
		cfg.DeviceAuthorizationEndpoint = v
		assertCode(t, NewConfigValidator().Validate(cfg), constants.DeviceAuthorizationEndpointNotFound)
	}
}

// 即使 HUMAN 显式配置了合法 authnMethod，也不能绕过 deviceAuthorizationEndpoint 必填。
func TestValidate_Human_WithAuthnMethod_MissingDeviceAuthorizationEndpoint_Fails(t *testing.T) {
	cfg := humanBaseConfig(t)
	cfg.DeviceAuthorizationEndpoint = ""
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodClientSecretPost
	cfg.AuthnConfiguration.ClientSecretEnvVarName = "CLOUD_IDAAS_CLIENT_SECRET"
	assertCode(t, NewConfigValidator().Validate(cfg), constants.DeviceAuthorizationEndpointNotFound)
}

// HUMAN 显式设置了 authnMethod 时仍按对应方式校验字段，错误配置不能被静默吞掉。
func TestValidate_Human_WithIncompleteAuthnMethod_Fails(t *testing.T) {
	cfg := humanBaseConfig(t)
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodClientSecretPost
	assertCode(t, NewConfigValidator().Validate(cfg), constants.ClientSecretEnvVarNameNotFound)
}

// "none" 仍被拒绝：HUMAN 不需要它（留空即可），CLIENT 不允许无客户端认证。
func TestValidate_Human_AuthnMethodNone_Rejected(t *testing.T) {
	cfg := humanBaseConfig(t)
	cfg.AuthnConfiguration.AuthnMethod = "none"
	assertCode(t, NewConfigValidator().Validate(cfg), constants.UnsupportedAuthenticationMethod)
}

// HUMAN 放行 authnMethod 时不能跳过 HTTP 超时范围校验。
func TestValidate_Human_WithoutAuthnMethod_InvalidHttpConfig_Fails(t *testing.T) {
	cfg := humanBaseConfig(t)
	cfg.HttpConfiguration = &HttpConfiguration{ConnectTimeout: 100}
	assertCode(t, NewConfigValidator().Validate(cfg), constants.ConnectTimeoutNotValid)
}

// HUMAN 放行 authnMethod 时不能跳过 staleValueBehavior 校验。
// 非法值(如 "INVALID")必须在 init 阶段拦截,否则会进入运行时 supplier,
// 在无 default 分支时返回过期 token 当成功。
func TestValidate_Human_WithoutAuthnMethod_InvalidStaleValueBehavior_Fails(t *testing.T) {
	cfg := humanBaseConfig(t)
	cfg.StaleValueBehavior = "INVALID"
	assertCode(t, NewConfigValidator().Validate(cfg), constants.InvalidStaleValueBehavior)
}

// HUMAN 放行 authnMethod 时合法 staleValueBehavior 仍能通过校验。
func TestValidate_Human_WithoutAuthnMethod_ValidStaleValueBehavior_Passes(t *testing.T) {
	cfg := humanBaseConfig(t)
	cfg.StaleValueBehavior = enums.StaleValueBehaviorBlock
	if err := NewConfigValidator().Validate(cfg); err != nil {
		t.Fatalf("valid staleValueBehavior should pass, got: %v", err)
	}
}

// 回归：CLIENT（显式或留空 identityType）不设 authnMethod 仍必须失败。
func TestValidate_Client_WithoutAuthnMethod_StillFails(t *testing.T) {
	for _, it := range []enums.AuthenticationIdentityEnum{enums.AuthenticationIdentityClient, ""} {
		cfg := validBaseConfig()
		cfg.AuthnConfiguration.AuthnMethod = ""
		cfg.AuthnConfiguration.IdentityType = it
		assertCode(t, NewConfigValidator().Validate(cfg), constants.AuthnConfigurationNotFound)
	}
}

// 非法 identityType 在 authnMethod 校验之前被识别，错误码不被 authnMethod 错误掩盖。
func TestValidate_UnsupportedIdentityType_ReportedFirst(t *testing.T) {
	cfg := validBaseConfig()
	cfg.AuthnConfiguration.AuthnMethod = ""
	cfg.AuthnConfiguration.IdentityType = "ROBOT"
	assertCode(t, NewConfigValidator().Validate(cfg), constants.UnsupportedIdentityType)
}

// TestValidate_StaleValueBehavior covers the newconfig field: empty
// passes (factory normalizes to REFRESH), valid values pass, and an unknown
// value is rejected with InvalidStaleValueBehavior.
func TestValidate_StaleValueBehavior(t *testing.T) {
	t.Run("empty passes", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.StaleValueBehavior = ""
		if err := NewConfigValidator().Validate(cfg); err != nil {
			t.Fatalf("empty staleValueBehavior should pass, got: %v", err)
		}
	})
	t.Run("valid values pass", func(t *testing.T) {
		for _, b := range []enums.StaleValueBehavior{
			enums.StaleValueBehaviorBlock,
			enums.StaleValueBehaviorAllow,
			enums.StaleValueBehaviorRefresh,
		} {
			cfg := validBaseConfig()
			cfg.StaleValueBehavior = b
			if err := NewConfigValidator().Validate(cfg); err != nil {
				t.Fatalf("staleValueBehavior=%s should pass, got: %v", b, err)
			}
		}
	})
	t.Run("invalid rejected", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.StaleValueBehavior = "FAST_FAIL"
		assertCode(t, NewConfigValidator().Validate(cfg), constants.InvalidStaleValueBehavior)
	})
}
