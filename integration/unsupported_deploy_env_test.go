//go:build integration

// 未实现部署环境报错集成测试。
// 验证配置未实现的部署环境时，SDK 正确返回 UnsupportedClientDeployEnvironment 错误。
//
// 注意：UnsupportedClientDeployEnvironment 错误只在 PKCS7 和 OIDC 认证方式中触发，
// 不在 client_secret_basic 等认证方式中触发（这些认证方式不检查 deploy environment）。
package integration

import (
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	idaaserrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/internal/implementation"
)

// TestUnsupportedDeployEnvironment_PKCS7 验证 PKCS7 认证方式下未实现的部署环境报错
//
// 验证内容：
// PKCS7 认证只支持 ALIBABA_CLOUD_ECS 和 AWS_EC2，其他部署环境应返回 UnsupportedClientDeployEnvironment 错误
func TestUnsupportedDeployEnvironment_PKCS7(t *testing.T) {
	skipIfIntegrationDisabled(t)

	// 基础配置（从 pkcs7 复制，如果没有则从 client_secret_basic 复制并修改）
	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)

	// 修改为 PKCS7 认证方式
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "test-federated-credential"

	// 测试未实现的部署环境（PKCS7 只支持 ALIBABA_CLOUD_ECS 和 AWS_EC2）
	unsupportedEnvs := []enums.ClientDeployEnvironmentEnum{
		enums.ClientDeployEnvironmentCommon,          // COMMON
		enums.ClientDeployEnvironmentAlibabaCloudEci, // ALIBABA_CLOUD_ECI
		enums.ClientDeployEnvironmentAlibabaCloudAck, // ALIBABA_CLOUD_ACK
		enums.ClientDeployEnvironmentAwsEks,          // AWS_EKS
		enums.ClientDeployEnvironmentHuaweiCloudEcs,  // HUAWEI_CLOUD_ECS
		enums.ClientDeployEnvironmentCustom,          // CUSTOM
		enums.ClientDeployEnvironmentComputer,        // COMPUTER（PKCS7 不支持）
		enums.ClientDeployEnvironmentKubernetes,      // KUBERNETES（PKCS7 不支持）
		enums.ClientDeployEnvironmentGoogleVm,        // GOOGLE_VM（PKCS7 不支持）
		enums.ClientDeployEnvironmentAzureVm,         // AZURE_VM（PKCS7 不支持）
	}

	for _, env := range unsupportedEnvs {
		t.Run(string(env), func(t *testing.T) {
			cfg.AuthnConfiguration.ClientDeployEnvironment = env

			// 尝试创建 provider
			p := implementation.NewIDaaSMachineCredentialProvider(
				cfg,
				enums.StaleValueBehaviorRefresh,
				newHttpClientFromConfig(cfg),
			)

			// 应该返回错误
			_, err := p.GetCredential()
			if err == nil {
				t.Fatalf("PKCS7 + %s 应返回 UnsupportedClientDeployEnvironment 错误，但成功了", env)
			}

			// 验证错误码
			if !idaaserrors.HasCode(err, constants.UnsupportedClientDeployEnvironment) {
				t.Errorf("PKCS7 + %s 期望错误码 %s，实际: %v", env, constants.UnsupportedClientDeployEnvironment, err)
			} else {
				t.Logf("✅ PKCS7 + %s 正确返回 UnsupportedClientDeployEnvironment 错误", env)
			}
		})
	}
}

// TestUnsupportedDeployEnvironment_OIDC 验证 OIDC 认证方式下未实现的部署环境报错
//
// 验证内容：
// OIDC 认证只支持 KUBERNETES、GOOGLE_VM、AZURE_VM 和 COMPUTER，其他部署环境应返回 UnsupportedClientDeployEnvironment 错误
func TestUnsupportedDeployEnvironment_OIDC(t *testing.T) {
	skipIfIntegrationDisabled(t)

	// 基础配置
	cfg := loadConfig(t, "client_secret_basic")
	ensureCredentials(t, cfg)

	// 修改为 OIDC 认证方式
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "test-federated-credential"

	// 测试未实现的部署环境（OIDC 只支持 KUBERNETES、GOOGLE_VM、AZURE_VM、COMPUTER）
	unsupportedEnvs := []enums.ClientDeployEnvironmentEnum{
		enums.ClientDeployEnvironmentCommon,          // COMMON
		enums.ClientDeployEnvironmentAlibabaCloudEcs, // ALIBABA_CLOUD_ECS（OIDC 不支持）
		enums.ClientDeployEnvironmentAlibabaCloudEci, // ALIBABA_CLOUD_ECI
		enums.ClientDeployEnvironmentAlibabaCloudAck, // ALIBABA_CLOUD_ACK
		enums.ClientDeployEnvironmentAwsEc2,          // AWS_EC2（OIDC 不支持）
		enums.ClientDeployEnvironmentAwsEks,          // AWS_EKS
		enums.ClientDeployEnvironmentHuaweiCloudEcs,  // HUAWEI_CLOUD_ECS
		enums.ClientDeployEnvironmentCustom,          // CUSTOM
	}

	for _, env := range unsupportedEnvs {
		t.Run(string(env), func(t *testing.T) {
			cfg.AuthnConfiguration.ClientDeployEnvironment = env

			// 尝试创建 provider
			p := implementation.NewIDaaSMachineCredentialProvider(
				cfg,
				enums.StaleValueBehaviorRefresh,
				newHttpClientFromConfig(cfg),
			)

			// 应该返回错误
			_, err := p.GetCredential()
			if err == nil {
				t.Fatalf("OIDC + %s 应返回 UnsupportedClientDeployEnvironment 错误，但成功了", env)
			}

			// 验证错误码
			if !idaaserrors.HasCode(err, constants.UnsupportedClientDeployEnvironment) {
				t.Errorf("OIDC + %s 期望错误码 %s，实际: %v", env, constants.UnsupportedClientDeployEnvironment, err)
			} else {
				t.Logf("✅ OIDC + %s 正确返回 UnsupportedClientDeployEnvironment 错误", env)
			}
		})
	}
}
