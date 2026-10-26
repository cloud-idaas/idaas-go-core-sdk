//go:build integration

// 多云部署面集成入口（AWS_EC2 PKCS7 / KUBERNETES·AZURE_VM·GOOGLE_VM OIDC）。
//
// 与 TestPkcs7（阿里云 ECS）、TestOidc（COMPUTER）同构：环境探活失败自动 skip，
// 因此放在任何机器上跑都安全；真实验证需在对应云上执行。
// 从零开始的实操步骤见 docs/m2m-multi-cloud-test-manual.md。
//
//	go test -tags integration -v -run TestPkcs7AwsEc2 ./integration/
//	go test -tags integration -v -run TestOidcKubernetes ./integration/
//	go test -tags integration -v -run 'TestOidc(Azure|Google)' ./integration/
package integration

import (
	"testing"
)

// TestPkcs7AwsEc2 走 AWS EC2 实例身份（IMDSv2 取 PKCS7 identity document）的 M2M 换票链路。
// 元数据服务地址硬编码 169.254.169.254，只有真实 EC2 实例可达；探活失败自动 skip。
// 前置：实例启用 IMDSv2、IDaaS 侧联邦凭证登记了对应 AWS 账号（aws_account_id 校验）。
func TestPkcs7AwsEc2(t *testing.T) {
	cred, _ := obtainToken(t, "pkcs7_aws_ec2")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

// TestOidcKubernetes 走 K8s Service Account JWT 的 OIDC 联邦换票。
// token 来源：oidcTokenFilePath → oidcTokenFilePathEnvVarName → 默认 SA 路径
// /var/run/secrets/.../token（三者依次回落，与 fetchOidcToken 的 KUBERNETES 分支一致）。
// 前置：在集群内 Pod 中运行（或 kubectl exec 进带 SA 的 Pod），且 IDaaS 联邦凭证
// 信任该集群 API Server 的 OIDC issuer（audience 需与 SA token 的 aud 匹配）。
func TestOidcKubernetes(t *testing.T) {
	cred, _ := obtainToken(t, "oidc_kubernetes")
	assertCredential(t, cred, "cloud_account_role:obtain_access_credential")
}

// TestOidcAzureVm 走 Azure VM Managed Identity（IMDS 取 ARM resource token）的 OIDC 联邦换票。
// 环境探活即真实取一次 MI token（非 200 一律 skip），因此"能跑"就意味着 MI 绑定正确。
// 前置：Azure VM 已分配系统/用户指派 MI，IDaaS 联邦凭证登记该 MI 的 issuer/subject 规则。
func TestOidcAzureVm(t *testing.T) {
	cred, _ := obtainToken(t, "oidc_azure_vm")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}

// TestOidcGoogleVm 走 GCE VM 元数据服务签发 ID Token 的 OIDC 联邦换票。
// audience 约定：取配置 issuer 的 origin（scheme://host），与 IDaaS 联邦凭证侧一致。
// 前置：GCE VM 挂载的 service account 与 IDaaS 联邦凭证登记一致；
// metadata.google.internal 仅 GCP 内可解析，开发机上探活失败自动 skip。
func TestOidcGoogleVm(t *testing.T) {
	cred, _ := obtainToken(t, "oidc_google_vm")
	assertCredential(t, cred, "cloud_account_resource:manage_all")
}
