package enums

// ClientDeployEnvironmentEnum 部署环境枚举，对应 authnConfiguration.clientDeployEnvironment。
// 与阿里云 Java SDK 对齐（共 11 值）；AWS_EKS 已修正 Java/Python 的 "AWS_ESK" 字母错排，
// 上游待同步。枚举齐全是为对齐 Java SDK + 预留扩展；实际支持的运行时分支：
// PKCS7+ALIBABA_CLOUD_ECS / PKCS7+AWS_EC2 / OIDC+KUBERNETES / OIDC+GOOGLE_VM / OIDC+AZURE_VM，
// 其余取值配置时报 UnsupportedClientDeployEnvironment。
type ClientDeployEnvironmentEnum string

const (
	// ClientDeployEnvironmentCommon 通用环境：仅支持基于环境变量的 client assertion
	ClientDeployEnvironmentCommon ClientDeployEnvironmentEnum = "COMMON"
	// ClientDeployEnvironmentComputer 个人电脑/工作站（开发模式）
	ClientDeployEnvironmentComputer ClientDeployEnvironmentEnum = "COMPUTER"
	// ClientDeployEnvironmentKubernetes Kubernetes 集群（OIDC 认证使用 SA Token）
	ClientDeployEnvironmentKubernetes ClientDeployEnvironmentEnum = "KUBERNETES"
	// ClientDeployEnvironmentAlibabaCloudEcs 阿里云 ECS 实例（PKCS7 认证使用元数据服务签名）
	ClientDeployEnvironmentAlibabaCloudEcs ClientDeployEnvironmentEnum = "ALIBABA_CLOUD_ECS"
	// ClientDeployEnvironmentAlibabaCloudEci 阿里云 ECI 弹性容器实例
	ClientDeployEnvironmentAlibabaCloudEci ClientDeployEnvironmentEnum = "ALIBABA_CLOUD_ECI"
	// ClientDeployEnvironmentAlibabaCloudAck 阿里云 ACK 容器服务
	ClientDeployEnvironmentAlibabaCloudAck ClientDeployEnvironmentEnum = "ALIBABA_CLOUD_ACK"
	// ClientDeployEnvironmentAwsEc2 AWS EC2 实例
	ClientDeployEnvironmentAwsEc2 ClientDeployEnvironmentEnum = "AWS_EC2"
	// ClientDeployEnvironmentAwsEks AWS EKS 服务（Elastic Kubernetes Service）
	ClientDeployEnvironmentAwsEks ClientDeployEnvironmentEnum = "AWS_EKS"
	// ClientDeployEnvironmentGoogleVm Google Cloud VM
	ClientDeployEnvironmentGoogleVm ClientDeployEnvironmentEnum = "GOOGLE_VM"
	// ClientDeployEnvironmentHuaweiCloudEcs 华为云 ECS
	ClientDeployEnvironmentHuaweiCloudEcs ClientDeployEnvironmentEnum = "HUAWEI_CLOUD_ECS"
	// ClientDeployEnvironmentAzureVm Azure 虚拟机（OIDC 认证使用 IMDS Managed Identity 获取 ID Token）
	ClientDeployEnvironmentAzureVm ClientDeployEnvironmentEnum = "AZURE_VM"
	// ClientDeployEnvironmentCustom 自定义环境（用户需手动指定 provider）
	ClientDeployEnvironmentCustom ClientDeployEnvironmentEnum = "CUSTOM"
)
