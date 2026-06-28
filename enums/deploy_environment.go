package enums

// ClientDeployEnvironmentEnum 部署环境枚举
//
// 对应 IDaaS 配置文件中 authnConfiguration.clientDeployEnvironment 字段，
// 与阿里云 Java SDK ClientDeployEnvironmentEnum 完全一致（共 11 个值）。
//
// 注意：枚举值定义齐全是为了与 Java SDK 对齐、以及为未来扩展预留；
// 当前 SDK 实际支持的运行时分支为：
//   - PKCS7 认证 + ALIBABA_CLOUD_ECS：从阿里云 ECS 元数据服务（IMDSv2）获取 PKCS7 attested document
//   - PKCS7 认证 + AWS_EC2：从 AWS EC2 元数据服务（IMDSv2）获取实例身份文档 + PKCS7 签名
//   - OIDC 认证 + KUBERNETES：从 Service Account Token 文件读取 OIDC token
//   - OIDC 认证 + GOOGLE_VM：从 GCP VM 元数据服务获取 ID Token
//   - OIDC 认证 + AZURE_VM：从 Azure VM IMDS 获取 Managed Identity ID Token
//
// 其他取值（如 ALIBABA_CLOUD_ACK / AWS_ESK 等）尚未实现具体 provider，
// 配置时会通过 UnsupportedClientDeployEnvironment 错误码报错。
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
	// ClientDeployEnvironmentAwsEsk AWS EKS 服务
	ClientDeployEnvironmentAwsEsk ClientDeployEnvironmentEnum = "AWS_ESK"
	// ClientDeployEnvironmentGoogleVm Google Cloud VM
	ClientDeployEnvironmentGoogleVm ClientDeployEnvironmentEnum = "GOOGLE_VM"
	// ClientDeployEnvironmentHuaweiCloudEcs 华为云 ECS
	ClientDeployEnvironmentHuaweiCloudEcs ClientDeployEnvironmentEnum = "HUAWEI_CLOUD_ECS"
	// ClientDeployEnvironmentAzureVm Azure 虚拟机（OIDC 认证使用 IMDS Managed Identity 获取 ID Token）
	ClientDeployEnvironmentAzureVm ClientDeployEnvironmentEnum = "AZURE_VM"
	// ClientDeployEnvironmentCustom 自定义环境（用户需手动指定 provider）
	ClientDeployEnvironmentCustom ClientDeployEnvironmentEnum = "CUSTOM"
)
