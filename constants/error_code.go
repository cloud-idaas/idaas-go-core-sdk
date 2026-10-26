package constants

// ErrorCode 常量定义
// 配置类错误码
const (
	IDaaSCredentialProviderFactoryNotInit = "IDaaSCredentialProviderFactoryNotInit"
	IDaaSInstanceIdNotFound               = "IDaaSInstanceIdNotFound"
	ClientIdNotFound                      = "ClientIdNotFound"
	IssuerEndpointNotFound                = "IssuerEndpointNotFound"
	TokenEndpointNotFound                 = "TokenEndpointNotFound"
	AuthnConfigurationNotFound            = "AuthnConfigurationNotFound"
	DeviceAuthorizationEndpointNotFound   = "DeviceAuthorizationEndpointNotFound"
	LoadConfigFileFailed                  = "LoadConfigFileFailed"

	// ClientConfigurationNotFound 传入的 *config.IDaaSClientConfig 为 nil。
	// 单独成码而不是让 Validate 直接 panic：SDK 作为库被调用，
	// 任何输入都不应该让宿主进程崩溃 (NF-ROBUST)。
	ClientConfigurationNotFound = "ClientConfigurationNotFound"

	// InvalidEndpointScheme endpoint 的 scheme 非法。
	// 自 v0.1.0 起 SDK 仅接受 https —— 明文 http 会让 Bearer token 暴露在链路上，
	// 归一化（util.NormalizeEndpoint，裸 host 会补全为 https://）之后仍非 https 的一律拒绝启动。
	InvalidEndpointScheme = "InvalidEndpointScheme"
	// InvalidEndpointFormat endpoint 不是合法的绝对 URL（无法解析 / 缺少 host）。
	// 合并了早期设计中的 InvalidEndpointHost / InvalidEndpointUrl 等细分码：
	// 对调用方而言处置动作完全相同（修正配置里的 endpoint），不值得区分。
	InvalidEndpointFormat = "InvalidEndpointFormat"
	// InsecureTLSDisallowed 宿主启用 WithTLSEnforcement() 后,配置里
	// unsafeIgnoreSslCert=true 被硬拒("生产路径不可降级开启")。
	// 库无法判定"是否生产",故以 opt-in 硬拒 hook 形式给到生产宿主;默认不启用(零回归)。
	// Experimental:beta 阶段接入;GA 前若 enforcement 模型调整会变更。
	InsecureTLSDisallowed = "InsecureTLSDisallowed"
)

// 认证材料类错误码
const (
	ClientSecretEnvVarNameNotFound             = "ClientSecretEnvVarNameNotFound"
	PrivateKeyEnvVarNameNotFound               = "PrivateKeyEnvVarNameNotFound"
	ApplicationFederatedCredentialNameNotFound = "ApplicationFederatedCredentialNameNotFound"
	// ClientDeployEnvironmentNotFound 当 authnMethod 为 PKCS7/OIDC 但未提供 clientDeployEnvironment 时使用
	ClientDeployEnvironmentNotFound = "ClientDeployEnvironmentNotFound"
	ClientX509CertificateNotFound   = "ClientX509CertificateNotFound"
	X509CertChainsNotFound          = "X509CertChainsNotFound"
	PluginNameNotFound              = "PluginNameNotFound"
	OpenApiEndpointNotFound         = "OpenApiEndpointNotFound"
	// OidcTokenFilePathNotFound COMPUTER 部署环境下 OIDC 认证未配置 token 文件路径
	// （oidcTokenFilePath 与 oidcTokenFilePathEnvVarName 均为空，或环境变量取值为空）。
	OidcTokenFilePathNotFound = "OidcTokenFilePathNotFound"

	// 语义边界说明（与 *EnvVarNameNotFound 系列区分）：
	// *EnvVarNameNotFound —— 配置文件里没写"该从哪个环境变量读凭证"，属配置缺失，
	// 在 Validate 阶段（进程启动时）即可发现。
	// *NotFound（下列两个）—— 配置写了环境变量名，但运行时该环境变量为空/不存在，
	// 属部署环境问题，只能在取凭证时才暴露。
	// 两者的排查方向完全不同，故不合并。

	// ClientSecretNotFound 配置指定的环境变量存在名字但取不到 client secret 值。
	ClientSecretNotFound = "ClientSecretNotFound"
	// PrivateKeyNotFound 配置指定的环境变量存在名字但取不到私钥内容。
	PrivateKeyNotFound = "PrivateKeyNotFound"
	// PrivateKeyInvalid 私钥内容存在但无法解析为合法的 PEM / PKCS#8 私钥。
	PrivateKeyInvalid = "PrivateKeyInvalid"

	// SubjectTokenNotFound RFC 8693 令牌交换的 subject_token 为必填参数（REQUIRED），
	// 调用方传入空值时在 SDK 客户端即拒绝（ClientError，不发请求、不消耗服务端配额），
	// 与"服务端收到空值后拒绝"相比错误语义更早、更明确。
	SubjectTokenNotFound = "SubjectTokenNotFound"
)

// HTTP类错误码
const (
	ConnectTimeoutNotValid = "ConnectTimeoutNotValid"
	ReadTimeoutNotValid    = "ReadTimeoutNotValid"
	ConnectTimeOut         = "ConnectTimeOut"
	ReadTimeOut            = "ReadTimeOut"
	// InvalidURL 请求 URL 无法被 net/http 解析（相对路径、非法字符、缺少 scheme 等）。
	// 属调用方/配置问题，不可重试。
	InvalidURL = "InvalidURL"
	// DnsLookupFailed DNS 解析失败。目标主机名无法解析为 IP 地址，
	// 通常是网络隔离 / DNS 配置错误，与"超时"是不同的问题，不该误标为 ConnectTimeOut。
	DnsLookupFailed = "DnsLookupFailed"
	// TlsHandshakeFailed TLS 握手 / 证书校验失败。
	// 涵盖 x509.UnknownAuthorityError / CertificateInvalidError / HostnameError，
	// 对调用方而言处置动作是"检查 CA 证书链 / 端点证书 / 时钟偏移"，与超时完全不同。
	TlsHandshakeFailed = "TlsHandshakeFailed"
	// ConnectionReset 连接被对端重置 (TCP RST)。
	// 通常是服务端主动断开 / 负载均衡健康检查剔除，可重试但不应误标为超时。
	ConnectionReset = "ConnectionReset"
	// ResponseTruncated 响应体被意外截断 (io.ErrUnexpectedEOF / io.EOF before Content-Length)。
	// 与 ReadTimeOut 不同：超时是"读了一段时间还没读完"，截断是"对端在发完之前关了连接"。
	ResponseTruncated = "ResponseTruncated"
	// ResponseTooLarge 响应体超过客户端硬上限。
	// 防止恶意 / 故障服务返回超大响应拖垮进程内存;正常 token / 元数据响应远低于上限。
	ResponseTooLarge = "ResponseTooLarge"
)

// 运行时类错误码
const (
	InvalidScope                 = "InvalidScope"
	MultipleAudienceNotSupported = "MultipleAudienceNotSupported"
	// InvalidExpiresIn token 响应的 expires_in 非正数（0 或负值），会导致退化缓存。
	InvalidExpiresIn                = "InvalidExpiresIn"
	UnsupportedAuthenticationMethod = "UnsupportedAuthenticationMethod"
	// InvalidStaleValueBehavior staleValueBehavior 取值不在 BLOCK / ALLOW / REFRESH 之内。
	InvalidStaleValueBehavior = "InvalidStaleValueBehavior"
	// UnsupportedIdentityType identityType 取值不在 CLIENT / HUMAN 之内。
	UnsupportedIdentityType = "UnsupportedIdentityType"
	// UnsupportedPrivateKeyType 私钥类型不支持（仅支持 RSA / ECDSA）。
	UnsupportedPrivateKeyType = "UnsupportedPrivateKeyType"
	// EncodeFailed 编码/序列化失败。
	// 命名刻意避开 "EncodingError"：后者是 errors 包里的错误**类型**名，
	// 错误码与类型名同名会让日志与文档难以区分二者。
	EncodeFailed = "EncodeFailed"
	// UnsupportedClientDeployEnvironment 当 clientDeployEnvironment 取值不在已实现的白名单内时使用。
	// 当前支持的部署环境：ALIBABA_CLOUD_ECS / AWS_EC2 / KUBERNETES / GOOGLE_VM / AZURE_VM / COMPUTER。
	UnsupportedClientDeployEnvironment = "UnsupportedClientDeployEnvironment"
	RefreshTokenEmpty                  = "RefreshTokenEmpty"
	InvalidTokenType                   = "InvalidTokenType"
	AccessTokenNotFound                = "AccessTokenNotFound"
	ClientError                        = "ClientError"
	// ClientRequestCanceled 调用方在凭证请求完成前取消了 context(leader 同步刷新
	// 路径检测到 ctx.Done())。底层 ctx.Err() 经 %w 透传,调用方可
	// errors.Is(err, context.Canceled/DeadlineExceeded) 区分取消原因。
	// 客户端类。
	// Experimental:beta 阶段接入;GA 前若 ctx 取消语义统一化会调整包装层。
	ClientRequestCanceled = "ClientRequestCanceled"
	ServerError           = "ServerError"
	// OidcAudienceNotFound OIDC 联邦认证缺少 audience（依赖 issuer endpoint）。
	OidcAudienceNotFound = "OidcAudienceNotFound"
	// GcpVmIdentityTokenFetchFailed 从 GCP Metadata Service 获取 identity token 失败。
	GcpVmIdentityTokenFetchFailed = "GcpVmIdentityTokenFetchFailed"
	// GcpVmIdentityTokenEmpty GCP Metadata Service 返回的 identity token 为空。
	GcpVmIdentityTokenEmpty = "GcpVmIdentityTokenEmpty"
	// AzureVmIdentityTokenFetchFailed 从 Azure IMDS 获取 identity token 失败。
	AzureVmIdentityTokenFetchFailed = "AzureVmIdentityTokenFetchFailed"
	// AzureVmIdentityTokenInvalidJson Azure IMDS 返回的内容无法 JSON 解析。
	AzureVmIdentityTokenInvalidJson = "AzureVmIdentityTokenInvalidJson"
	// AzureVmIdentityTokenEmpty Azure IMDS 返回的 identity token 为空。
	AzureVmIdentityTokenEmpty = "AzureVmIdentityTokenEmpty"
	// UnexpectedError 兜底错误码，对应 errors.IDaaSUnexpectedError。
	// 出现它通常意味着 SDK 内部有未覆盖的分支，应当当作 bug 上报而不是在调用方重试。
	UnexpectedError = "UnexpectedError"
	// OAuth2Failed OAuth2 响应体里没有标准 error 字段时，errors.OAuth2Error 的兜底错误码。
	// 字面量保持 "OAuth2Error" 以兼容已有的调用方判定逻辑；
	// 常量名避开类型名 OAuth2Error，理由同 EncodeFailed。
	OAuth2Failed = "OAuth2Error"
)

// 插件类错误码
const (
	PluginNameEmpty         = "PluginNameEmpty"
	PluginAlreadyRegistered = "PluginAlreadyRegistered"
	PluginNotFound          = "PluginNotFound"
)

// 设备码 / 缓存类错误码
const (
	CachedResultNotFound = "CachedResultNotFound"
	// CachedResultStale 缓存凭证已过期但作为降级旧值返回时的错误码。
	CachedResultStale = "CachedResultStale"
	// CachedRefreshInBackoff 退避窗口内的刷新被短路返回错误(防 IdP 雪崩)。
	// 触发点:GetWithContext 的 BLOCK expired 分支检测到 inStaleBackoff(上次刷新失败
	// 后的退避窗未过)时返回 ErrRefreshInBackoff。BLOCK 硬保证"不返回过期值"仍成立
	// (返回错误非旧值)。调用方可 errors.Is 区分"退避中稍后重试" vs "硬刷新失败"。
	// Experimental:beta 阶段接入;退避窗固定 10s,指数退避留 GA 前。
	CachedRefreshInBackoff = "CachedRefreshInBackoff"
	// RefreshPanicRecovered 刷新 goroutine(leader 同步 worker / async worker)
	// 顶层 recover 捕获到 panic 时写入的错误码。缓存类。
	// recovered 值转 string 入 message,不入 kv(避免结构化字段被滥用)。
	// Experimental:beta 阶段接入;recover 语义对齐"所有 goroutine 须 recover"。
	RefreshPanicRecovered = "RefreshPanicRecovered"
	DeviceCodeTimeout     = "DeviceCodeTimeout"
)

// 并发类错误码
const (
	ConcurrentOperationFailed = "ConcurrentOperationFailed"
)
