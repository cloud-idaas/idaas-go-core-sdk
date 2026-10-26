package factory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// capturedRequest 是一次 token 请求被记录下来的 form 与 header。
type capturedRequest struct {
	form    url.Values
	headers map[string]string
}

// requestCapturingHttpClient 记录每次请求的 form 与 header，并返回一个合法的 token 响应。
// metadata 非空时，先交给它处理（用于 mock ECS 元数据服务等非 token endpoint 请求），
// 返回非 nil 响应则不记录到 requests。
type requestCapturingHttpClient struct {
	mu       sync.Mutex
	requests []capturedRequest
	metadata func(req *domain.HttpRequest) *domain.HttpResponse
}

func (c *requestCapturingHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return c.ExecuteContext(context.Background(), req)
}

func (c *requestCapturingHttpClient) ExecuteContext(_ context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	if c.metadata != nil {
		if resp := c.metadata(req); resp != nil {
			return resp, nil
		}
	}
	form, err := url.ParseQuery(fmt.Sprint(req.Body))
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.requests = append(c.requests, capturedRequest{form: form, headers: req.Headers})
	c.mu.Unlock()
	return &domain.HttpResponse{
		StatusCode: 200,
		Body:       []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`),
	}, nil
}

func (c *requestCapturingHttpClient) Get(string, map[string]string) (*domain.HttpResponse, error) {
	return nil, fmt.Errorf("unexpected GET")
}

func (c *requestCapturingHttpClient) Post(string, map[string]string, interface{}) (*domain.HttpResponse, error) {
	return nil, fmt.Errorf("unexpected Post")
}

func (c *requestCapturingHttpClient) last(t *testing.T) capturedRequest {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.requests) == 0 {
		t.Fatal("no request captured")
	}
	return c.requests[len(c.requests)-1]
}

// setupExchangeFactory 用 cfg 初始化 factory，并把 http client 换成捕获 client。
func setupExchangeFactory(t *testing.T, cfg *config.IDaaSClientConfig) (*IDaaSCredentialProviderFactory, *requestCapturingHttpClient) {
	t.Helper()
	f := GetInstance()
	if err := f.Initialize(cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	capture := &requestCapturingHttpClient{}
	f.mu.Lock()
	f.httpClient = capture
	f.providers = make(map[string]provider.IDaaSCredentialProvider)
	f.exchangeProviders = make(map[string]provider.IDaaSTokenExchangeCredentialProvider)
	f.mu.Unlock()
	return f, capture
}

func exchange(t *testing.T, f *IDaaSCredentialProviderFactory, scope string, req provider.TokenExchangeRequest) {
	t.Helper()
	p, err := f.GetIDaaSTokenExchangeCredentialProviderByScope(scope)
	if err != nil {
		t.Fatalf("GetIDaaSTokenExchangeCredentialProviderByScope failed: %v", err)
	}
	if _, err := p.ExchangeToken(req); err != nil {
		t.Fatalf("ExchangeToken failed: %v", err)
	}
}

func assertExchangeFields(t *testing.T, form url.Values, wantScope string) {
	t.Helper()
	if got := form.Get(constants.ParamGrantType); got != constants.GrantTypeTokenExchange {
		t.Errorf("grant_type = %q, want token-exchange", got)
	}
	if got := form.Get(constants.ParamSubjectToken); got != "subject-at" {
		t.Errorf("subject_token = %q", got)
	}
	if got := form.Get(constants.ParamScope); got != wantScope {
		t.Errorf("scope = %q, want %q", got, wantScope)
	}
}

// TestTokenExchange_PrivateKeyJwt 回归：private_key_jwt 应用必须能做 token exchange，
// 并用 jwt-bearer client_assertion 认证客户端（与 Java 一致）。修复前 factory 直接拒绝。
func TestTokenExchange_PrivateKeyJwt(t *testing.T) {
	Reset()
	defer Reset()
	generatePrivateKeyEnv(t, "TEST_EXCHANGE_PK")

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPrivateKeyJwt
	cfg.AuthnConfiguration.PrivateKeyEnvVarName = "TEST_EXCHANGE_PK"
	f, capture := setupExchangeFactory(t, cfg)

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	got := capture.last(t)
	if v := got.form.Get(constants.ParamClientAssertionType); v != constants.AssertionTypeJwtBearer {
		t.Errorf("client_assertion_type = %q, want %q", v, constants.AssertionTypeJwtBearer)
	}
	if got.form.Get(constants.ParamClientAssertion) == "" {
		t.Error("client_assertion is empty")
	}
	if got.form.Get(constants.ParamClientID) != cfg.ClientId {
		t.Errorf("client_id = %q", got.form.Get(constants.ParamClientID))
	}
	if got.form.Has(constants.ParamClientSecret) {
		t.Error("client_secret must not be sent for private_key_jwt")
	}
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_ClientSecretBasic 回归：client_secret_basic 必须用 Authorization: Basic
// 认证，secret 不得出现在 form 里。修复前 secret 以 client_secret_post 方式放进 form。
func TestTokenExchange_ClientSecretBasic(t *testing.T) {
	Reset()
	defer Reset()
	t.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret")

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodClientSecretBasic
	f, capture := setupExchangeFactory(t, cfg)

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	got := capture.last(t)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.ClientId+":test_secret"))
	if h := got.headers["Authorization"]; h != want {
		t.Errorf("Authorization = %q, want %q", h, want)
	}
	if got.form.Has(constants.ParamClientSecret) {
		t.Error("client_secret must not be sent in the form for client_secret_basic")
	}
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_ClientSecretBasic_Rfc6749FormUrlencode 回归 P3 / RFC 6749 §2.3.1:
// client_id 与 client_secret 在拼接前必须各自做 application/x-www-form-urlencoded 编码。
// 含 ':' / '+' / 空格等特殊字符的凭证若不做编码,基本头会被 ':' 截断或被 + 误解析。
func TestTokenExchange_ClientSecretBasic_Rfc6749FormUrlencode(t *testing.T) {
	Reset()
	defer Reset()
	// secret 含需要编码的字符:冒号会与 basic 头的分隔符冲突,+ 在 form-urlencoded 里是空格。
	t.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "p:ss+word=1")

	cfg := validTestConfig()
	// clientId 也含特殊字符,验证两端都被编码而非只编码 secret。
	cfg.ClientId = "app+user:special"
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodClientSecretBasic
	f, capture := setupExchangeFactory(t, cfg)

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	got := capture.last(t)
	// 期望:对 id 和 secret 各自 QueryEscape 后再拼接,再 base64。
	want := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape("app+user:special")+":"+url.QueryEscape("p:ss+word=1")))
	if h := got.headers["Authorization"]; h != want {
		t.Errorf("Authorization = %q, want %q (RFC 6749 §2.3.1 form-urlencoded)", h, want)
	}
	// 解码 base64 后,payload 里应保留各自身份的 form-urlencoded 形式
	// (id 与 secret 各自被编码,而非整体裸拼接)。
	raw := got.headers["Authorization"]
	b64 := strings.TrimPrefix(raw, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode basic header: %v", err)
	}
	if wantDecoded := url.QueryEscape("app+user:special") + ":" + url.QueryEscape("p:ss+word=1"); string(decoded) != wantDecoded {
		t.Errorf("decoded basic payload = %q, want %q", string(decoded), wantDecoded)
	}
	// 裸 '+' 必须被编码成 %2B(否则 form-urlencoded 里 '+' 等同于空格)。
	if strings.Contains(string(decoded), "+") {
		t.Errorf("found unescaped '+' in decoded basic payload: %q", string(decoded))
	}
}

// TestTokenExchange_ClientSecretJwt 回归：client_secret_jwt 发 HS256 client_assertion，
// 而不是把明文 secret 放进 form。
func TestTokenExchange_ClientSecretJwt(t *testing.T) {
	Reset()
	defer Reset()
	t.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "test_secret_that_is_long_enough_for_hs256")

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodClientSecretJwt
	f, capture := setupExchangeFactory(t, cfg)

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	got := capture.last(t)
	if v := got.form.Get(constants.ParamClientAssertionType); v != constants.AssertionTypeJwtBearer {
		t.Errorf("client_assertion_type = %q", v)
	}
	if got.form.Get(constants.ParamClientAssertion) == "" {
		t.Error("client_assertion is empty")
	}
	if got.form.Has(constants.ParamClientSecret) {
		t.Error("client_secret must not be sent in the form for client_secret_jwt")
	}
}

// TestTokenExchange_ReadsSecretPerRequestAndBindsScope 回归：
//   - secret 每次请求时读取（轮换 env 后无需重建 provider，与 machine provider 一致）；
//   - req.Scope 为空时使用 provider 绑定的 scope，ByScope("") 绑定 config.Scope。
func TestTokenExchange_ReadsSecretPerRequestAndBindsScope(t *testing.T) {
	Reset()
	defer Reset()
	t.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "secret-1")

	cfg := validTestConfig()
	f, capture := setupExchangeFactory(t, cfg)

	const bound = "api://other.example.com|write"
	exchange(t, f, bound, provider.TokenExchangeRequest{SubjectToken: "subject-at"})
	if got := capture.last(t); got.form.Get(constants.ParamClientSecret) != "secret-1" {
		t.Errorf("client_secret = %q, want secret-1", got.form.Get(constants.ParamClientSecret))
	} else {
		assertExchangeFields(t, got.form, bound)
	}

	os.Setenv("CLOUD_IDAAS_CLIENT_SECRET", "secret-2")
	exchange(t, f, bound, provider.TokenExchangeRequest{SubjectToken: "subject-at", Scope: "explicit"})
	got := capture.last(t)
	if got.form.Get(constants.ParamClientSecret) != "secret-2" {
		t.Errorf("client_secret = %q, want secret-2 (secret must be read per request)", got.form.Get(constants.ParamClientSecret))
	}
	assertExchangeFields(t, got.form, "explicit")

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})
	assertExchangeFields(t, capture.last(t).form, cfg.Scope)
}

// generatePrivateKeyEnv 生成 RSA 私钥并以 PKCS8 PEM 写入环境变量 name。
func generatePrivateKeyEnv(t *testing.T, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(name, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
}

// assertFederatedAssertion 校验联邦类认证方式的公共字段：assertion type / assertion /
// application_federated_credential_name，且不发送 client_secret。
func assertFederatedAssertion(t *testing.T, form url.Values, wantType, wantAssertion, wantCredName string) {
	t.Helper()
	if v := form.Get(constants.ParamClientAssertionType); v != wantType {
		t.Errorf("client_assertion_type = %q, want %q", v, wantType)
	}
	assertion := form.Get(constants.ParamClientAssertion)
	if assertion == "" {
		t.Error("client_assertion is empty")
	} else if wantAssertion != "" && assertion != wantAssertion {
		t.Errorf("client_assertion = %q, want %q", assertion, wantAssertion)
	}
	if v := form.Get(constants.ParamApplicationFederatedCredentialName); v != wantCredName {
		t.Errorf("application_federated_credential_name = %q, want %q", v, wantCredName)
	}
	if form.Has(constants.ParamClientSecret) {
		t.Error("client_secret must not be sent for federated authn methods")
	}
}

// TestTokenExchange_PCA 回归：PCA 应用 token exchange 发 x509-jwt-bearer assertion，
// 并携带 client_x509 / client_x509_chain / federated credential name（与 machine PCA 路径一致）。
func TestTokenExchange_PCA(t *testing.T) {
	Reset()
	defer Reset()
	generatePrivateKeyEnv(t, "TEST_EXCHANGE_PCA_PK")

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPca
	cfg.AuthnConfiguration.PrivateKeyEnvVarName = "TEST_EXCHANGE_PCA_PK"
	cfg.AuthnConfiguration.ClientX509Certificate = "PEM_LEAF_CERT"
	cfg.AuthnConfiguration.X509CertChains = "PEM_CHAIN"
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "pca-cred"
	f, capture := setupExchangeFactory(t, cfg)

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	got := capture.last(t)
	assertFederatedAssertion(t, got.form, constants.AssertionTypeX509JwtBearer, "", "pca-cred")
	if v := got.form.Get(constants.ParamClientX509); v != "PEM_LEAF_CERT" {
		t.Errorf("client_x509 = %q", v)
	}
	if v := got.form.Get(constants.ParamClientX509Chain); v != "PEM_CHAIN" {
		t.Errorf("client_x509_chain = %q", v)
	}
	if got.form.Get(constants.ParamClientID) != cfg.ClientId {
		t.Errorf("client_id = %q", got.form.Get(constants.ParamClientID))
	}
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_Pkcs7Ecs 回归：PKCS7 (ALIBABA_CLOUD_ECS) 应用 token exchange 时，
// 先经 IMDSv2 拿 metadata token、再取 attested document，作为 pkcs7-bearer assertion 发送。
func TestTokenExchange_Pkcs7Ecs(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
	cfg.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAlibabaCloudEcs
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "ecs-cred"
	f, capture := setupExchangeFactory(t, cfg)

	var docRequestToken string
	capture.metadata = func(req *domain.HttpRequest) *domain.HttpResponse {
		switch {
		case req.URL == constants.EcsMetadataServiceUrl:
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("imds-token")}
		case strings.HasPrefix(req.URL, "http://100.100.100.200/latest/dynamic/instance-identity/pkcs7"):
			docRequestToken = req.Headers[constants.HeaderXAliyunEcsMetadataToken]
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("pkcs7-doc")}
		}
		return nil
	}

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	if docRequestToken != "imds-token" {
		t.Errorf("attested document request token header = %q, want imds-token", docRequestToken)
	}
	got := capture.last(t)
	assertFederatedAssertion(t, got.form, constants.AssertionTypePkcs7Bearer, "pkcs7-doc", "ecs-cred")
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_OidcComputer 回归：OIDC (COMPUTER) 应用 token exchange 时，
// 从配置的文件读取 OIDC token，作为 id-token-bearer assertion 发送；
// token 每次请求时读取，文件轮换后无需重建 provider。
func TestTokenExchange_OidcComputer(t *testing.T) {
	Reset()
	defer Reset()
	tokenFile := filepath.Join(t.TempDir(), "oidc-token")
	if err := os.WriteFile(tokenFile, []byte("oidc-token-1"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
	cfg.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentComputer
	cfg.AuthnConfiguration.OidcTokenFilePath = tokenFile
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "oidc-cred"
	f, capture := setupExchangeFactory(t, cfg)

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})
	got := capture.last(t)
	assertFederatedAssertion(t, got.form, constants.AssertionTypeIdTokenBearer, "oidc-token-1", "oidc-cred")
	assertExchangeFields(t, got.form, cfg.Scope)

	if err := os.WriteFile(tokenFile, []byte("oidc-token-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})
	if v := capture.last(t).form.Get(constants.ParamClientAssertion); v != "oidc-token-2" {
		t.Errorf("client_assertion = %q, want oidc-token-2 (token must be read per request)", v)
	}
}

// TestTokenExchange_Pkcs7AwsEc2 回归：PKCS7 (AWS_EC2) 走 IMDSv2：
// PUT 拿 metadata token，再带 token GET PKCS7 签名，作为 pkcs7-bearer assertion 发送。
func TestTokenExchange_Pkcs7AwsEc2(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
	cfg.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAwsEc2
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "ec2-cred"
	f, capture := setupExchangeFactory(t, cfg)

	var ttlHeader, docRequestToken string
	capture.metadata = func(req *domain.HttpRequest) *domain.HttpResponse {
		switch req.URL {
		case constants.Ec2MetadataServiceUrl:
			ttlHeader = req.Headers[constants.HeaderXAwsEc2MetadataTokenTtlSeconds]
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("ec2-imds-token")}
		case constants.Ec2Pkcs7Url:
			docRequestToken = req.Headers[constants.HeaderXAwsEc2MetadataToken]
			return &domain.HttpResponse{StatusCode: 200, Body: []byte("ec2-pkcs7-sig")}
		}
		return nil
	}

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	if ttlHeader == "" {
		t.Error("IMDSv2 token request missing ttl header")
	}
	if docRequestToken != "ec2-imds-token" {
		t.Errorf("PKCS7 request token header = %q, want ec2-imds-token", docRequestToken)
	}
	got := capture.last(t)
	assertFederatedAssertion(t, got.form, constants.AssertionTypePkcs7Bearer, "ec2-pkcs7-sig", "ec2-cred")
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_OidcKubernetes 回归：OIDC (KUBERNETES) 从 oidcTokenFilePathEnvVarName
// 指向的文件读取 service account token，作为 id-token-bearer assertion 发送。
func TestTokenExchange_OidcKubernetes(t *testing.T) {
	Reset()
	defer Reset()
	tokenFile := filepath.Join(t.TempDir(), "sa-token")
	if err := os.WriteFile(tokenFile, []byte("k8s-sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_EXCHANGE_K8S_TOKEN_PATH", tokenFile)

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
	cfg.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentKubernetes
	cfg.AuthnConfiguration.OidcTokenFilePathEnvVarName = "TEST_EXCHANGE_K8S_TOKEN_PATH"
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "k8s-cred"
	f, capture := setupExchangeFactory(t, cfg)

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	got := capture.last(t)
	assertFederatedAssertion(t, got.form, constants.AssertionTypeIdTokenBearer, "k8s-sa-token", "k8s-cred")
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_OidcGoogleVm 回归：OIDC (GOOGLE_VM) 从 GCP 元数据服务取 identity token，
// audience 为 issuer 的 origin，请求必须带 Metadata-Flavor: Google。
func TestTokenExchange_OidcGoogleVm(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
	cfg.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentGoogleVm
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "gcp-cred"
	f, capture := setupExchangeFactory(t, cfg)

	wantURL := fmt.Sprintf(constants.GcpVmIdentityTokenUrlTemplate, url.QueryEscape("https://test.example.com"))
	var flavor string
	capture.metadata = func(req *domain.HttpRequest) *domain.HttpResponse {
		if req.URL != wantURL {
			return nil
		}
		flavor = req.Headers[constants.HeaderMetadataFlavor]
		return &domain.HttpResponse{StatusCode: 200, Body: []byte("gcp-id-token\n")}
	}

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	if flavor != constants.HeaderMetadataFlavorValueGoogle {
		t.Errorf("Metadata-Flavor = %q, want Google (or metadata URL/audience mismatch, want %s)", flavor, wantURL)
	}
	got := capture.last(t)
	assertFederatedAssertion(t, got.form, constants.AssertionTypeIdTokenBearer, "gcp-id-token", "gcp-cred")
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_OidcAzureVm 回归：OIDC (AZURE_VM) 从 IMDS Managed Identity 取 token
// （JSON 响应中的 access_token），请求必须带 Metadata: true。
func TestTokenExchange_OidcAzureVm(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodOidc
	cfg.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAzureVm
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "azure-cred"
	f, capture := setupExchangeFactory(t, cfg)

	wantURL := fmt.Sprintf(constants.AzureVmIdentityTokenUrlTemplate, url.QueryEscape(constants.AzureVmManagementResource))
	var metadataHeader string
	capture.metadata = func(req *domain.HttpRequest) *domain.HttpResponse {
		if req.URL != wantURL {
			return nil
		}
		metadataHeader = req.Headers[constants.HeaderMetadata]
		return &domain.HttpResponse{
			StatusCode: 200,
			Body:       []byte(`{"access_token":"azure-id-token","expires_in":"3600","token_type":"Bearer"}`),
		}
	}

	exchange(t, f, "", provider.TokenExchangeRequest{SubjectToken: "subject-at"})

	if metadataHeader != constants.HeaderMetadataValueTrue {
		t.Errorf("Metadata header = %q, want true (or IMDS URL mismatch, want %s)", metadataHeader, wantURL)
	}
	got := capture.last(t)
	assertFederatedAssertion(t, got.form, constants.AssertionTypeIdTokenBearer, "azure-id-token", "azure-cred")
	assertExchangeFields(t, got.form, cfg.Scope)
}

// TestTokenExchange_FederatedCredentialFetchFailure 回归：联邦凭证（此处为 ECS PKCS7）获取失败时，
// ExchangeToken 返回错误，且不会带着缺失的 assertion 去请求 token endpoint。
func TestTokenExchange_FederatedCredentialFetchFailure(t *testing.T) {
	Reset()
	defer Reset()

	cfg := validTestConfig()
	cfg.AuthnConfiguration.AuthnMethod = enums.TokenAuthnMethodPkcs7
	cfg.AuthnConfiguration.ClientDeployEnvironment = enums.ClientDeployEnvironmentAlibabaCloudEcs
	cfg.AuthnConfiguration.ApplicationFederatedCredentialName = "ecs-cred"
	f, capture := setupExchangeFactory(t, cfg)
	capture.metadata = func(req *domain.HttpRequest) *domain.HttpResponse {
		if strings.HasPrefix(req.URL, "http://100.100.100.200/") {
			return &domain.HttpResponse{StatusCode: 500, Body: []byte("imds unavailable")}
		}
		return nil
	}

	p, err := f.GetIDaaSTokenExchangeCredentialProviderByScope("")
	if err != nil {
		t.Fatalf("GetIDaaSTokenExchangeCredentialProviderByScope failed: %v", err)
	}
	if _, err := p.ExchangeToken(provider.TokenExchangeRequest{SubjectToken: "subject-at"}); err == nil {
		t.Fatal("expected error when attested document cannot be fetched")
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.requests) != 0 {
		t.Errorf("token endpoint must not be called on credential fetch failure, got %d request(s)", len(capture.requests))
	}
}
