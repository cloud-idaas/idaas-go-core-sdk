package authentication

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/aliyun/idaas-go-core-sdk/constants"
	"github.com/aliyun/idaas-go-core-sdk/domain"
	"github.com/aliyun/idaas-go-core-sdk/enums"
	"github.com/aliyun/idaas-go-core-sdk/errors"
	"github.com/aliyun/idaas-go-core-sdk/http"
)

// AlibabaCloudEcsAttestedDocumentProvider 阿里云 ECS PKCS7 attested document 提供者
//
// 与阿里云 Java SDK AlibabaCloudEcsAttestedDocumentProvider 完全对齐：
//  1. 通过 IMDSv2 协议从 ECS 元数据服务获取 attested document：
//     - PUT  http://100.100.100.200/latest/api/token （携带 X-aliyun-ecs-metadata-token-ttl-seconds 头）获取 metadata token
//     - GET  http://100.100.100.200/latest/dynamic/instance-identity/pkcs7?audience=<URL-encoded JSON>
//     （在 X-aliyun-ecs-metadata-token 头中携带上一步取到的 metadata token）
//  2. audience 参数为 URL-encoded 的 JSON：{"aud": idaasInstanceId, "signingTime": <unix秒>}
//  3. 调用方需自行实现缓存策略（本实现每次调用都重新签发，配合上层 cache 层使用）
//
// 适用场景：authnMethod = PKCS7、clientDeployEnvironment = ALIBABA_CLOUD_ECS
type AlibabaCloudEcsAttestedDocumentProvider struct {
	httpClient                      http.HttpClient
	tokenUrl                        string
	pkcs7UrlTemplate                string
	idaasInstanceId                 string
	defaultDocumentEffectiveSeconds int
}

// NewAlibabaCloudEcsAttestedDocumentProvider 创建 AlibabaCloudEcsAttestedDocumentProvider
//
// idaasInstanceId：IDaaS EIAM 实例 ID，作为 audience.aud 写入 attested document（必填）
// ttlSeconds：attested document 有效期（秒），传 0 时使用默认值 3600。合法范围 (1200, 1314000]
func NewAlibabaCloudEcsAttestedDocumentProvider(httpClient http.HttpClient, idaasInstanceId string, ttlSeconds int) *AlibabaCloudEcsAttestedDocumentProvider {
	if ttlSeconds <= 0 {
		ttlSeconds = constants.DefaultEcsAttestedDocumentTtlSeconds
	}
	return &AlibabaCloudEcsAttestedDocumentProvider{
		httpClient:                      httpClient,
		tokenUrl:                        constants.EcsMetadataServiceUrl,
		pkcs7UrlTemplate:                constants.EcsPkcs7AttestedDocumentUrlTemplate,
		idaasInstanceId:                 idaasInstanceId,
		defaultDocumentEffectiveSeconds: ttlSeconds,
	}
}

// GetAttestedDocument 获取 PKCS7 attested document
func (p *AlibabaCloudEcsAttestedDocumentProvider) GetAttestedDocument() (string, error) {
	if p.idaasInstanceId == "" {
		return "", errors.NewConfigError("IDaaSInstanceIdNotFound", "idaasInstanceId is required for PKCS7 attested document signing", nil)
	}

	// 第一步：获取 IMDSv2 metadata token
	metadataToken, err := p.fetchMetadataToken()
	if err != nil {
		return "", err
	}

	// 第二步：构造 audience JSON 并 URL 编码
	signingTime := time.Now().Unix()
	audienceJson, err := json.Marshal(map[string]interface{}{
		"aud":         p.idaasInstanceId,
		"signingTime": signingTime,
	})
	if err != nil {
		return "", errors.NewEncodingError("EncodingError", "Failed to marshal audience JSON", err)
	}
	audienceEncoded := url.QueryEscape(string(audienceJson))
	pkcs7Url := fmt.Sprintf(p.pkcs7UrlTemplate, audienceEncoded)

	// 第三步：携带 metadata token 请求 PKCS7 attested document
	docResp, err := p.httpClient.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    pkcs7Url,
		Headers: map[string]string{
			constants.HeaderXAliyunEcsMetadataToken: metadataToken,
		},
	})
	if err != nil {
		return "", err
	}
	if !docResp.IsSuccess() {
		return "", errors.NewHttpError(
			"ClientError",
			fmt.Sprintf("Failed to fetch ECS PKCS7 attested document (HTTP %d): %s", docResp.StatusCode, string(docResp.Body)),
			docResp.StatusCode,
			nil,
		)
	}
	return string(docResp.Body), nil
}

// fetchMetadataToken 通过 IMDSv2 协议获取 metadata token
func (p *AlibabaCloudEcsAttestedDocumentProvider) fetchMetadataToken() (string, error) {
	tokenResp, err := p.httpClient.Execute(&domain.HttpRequest{
		Method: enums.HttpMethodPut,
		URL:    p.tokenUrl,
		Headers: map[string]string{
			constants.HeaderXAliyunEcsMetadataTokenTtlSeconds: strconv.Itoa(p.defaultDocumentEffectiveSeconds),
		},
	})
	if err != nil {
		return "", err
	}
	if !tokenResp.IsSuccess() {
		return "", errors.NewHttpError(
			"ClientError",
			fmt.Sprintf("Failed to fetch ECS IMDSv2 metadata token (HTTP %d): %s", tokenResp.StatusCode, string(tokenResp.Body)),
			tokenResp.StatusCode,
			nil,
		)
	}
	return string(tokenResp.Body), nil
}
