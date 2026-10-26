package authentication

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/util"
)

// AwsEc2AttestedDocumentProvider AWS EC2 PKCS7 attested document 提供者
//
// 通过 IMDSv2 协议从 EC2 元数据服务获取 PKCS7 签名：
// 1. PUT http://169.254.169.254/latest/api/token （携带 X-aws-ec2-metadata-token-ttl-seconds 头）获取 metadata token
// 2. GET http://169.254.169.254/latest/dynamic/instance-identity/pkcs7 获取 PKCS7 签名（多行 Base64）
//
// 注意：IMDS 返回的 PKCS7 是多行 Base64（每行约 76 字符），必须去除所有换行和空格合并为单行，
// 否则 IDaaS 服务端 Base64 解码时会报 "Illegal base64 character 20" 错误。
//
// 获取到的 PKCS7 签名通过统一的 client_credentials + pkcs7-bearer 方式提交给 IDaaS Token Endpoint，
// 与阿里云 ECS PKCS7 使用相同的提交协议。
//
// 适用场景：authnMethod = PKCS7、clientDeployEnvironment = AWS_EC2
type AwsEc2AttestedDocumentProvider struct {
	httpClient      http.HttpClient
	tokenUrl        string
	pkcs7Url        string
	tokenTtlSeconds int
}

// NewAwsEc2AttestedDocumentProvider 创建 AwsEc2AttestedDocumentProvider
//
// ttlSeconds：IMDSv2 metadata token 有效期（秒），传 0 时使用默认值 21600（6小时）
func NewAwsEc2AttestedDocumentProvider(httpClient http.HttpClient, ttlSeconds int) *AwsEc2AttestedDocumentProvider {
	if ttlSeconds <= 0 {
		ttlSeconds = constants.DefaultEc2MetadataTokenTtlSeconds
	}
	return &AwsEc2AttestedDocumentProvider{
		httpClient:      httpClient,
		tokenUrl:        constants.Ec2MetadataServiceUrl,
		pkcs7Url:        constants.Ec2Pkcs7Url,
		tokenTtlSeconds: ttlSeconds,
	}
}

// GetAttestedDocument 获取 EC2 PKCS7 attested document（实现 Pkcs7AttestedDocumentProvider 接口）
//
// 返回去除换行空格后的单行 Base64 PKCS7 签名
func (p *AwsEc2AttestedDocumentProvider) GetAttestedDocument() (string, error) {
	return p.GetAttestedDocumentWithContext(context.Background())
}

// GetAttestedDocumentWithContext 获取 EC2 PKCS7 attested document,带 context。
// ctx 透传到 EC2 元数据服务请求,使调用方可取消长时间挂起的 IMDS 调用。
func (p *AwsEc2AttestedDocumentProvider) GetAttestedDocumentWithContext(ctx context.Context) (string, error) {
	// Step 1: 获取 IMDSv2 metadata token
	metadataToken, err := p.fetchMetadataToken(ctx)
	if err != nil {
		return "", err
	}

	// Step 2: 获取 PKCS7 签名
	pkcs7Raw, err := p.fetchPkcs7(ctx, metadataToken)
	if err != nil {
		return "", err
	}

	// PKCS7 去除所有换行和空格，合并为单行 Base64
	return stripWhitespace(pkcs7Raw), nil
}

// fetchMetadataToken 通过 IMDSv2 协议获取 metadata token
func (p *AwsEc2AttestedDocumentProvider) fetchMetadataToken(ctx context.Context) (string, error) {
	resp, err := p.httpClient.ExecuteContext(ctx, &domain.HttpRequest{
		Method: enums.HttpMethodPut,
		URL:    p.tokenUrl,
		Headers: map[string]string{
			constants.HeaderXAwsEc2MetadataTokenTtlSeconds: strconv.Itoa(p.tokenTtlSeconds),
		},
	})
	if err != nil {
		return "", errors.NewHttpError(
			"Ec2MetadataTokenError",
			"Failed to fetch EC2 IMDSv2 metadata token: "+err.Error(),
			0,
			err,
		)
	}
	if !resp.IsSuccess() {
		return "", errors.NewHttpError(
			"Ec2MetadataTokenError",
			fmt.Sprintf("Failed to fetch EC2 IMDSv2 metadata token (HTTP %d): %s", resp.StatusCode, util.TruncateForError(resp.Body, 512)),
			resp.StatusCode,
			nil,
		)
	}
	return string(resp.Body), nil
}

// fetchPkcs7 携带 metadata token 请求 EC2 PKCS7 签名接口
func (p *AwsEc2AttestedDocumentProvider) fetchPkcs7(ctx context.Context, metadataToken string) (string, error) {
	resp, err := p.httpClient.ExecuteContext(ctx, &domain.HttpRequest{
		Method: enums.HttpMethodGet,
		URL:    p.pkcs7Url,
		Headers: map[string]string{
			constants.HeaderXAwsEc2MetadataToken: metadataToken,
		},
	})
	if err != nil {
		return "", errors.NewHttpError(
			"Ec2MetadataError",
			"Failed to fetch EC2 PKCS7 signature: "+err.Error(),
			0,
			err,
		)
	}
	if !resp.IsSuccess() {
		return "", errors.NewHttpError(
			"Ec2MetadataError",
			fmt.Sprintf("Failed to fetch EC2 PKCS7 signature (HTTP %d): %s", resp.StatusCode, util.TruncateForError(resp.Body, 512)),
			resp.StatusCode,
			nil,
		)
	}
	return string(resp.Body), nil
}

// stripWhitespace 去除字符串中所有空白字符（换行、回车、空格、制表符）
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
}
