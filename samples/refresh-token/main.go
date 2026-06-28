// Sample: 使用 Refresh Token 续期 Access Token
//
// 场景说明：
//
//	当 Access Token 即将过期时，使用之前签发的 Refresh Token
//	直接向 token endpoint 换取新的 Access Token，无需重新认证。
//	常用于 Device Code、Authorization Code 等带 refresh_token 返回的流程。
//
// 工作流程：
//   - SDK 调用 token endpoint，提交：
//     grant_type    = refresh_token
//     refresh_token = <上一次拿到的 refresh_token>
//     client_id     = <应用 ID>
//
// 前置条件：
//  1. 配置文件中已配置 clientId 与 tokenEndpoint
//  2. 已通过其它方式（如 Device Code）拿到过 refresh_token
//
// 运行方式：
//
//	export IDAAS_REFRESH_TOKEN=<your_refresh_token>
//	go run ./samples/refresh-token
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aliyun/idaas-go-core-sdk/config"
	"github.com/aliyun/idaas-go-core-sdk/factory"
	"github.com/aliyun/idaas-go-core-sdk/http"
	"github.com/aliyun/idaas-go-core-sdk/oauth2"
)

func main() {
	configPath := flag.String("config", "", "path to IDaaS client config file; empty means use default priority")
	flag.Parse()

	// 1. 加载配置（仅用于读取 clientId 与 tokenEndpoint）
	reader := config.NewConfigReader()
	cfg, err := reader.LoadWithPriority(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. 初始化工厂（确保 cfg 字段经过校验）
	factoryInstance := factory.GetInstance()
	if err = factoryInstance.Initialize(cfg); err != nil {
		log.Fatalf("Failed to initialize factory: %v", err)
	}

	// 3. 从环境变量获取 refresh_token
	refreshToken := os.Getenv("IDAAS_REFRESH_TOKEN")
	if refreshToken == "" {
		log.Fatal("IDAAS_REFRESH_TOKEN env var is required")
	}

	// 4. 直接调用 OAuth2TokenUtil 完成 refresh_token 续期
	tokenUtil := oauth2.NewOAuth2TokenUtil(newHttpClientFromConfig(cfg))

	fmt.Println("Refreshing access token via refresh_token grant...")
	tokenResp, err := tokenUtil.RefreshToken(
		cfg.TokenEndpoint,
		cfg.ClientId,
		refreshToken,
	)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}

	fmt.Println("New Access Token:")
	fmt.Println(maskToken(tokenResp.GetAccessToken()))
	fmt.Printf("Token Type:    %s\n", tokenResp.GetTokenType())
	fmt.Printf("Expires In:    %d seconds\n", tokenResp.GetExpiresIn())
	if refreshToken := tokenResp.GetRefreshToken(); refreshToken != "" {
		fmt.Printf("Refresh Token: %s\n", maskToken(refreshToken))
	}
}

func newHttpClientFromConfig(cfg *config.IDaaSClientConfig) http.HttpClient {
	if cfg.HttpConfiguration == nil {
		return http.NewDefaultHttpClient(0, 0)
	}
	return http.NewDefaultHttpClientWithOptions(
		cfg.HttpConfiguration.ConnectTimeout,
		cfg.HttpConfiguration.ReadTimeout,
		cfg.HttpConfiguration.UnsafeIgnoreSSLCert,
	)
}

func maskToken(token string) string {
	if len(token) <= 12 {
		return "***"
	}
	return token[:6] + "..." + token[len(token)-6:]
}
