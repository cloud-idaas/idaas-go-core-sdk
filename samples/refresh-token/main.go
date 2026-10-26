// Sample: 使用 Refresh Token 续期 Access Token
//
// 场景说明：
//
//	当 Access Token 即将过期时，使用之前签发的 Refresh Token
//	直接向 token endpoint 换取新的 Access Token，无需重新认证。
//	常用于 Device Code、Authorization Code 等带 refresh_token 返回的流程。
//
// 工作流程：
// - SDK 调用 token endpoint，提交：
// grant_type = refresh_token
// refresh_token = <上一次拿到的 refresh_token>
// client_id = <应用 ID>
//
// 前置条件：
// 1. 配置文件中已配置 clientId 与 tokenEndpoint
// 2. 已通过其它方式（如 Device Code）拿到过 refresh_token
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

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/oauth2"
)

func main() {
	configPath := flag.String("config", "", "path to IDaaS client config file; empty means use default priority")
	flag.Parse()

	// 1. 加载配置（仅用于读取 clientId 与 tokenEndpoint，本 sample 直接调用 oauth2 而非走 factory provider）
	reader := config.NewConfigReader()
	cfg, err := reader.LoadWithPriority(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. 校验配置完整性（不走 factory.InitWithConfig，避免 HUMAN 配置 + 非空 scope
	//    触发后台预热——预热会启动 Device Code 流程并打开浏览器，但本 sample
	//    只用 OAuth2TokenUtil.RefreshToken 直接续期，不需要预热副作用）。
	//
	//    LoadWithPriority 不做端点归一化(裸 hostname 补 https://、
	//    http→https 升级),Validate 的 validateHttpsUrl 会拒绝裸 hostname。
	//    factory.Initialize 内部会自动归一化,但本 sample 跳过了 factory,
	//    需显式调用 NormalizeEndpoints。
	cfg.NormalizeEndpoints()
	validator := config.NewConfigValidator()
	if err = validator.Validate(cfg); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
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
