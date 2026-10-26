// Sample: Device Code 流程（设备授权码）人类登录认证
//
// 场景说明：
//
//	适用于无键盘输入或受限输入设备（CLI 工具、智能电视、IoT 设备等）
//	的人类用户登录场景。SDK 输出 user_code 与验证 URL，用户在另一台
//	设备的浏览器中完成登录授权后，SDK 自动轮询 token endpoint，
//	解析 RFC 8628 标准错误（authorization_pending/slow_down/
//	access_denied/expired_token），直到拿到 Access Token。
//
// 配置示例（identityType 必须为 HUMAN；device code 为公共客户端流程，无需设置 authnMethod）：
//
//	{
//	  "idaasInstanceId": "idaas_xxx",
//	  "clientId": "app_xxx",
//	  "issuer": "https://your-idaas-instance.aliyuncs.com/api/v2/iauths_system/oauth2",
//	  "tokenEndpoint": "https://your-idaas-instance.aliyuncs.com/api/v2/iauths_system/oauth2/token",
//	  "deviceAuthorizationEndpoint": "https://your-idaas-instance.aliyuncs.com/api/v2/iauths_system/oauth2/device_authorization",
//	  "scope": "api://api.xxxxx.com|read:file",
//	  "authnConfiguration": {
//	    "identityType": "HUMAN",
//	    "humanAuthenticateClientId": "iap_developer"
//	  }
//	}
//
// 用法：
//
//	go run ./samples/device-code -config /path/to/human-config.json
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
	configPath := flag.String("config", "", "path to IDaaS client config file (identityType must be HUMAN); empty means use default priority")
	flag.Parse()

	// 1. 加载配置（仅用于提前校验 identityType，避免用户拿 CLIENT 配置跑 device flow 拿到一脸懵的 401）
	reader := config.NewConfigReader()
	cfg, err := reader.LoadWithPriority(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if cfg.AuthnConfiguration == nil || cfg.AuthnConfiguration.IdentityType != enums.AuthenticationIdentityHuman {
		log.Fatalf("device_code_sample requires identityType=HUMAN, got: %v",
			cfg.AuthnConfiguration)
	}

	// 2. 初始化工厂（包级函数，内部幂等，自带预热）
	if err = factory.InitWithConfig(cfg); err != nil {
		log.Fatalf("Failed to initialize factory: %v", err)
	}

	// 3. 创建凭证提供者（identityType=HUMAN 时走 Device Code 流程）
	credentialProvider, err := factory.GetIDaaSCredentialProvider()
	if err != nil {
		log.Fatalf("Failed to create credential provider: %v", err)
	}

	fmt.Println("Starting Device Code authorization flow...")
	fmt.Println("Please follow the verification URL printed below in any browser to complete login.")
	fmt.Println("This terminal will keep polling and print a masked Access Token once authorization completes.")
	fmt.Println()

	// 4. 触发 device flow（GetCredential 内部完成 polling）
	cred, err := credentialProvider.GetCredential()
	if err != nil {
		log.Fatalf("Failed to get credential: %v", err)
	}

	fmt.Println("\nAccess Token:")
	fmt.Println(maskToken(cred.GetAccessToken()))
	fmt.Printf("Token Type:    %s\n", cred.GetTokenType())
	fmt.Printf("Expires In:    %d seconds\n", cred.GetExpiresIn())
	if refreshToken := cred.GetRefreshToken(); refreshToken != "" {
		fmt.Printf("Refresh Token: %s\n", maskToken(refreshToken))
	}
}

func maskToken(token string) string {
	if len(token) <= 12 {
		return "***"
	}
	return token[:6] + "..." + token[len(token)-6:]
}
