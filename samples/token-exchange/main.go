// Sample: Token Exchange (RFC 8693)
//
// 将一个 subject token 交换为新作用域的 Access Token。
//
// 用法：
//
//	export IDAAS_CLIENT_SECRET='your_client_secret'
//	export IDAAS_SUBJECT_TOKEN='the_token_to_exchange'
//	go run ./samples/token-exchange -config /path/to/client_secret_post.json
//
// 配置必须包含 client_secret 类认证（authnMethod=client_secret_post/basic），
// SDK 才能从 ClientSecretEnvVarName 指定的环境变量读到 client_secret。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

func main() {
	configPath := flag.String("config", "", "path to IDaaS client config file; empty means use default priority")
	flag.Parse()

	// 1. 初始化工厂（包级函数，内部加载配置 + 幂等 + 预热；
	// token-exchange 仅支持 client_secret_* 认证方式，factory 会在创建
	// exchange provider 时从 env var 读取 client_secret）
	if err := factory.Init(*configPath); err != nil {
		log.Fatalf("Failed to initialize factory: %v", err)
	}

	// 2. 从环境变量获取 subject token（要被交换的原始 token）
	subjectToken := os.Getenv("IDAAS_SUBJECT_TOKEN")
	if subjectToken == "" {
		log.Fatal("IDAAS_SUBJECT_TOKEN env var is required")
	}

	// 3. 获取 token exchange provider（factory 内部已读取 client_secret）
	tokenExchangeProvider, err := factory.GetIDaaSTokenExchangeCredentialProvider()
	if err != nil {
		log.Fatalf("Failed to create token exchange provider: %v", err)
	}

	// 4. 执行 token exchange
	fmt.Println("Performing RFC 8693 token exchange...")
	cred, err := tokenExchangeProvider.ExchangeToken(provider.TokenExchangeRequest{
		SubjectToken: subjectToken,
	})
	if err != nil {
		log.Fatalf("Failed to exchange token: %v", err)
	}

	fmt.Println("Exchanged Access Token:")
	fmt.Println(maskToken(cred.GetAccessToken()))
	fmt.Printf("Token Type:    %s\n", cred.GetTokenType())
	fmt.Printf("Expires In:    %d seconds\n", cred.GetExpiresIn())
}

func maskToken(token string) string {
	if len(token) <= 12 {
		return "***"
	}
	return token[:6] + "..." + token[len(token)-6:]
}
