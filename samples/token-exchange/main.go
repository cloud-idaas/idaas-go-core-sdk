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

	"github.com/aliyun/idaas-go-core-sdk/config"
	"github.com/aliyun/idaas-go-core-sdk/factory"
	"github.com/aliyun/idaas-go-core-sdk/http"
	"github.com/aliyun/idaas-go-core-sdk/implementation"
)

func main() {
	configPath := flag.String("config", "", "path to IDaaS client config file; empty means use default priority")
	flag.Parse()

	// 1. 加载配置
	reader := config.NewConfigReader()
	cfg, err := reader.LoadWithPriority(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. 初始化工厂（顺带校验配置）
	factoryInstance := factory.GetInstance()
	if err = factoryInstance.Initialize(cfg); err != nil {
		log.Fatalf("Failed to initialize factory: %v", err)
	}

	// 3. 从环境变量获取 subject token（要被交换的原始 token）
	subjectToken := os.Getenv("IDAAS_SUBJECT_TOKEN")
	if subjectToken == "" {
		log.Fatal("IDAAS_SUBJECT_TOKEN env var is required")
	}

	// 4. 从配置指定的 env var 读取 client_secret
	if cfg.AuthnConfiguration == nil || cfg.AuthnConfiguration.ClientSecretEnvVarName == "" {
		log.Fatal("ClientSecretEnvVarName not configured; token exchange requires a client_secret auth config")
	}
	clientSecret := os.Getenv(cfg.AuthnConfiguration.ClientSecretEnvVarName)
	if clientSecret == "" {
		log.Fatalf("Client secret not found in env var: %s", cfg.AuthnConfiguration.ClientSecretEnvVarName)
	}

	// 5. 执行 token exchange
	tokenExchangeProvider := implementation.NewIDaaSMachineTokenExchangeCredentialProvider(
		cfg.ClientId,
		clientSecret,
		cfg.TokenEndpoint,
		newHttpClientFromConfig(cfg),
	)

	fmt.Println("Performing RFC 8693 token exchange...")
	cred, err := tokenExchangeProvider.ExchangeToken(subjectToken, "")
	if err != nil {
		log.Fatalf("Failed to exchange token: %v", err)
	}

	fmt.Println("Exchanged Access Token:")
	fmt.Println(maskToken(cred.GetAccessToken()))
	fmt.Printf("Token Type:    %s\n", cred.GetTokenType())
	fmt.Printf("Expires In:    %d seconds\n", cred.GetExpiresIn())
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
