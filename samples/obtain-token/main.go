// Sample: 通用 Access Token 获取入口
//
// 一个文件覆盖全部 7 种 CLIENT 身份认证方式：
//
//	client_secret_basic / client_secret_post / client_secret_jwt /
//	private_key_jwt    / pca / pkcs7 / oidc
//
// 支持两种模式：
//
//  1. 单配置模式 — 传入一个 -config 或走默认优先级
//  2. 多配置批量模式 — 传入多个配置文件路径（用逗号分隔或多次指定 -config），
//     依次加载并测试每个配置，汇总结果。适用于一次性验证多种 authnMethod。
//
// 用法：
//
//	go run ./samples/obtain-token                                            # 走默认优先级
//	go run ./samples/obtain-token -config /path/to/cfg.json                  # 单配置
//	go run ./samples/obtain-token -config a.json -config b.json -config c.json  # 多配置批量
//	go run ./samples/obtain-token -config "a.json,b.json,c.json"             # 逗号分隔
//
// 各 authnMethod 对应的配置文件示例参见 samples/README.md。
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aliyun/idaas-go-core-sdk/config"
	"github.com/aliyun/idaas-go-core-sdk/credential"
	"github.com/aliyun/idaas-go-core-sdk/http"
	"github.com/aliyun/idaas-go-core-sdk/implementation"
)

// configFlags 支持多次指定 -config 的自定义 flag 类型
type configFlags []string

func (f *configFlags) String() string { return strings.Join(*f, ",") }
func (f *configFlags) Set(value string) error {
	// 支持逗号分隔：-config "a.json,b.json"
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			*f = append(*f, v)
		}
	}
	return nil
}

func main() {
	var configs configFlags
	// 手动解析 flag（因为需要自定义 flag 类型）
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-config" || arg == "--config" {
			if i+1 < len(os.Args) {
				i++
				_ = configs.Set(os.Args[i])
			}
		} else if strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "--config=") {
			_ = configs.Set(arg[strings.Index(arg, "=")+1:])
		} else if arg == "-h" || arg == "--help" {
			fmt.Println("Usage: obtain_token_sample [-config path] [-config path] ...")
			fmt.Println("  -config  path to IDaaS client config file (repeatable, comma-separated)")
			fmt.Println("           empty means use default priority")
			os.Exit(0)
		}
	}

	// 无 -config 参数：走默认优先级（单配置模式）
	if len(configs) == 0 {
		configs = []string{""}
	}

	type result struct {
		configPath  string
		authnMethod string
		success     bool
		errMsg      string
	}
	var results []result

	reader := config.NewConfigReader()

	for i, cfgPath := range configs {
		if len(configs) > 1 {
			label := cfgPath
			if label == "" {
				label = "(default priority)"
			}
			fmt.Printf("\n========== [%d/%d] %s ==========\n", i+1, len(configs), label)
		}

		cfg, err := reader.LoadWithPriority(cfgPath)
		if err != nil {
			msg := fmt.Sprintf("Failed to load configuration: %v", err)
			log.Println(msg)
			results = append(results, result{configPath: cfgPath, errMsg: msg})
			continue
		}

		authnMethod := ""
		if cfg.AuthnConfiguration != nil {
			authnMethod = string(cfg.AuthnConfiguration.AuthnMethod)
		}
		fmt.Printf("Getting access token (authnMethod=%s)...\n", authnMethod)

		httpClient := newHttpClientFromConfig(cfg)
		credentialProvider := implementation.NewIDaaSMachineCredentialProvider(cfg, httpClient)

		var cred credential.IDaaSCredential
		cred, err = credentialProvider.GetCredential()
		if err != nil {
			msg := fmt.Sprintf("Failed to get credential: %v", err)
			log.Println(msg)
			results = append(results, result{configPath: cfgPath, authnMethod: authnMethod, errMsg: msg})
			continue
		}

		printCredential(cred)
		results = append(results, result{configPath: cfgPath, authnMethod: authnMethod, success: true})
	}

	// 多配置模式下打印汇总
	if len(configs) > 1 {
		fmt.Println("\n========== Summary ==========")
		passed, failed := 0, 0
		for _, r := range results {
			label := r.configPath
			if label == "" {
				label = "(default)"
			}
			if r.success {
				passed++
				fmt.Printf("  ✅ %-40s authnMethod=%-20s\n", label, r.authnMethod)
			} else {
				failed++
				fmt.Printf("  ❌ %-40s %s\n", label, r.errMsg)
			}
		}
		fmt.Printf("\nTotal: %d  Passed: %d  Failed: %d\n", len(results), passed, failed)
		if failed > 0 {
			os.Exit(1)
		}
	}
}

func printCredential(cred credential.IDaaSCredential) {
	fmt.Println("Access Token:")
	fmt.Println(maskToken(cred.GetAccessToken()))
	fmt.Printf("Token Type:    %s\n", cred.GetTokenType())
	fmt.Printf("Expires In:    %d seconds\n", cred.GetExpiresIn())
	if scope := cred.GetScope(); scope != "" {
		fmt.Printf("Scope:         %s\n", scope)
	}
	if refreshToken := cred.GetRefreshToken(); refreshToken != "" {
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
