package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadPrivateKeyMaterial 将"环境变量原始字符串"归一化为一段 PEM 文本字节。
//
// 支持两种使用方式（按顺序判定）：
// 1. 字符串本身就是 PEM 文本（包含 "-----BEGIN" 头）；
// 此函数会修复用户常见的字面量 "\n" 反转义为真实换行的问题。
// 2. 字符串是一个本地文件路径（支持以 "~/" 开头的家目录展开），
// 此时读取文件内容作为 PEM。
//
// 设计动机：用户在 shell 中 `export VAR="$(cat key.pem)"` 或将 PEM 复制到
// 配置中时，极易因换行/转义/引号问题导致字符串不是合法 PEM 文本。
// 直接支持"环境变量装路径"是体验最好的兜底方案。
func LoadPrivateKeyMaterial(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("private key material is empty")
	}

	// Case 1: 看起来已经是 PEM 文本
	if strings.Contains(trimmed, "-----BEGIN") {
		// 修复 JSON / shell 中常见的字面量 "\n" 未被转义为真实换行
		if !strings.Contains(trimmed, "\n") && strings.Contains(trimmed, `\n`) {
			trimmed = strings.ReplaceAll(trimmed, `\n`, "\n")
		}
		return []byte(trimmed), nil
	}

	// Case 2: 当作文件路径处理（含 ~ 展开）
	if data, err := ReadFile(trimmed); err == nil {
		return data, nil
	} else if !os.IsNotExist(err) {
		// 文件存在但读取失败（权限等），直接抛出读取错误
		return nil, fmt.Errorf("failed to read private key file %q: %w", trimmed, err)
	}

	return nil, fmt.Errorf(
		"private key material is neither a PEM block (missing '-----BEGIN' header) " +
			"nor an existing file path; please export the env var as either the raw PEM " +
			"content (e.g. IDAAS_PRIVATE_KEY=\"$(cat key.pem)\") or an absolute file path",
	)
}

// ParsePrivateKeyFromPEM 从 PEM 格式解析私钥，支持多种格式。
//
// pemData 是 PEM 文本字节(含 base64 编码的私钥明文),属敏感副本。
// pem.Decode 不保留 pemData 引用(block.Bytes 是 base64 解码后的 fresh
// 分配),故解析完成后立即 ClearBytes 清零 pemData,缩短私钥明文在堆上
// 的驻留窗口(见 util 包文档"敏感 []byte 清零约定")。
func ParsePrivateKeyFromPEM(pemData []byte) (interface{}, error) {
	defer ClearBytes(pemData) // 用毕即清,无论解析成功或 panic
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New(
			"failed to decode PEM block: the input is not a valid PEM-encoded private key " +
				"(must contain '-----BEGIN ... PRIVATE KEY-----' header and base64 body)",
		)
	}

	// 尝试 PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// 尝试 RSA PKCS1
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return rsaKey, nil
	}

	// 尝试 EC PKCS1
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return ecKey, nil
	}

	return nil, errors.New("unsupported private key format")
}

// GetKeyType 获取密钥类型
func GetKeyType(key interface{}) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "EC"
	default:
		return "Unknown"
	}
}
