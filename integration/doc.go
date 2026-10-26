// Package integration 存放针对真实 IDaaS Endpoint 的端到端测试。
//
// 所有测试文件都带 `//go:build integration` 标签，因此：
//
//	go build ./... / go vet ./... / go test ./... # 默认完全不编译、不运行这些用例
//	go test -tags integration -v ./integration/ # 显式开启才会真实请求 Token
//
// 这样 CI（无凭证、无内网）不会被集成测试拖挂。本文件是不带标签的占位文件，
// 保证包在无标签时依然存在，避免 go list 报 "no Go files"。
package integration
