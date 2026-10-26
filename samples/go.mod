// samples/ 是一个**独立 module**。
//
// 拆分原因:样例与主模块共用一个 go.mod 时,`go build ./...` 会把样例纳入主模块
// 构建图,样例的依赖与 Go 版本需求会**反向抬高 SDK 的版本下限**。
// SDK 承诺 Go 1.18 下限,而样例希望自由使用 1.21+ 特性(例如 log/slog 适配器演示),
// 二者只能靠模块边界隔离。
//
// 本 module 通过 replace 指向上一级目录的工作副本,因此样例永远跑的是当前源码,
// 不需要等主模块发版。发布流程不发布本 module。
module github.com/cloud-idaas/idaas-go-core-sdk/samples

go 1.21

require github.com/cloud-idaas/idaas-go-core-sdk v0.0.0

replace github.com/cloud-idaas/idaas-go-core-sdk => ../

require (
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
)
