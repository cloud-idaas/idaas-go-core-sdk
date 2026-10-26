// logger/adapters/slog 是一个独立嵌套 module。
//
// 拆分原因:log/slog 是 Go 1.21 stdlib,而主模块下限锁定在 1.18+。
// 把 slog 适配器放进带自己 go.mod 的子目录,该子目录不参与主模块的
// `go build ./...`,因此可以声明 go 1.21 而不影响主模块的版本下限。
// 先例:grpc-go、opentelemetry-go 均采用此结构。
//
// 本 module 通过 replace 指向仓库根目录(../../..)的工作副本,因此适配器
// 永远跑的是当前源码,不需要等主模块发版。发布流程不发布本 module。
module github.com/cloud-idaas/idaas-go-core-sdk/logger/adapters/slog

go 1.21

require github.com/cloud-idaas/idaas-go-core-sdk v0.0.0

replace github.com/cloud-idaas/idaas-go-core-sdk => ../../..
