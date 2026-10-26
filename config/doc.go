// Package config 定义 IDaaS Go Core SDK 的客户端配置模型与校验链。
//
// # 配置生命周期
//
// 配置经 Load(Defaulting) → Normalize → Validate 三阶段后交付 factory.Initialize 使用。
//   - Defaulting:补齐 0 值字段为默认值(connectTimeout/readTimeout 等)。
//   - Normalize:对身份字段与 scope 应用 TrimSpace 写回(见 ConfigValidator.Validate
//     内 normalizeTrimmedFields);端点归一化见 NormalizeEndpoints。
//   - Validate:四组校验(基础字段非空白/端点 https/authnMethod 字段/HTTP 超时范围)。
//
// # 配置冻结
//
// Initialize 成功后,config 视为**冻结**:SDK 不支持运行期热更新字段值。
// 如需变更 clientId/endpoints/authnMethod 等,须重建 CredentialProvider(新 factory.Initialize)。
// 这与 Java/Python SDK 一致——配置是构建期契约,而非运行期可变状态。
// 运行期可变的只有凭证内容本身(token 刷新),配置形态不变。
//
// # Experimental 标注惯例
//
// beta 阶段新增或语义未稳定的公开 API(类型/字段/函数/常量)须在 doc 注释首行
// 标 `// Experimental:`,并在注释内说明可能在 GA 前调整的点。GA 稳定后移除该标注。
// 示例:StaleValueBehavior(beta 已接入但退避策略 GA 前可能调整)。
package config
