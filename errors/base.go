package errors

import (
	stderrors "errors"
	"reflect"
)

// IDaaSError 所有 SDK 错误的基础接口。
// RequestId()：服务端排查唯一可用关联键，缺它则调用方拿 "invalid_grant" 无法定位请求；
// Java/Python 已有该字段，Go 补齐三语言一致性缺口。
// Unwrap()：写进接口防新增错误类型忘记实现导致 errors.As 断链。
// ⚠️ 兼容性：Go 无接口默认方法，新增方法破坏外部实现者；本接口设计为"SDK 实现、
// 调用方消费"，外部不应自定义；如确有，改为实现 error 并用 errors.As 断言具体类型。
type IDaaSError interface {
	error
	ErrorCode() string
	ErrorMessage() string
	// RequestId 返回服务端请求 ID;本地错误(配置、编解码等)返回空串。
	// 包装型错误会沿 Unwrap 链向下查找第一个非空值,因此顶层错误上调用即可。
	RequestId() string
	// Unwrap 返回被包装的底层错误,没有则返回 nil。
	Unwrap() error
}

// AsIDaaSError 把任意 error 断言为 IDaaSError。
//
// 它沿 Unwrap 链查找,因此即便 SDK 错误被调用方用 fmt.Errorf("%w") 再包了一层也能取到。
func AsIDaaSError(err error) (IDaaSError, bool) {
	var target IDaaSError
	if stderrors.As(err, &target) {
		return target, true
	}
	return nil, false
}

// HasCode 判断错误链上是否存在指定错误码。用法：errors.HasCode(err, constants.InvalidScope)。
// 相比类型断言写法，它不要求调用方知道错误具体类型——同一错误码可由 ClientError 或
// ConfigError 携带，类型断言会漏判。
//
// 支持标准库 errors.Join（Go 1.20+）的 Unwrap() []error 多路展开。
func HasCode(err error, code string) bool {
	// 用指针地址做 visited key,而非 error 值本身:
	// error 接口的可比较性取决于其动态类型,含 slice/map 字段且值接收者的结构体
	// 是不可比较的,直接 map[error]bool 会 panic。用 reflect.ValueOf(e).Pointer()
	// 取指针地址(对不可寻址的值退回 CanAddr 检查后跳过),避免 map key panic。
	visited := make(map[uintptr]bool)
	var walk func(e error) bool
	walk = func(e error) bool {
		if e == nil {
			return false
		}
		ptr := errorPointer(e)
		if ptr != 0 && visited[ptr] {
			return false
		}
		if ptr != 0 {
			visited[ptr] = true
		}
		if ie, ok := e.(IDaaSError); ok && ie.ErrorCode() == code {
			return true
		}
		// Unwrap() []error（errors.Join, Go 1.20+）
		if multi, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range multi.Unwrap() {
				if walk(child) {
					return true
				}
			}
		}
		// Unwrap() error（fmt.Errorf %w / 手动包装）
		if single, ok := e.(interface{ Unwrap() error }); ok {
			if child := single.Unwrap(); child != nil {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(err)
}

// errorPointer 返回 error 底层值的指针地址(用于 visited 去重)。
// 对指针类型(*ClientError 等)返回指针值;对值类型或不可寻址的返回 0(不去重,
// 接受极端环路径下可能的重复遍历,但不会 panic)。不可比较的 error 类型
// (含 slice/map 字段 + 值接收者)无法作为 map key,故用指针地址而非值做 key。
func errorPointer(e error) uintptr {
	v := reflect.ValueOf(e)
	if v.Kind() == reflect.Ptr && !v.IsNil() {
		return v.Pointer()
	}
	return 0
}

// RequestIdOf 取出错误链上的第一个非空 requestId;没有则返回空串。
//
// 调用方通常直接用 `ie.RequestId()`,此函数用于手上只有 error 的场景。
//
// 从 err 自身开始遍历（而非 Unwrap(err)），因此只实现了 RequestId() string
// 但不实现 IDaaSError / Unwrap 的第三方错误也能被取到。
func RequestIdOf(err error) string {
	if err == nil {
		return ""
	}
	if ie, ok := err.(IDaaSError); ok {
		return ie.RequestId()
	}
	return requestIdFromChain(err)
}

// extractRequestIdDirect 从 SDK 错误类型直接读取 requestId 字段，
// 不调用 RequestId() 方法，避免 requestIdFromChain → RequestId() →
// requestIdFromChain 的重入（重入会创建新的 visited 集合，无法检测环）。
// 返回 (id, isSDKType)：对 SDK 类型返回其 requestId 字段值（可能为空）；
// 对非 SDK 类型返回 ("", false)。
func extractRequestIdDirect(err error) (string, bool) {
	switch e := err.(type) {
	case *ClientError:
		return e.requestId, true
	case *ServerError:
		return e.requestId, true
	case *HttpError:
		return e.requestId, true
	case *OAuth2Error:
		return e.requestId, true
	case *EncodingError:
		return e.requestId, true
	case *ConfigError:
		return e.ClientError.requestId, true
	case *ConcurrentOperationError:
		return e.ClientError.requestId, true
	case *CredentialError:
		return e.requestId, true
	case *CacheError:
		return "", true
	case *IDaaSUnexpectedError:
		return "", true
	default:
		return "", false
	}
}

// requestIdFromChain 沿错误树（Unwrap 链）查找第一个非空 requestId。
//
// 支持两种 Unwrap 形式：
//   - Unwrap() error   （fmt.Errorf("%w")、SDK 错误的 Cause 链）
//   - Unwrap() []error （errors.Join, Go 1.20+）
//
// 对 SDK 错误类型,直接读取 requestId 字段而非调用 RequestId() 方法,
// 避免方法重入导致 visited 集合失效:e.Cause = e 时 e.RequestId() 会触发
// requestIdFromChain(e.Cause) → requestIdFromChain(e) → e.RequestId() → …
// 的无限递归。
//
// 对第三方错误实现 interface{ RequestId() string } 的，调用其方法取值。
// 链上可能混入只实现了 RequestId() 的第三方错误（例如阿里云 SDK 的错误类型），
// 能取到就取，不强求对方实现完整的 IDaaSError。
func requestIdFromChain(err error) string {
	// 同 HasCode,用指针地址做 visited key 避免 map key panic。
	visited := make(map[uintptr]bool)
	var walk func(e error) string
	walk = func(e error) string {
		if e == nil {
			return ""
		}
		ptr := errorPointer(e)
		if ptr != 0 && visited[ptr] {
			return ""
		}
		if ptr != 0 {
			visited[ptr] = true
		}

		// SDK 类型：直接读取 requestId 字段，跳过 RequestId() 方法调用。
		if id, isSDK := extractRequestIdDirect(e); isSDK {
			if id != "" {
				return id
			}
			// SDK 类型但自身无 requestId：继续遍历 Unwrap/Cause 链。
		} else if r, ok := e.(interface{ RequestId() string }); ok {
			// 第三方错误实现了 RequestId()：调用取值。
			if id := r.RequestId(); id != "" {
				return id
			}
		}

		// 遍历子节点：先尝试 Unwrap() []error（errors.Join），再尝试 Unwrap() error。
		if multi, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range multi.Unwrap() {
				if id := walk(child); id != "" {
					return id
				}
			}
		}
		if single, ok := e.(interface{ Unwrap() error }); ok {
			if child := single.Unwrap(); child != nil {
				if id := walk(child); id != "" {
					return id
				}
			}
		}
		return ""
	}
	return walk(err)
}
