// Package util 汇集 SDK 内部通用工具:文件读写、JWT/PEM 处理、URL 归一化、配置校验等。
//
// # 敏感 []byte 清零约定
//
// Go 的 string 不可变:从 `[]byte(s)` 派生的副本可清零,但源 string 仍待 GC
// 回收、其底层只读段在 GC 前仍驻留堆。SDK 的凭证(client_secret、PEM 私钥、
// HS256 密钥)多以 string 形态在配置/结构体中流转,真正的可清零副本是各签名/
// 解析路径上由 `[]byte(secret)` 或 `ReadFile` 返回的堆分配切片。
//
// 约定:凡持有凭证副本 []byte 的函数,在用毕(签名/解析完成、token 已生成)
// 后立即 [ClearBytes] 清零该切片,缩短敏感明文在堆上的驻留窗口。这不是
// 替代 GC,而是减少被 heap dump / core dump 捕获的窗口。源 string 不可变
// 的限制由 GC + 进程短寿命凭证(刷新即覆盖)兜底,本包不试图改写 string。
package util

import (
	"os"
	"path/filepath"
	"strings"
)

// ClearBytes 原地清零 []byte 切片的可写部分(len 范围内)。
//
// 用于凭证副本(client_secret → []byte、PEM 字节、HS256 密钥)用毕即清,
// 缩短敏感明文在堆上的驻留窗口(见包文档"敏感 []byte 清零约定")。
//
// 安全性:
//   - nil / len==0 切片:range 零迭代,空操作,不 panic;
//   - 仅清零 [0:len),不动 [len:cap) 的尾区(若 cap>len 尾区本就不可见,无泄漏面);
//   - 不影响底层 string([]byte(s) 派生的副本与源 string 不共享底层——
//     string→[]byte 在 Go 运行时是 fresh alloc,清零副本不污染源 string)。
//
// 限制:源 string 仍待 GC(见包文档),本函数只覆盖可写副本。
func ClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ReadFile 读取文件内容，支持 ~ 路径展开
func ReadFile(filePath string) ([]byte, error) {
	// 展开 ~ 路径
	if strings.HasPrefix(filePath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		filePath = filepath.Join(homeDir, filePath[2:])
	}

	return os.ReadFile(filePath)
}

// WriteFile 写入文件内容。
//
// 默认使用 0600（rw-------）权限，这是 SDK 持久化敏感数据（refresh_token、
// access_token 等长寿命凭证）的安全默认值。多用户机器上 0644 会让同机器
// 任意账号读到凭证，存在严重信息泄露风险。
//
// 如需自定义权限（例如写非敏感缓存），使用 WriteFileMode。
func WriteFile(filePath string, data []byte) error {
	return WriteFileMode(filePath, data, 0o600)
}

// WriteFileMode 以指定权限写入文件内容。
//
// 原子写入凭证文件:先写同目录 0600 临时文件 + 原子 rename 替换目标文件,
// 避免用 O_TRUNC 截断目标文件期间旧 refresh_token 对其他读者短暂可读/丢失
// (chmod 可能 EPERM 但文件已被截空)。同目录 rename 在 POSIX 上是原子的,
// 保证写入过程其他读者看到的是完整的旧或新文件。
func WriteFileMode(filePath string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(filePath)
	// CreateTemp 创建 0600 临时文件(安全默认),写入成功后再 chmod 到目标权限。
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	// defer 清理:rename 成功后 tmpPath 不存在;失败时删除残留临时文件。
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// 设置目标权限后再 rename,确保替换后的文件已是目标权限。
	// 对新建文件幂等,对历史宽松权限文件在替换时收紧。
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}

	// 原子替换(同目录 rename 在 POSIX 上是原子的)。
	return os.Rename(tmpPath, filePath)
}
