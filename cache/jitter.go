package cache

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"sync"
	"time"
)

// Jitter 常量。
//
// 对齐 Python JITTER_START=5min / JITTER_RANGE=5min。
const (
	JitterStart  = 5 * time.Minute  // 期望的最早抖动偏移
	JitterRange  = 5 * time.Minute  // 期望的抖动区间长度
	SafetyMargin = 30 * time.Second // 刷新时刻不得超过 expiresAt - SafetyMargin
)

// seededRand 是包内私有随机数生成器。
//
// math/rand 全局源自 Go 1.20 起才自动播种；1.18/1.19 上固定 seed=1，
// 会导致所有容器副本算出完全相同的抖动序列，jitter 退化为惊群。
//
// 不修改全局 rand 源（宿主全局状态），而是用 crypto/rand 取初始 seed，
// 构造包内私有 *mathrand.Rand + sync.Mutex，在 1.18~最新工具链上行为一致。
var (
	seededRand *mathrand.Rand
	seededMu   sync.Mutex
)

func init() {
	seed := readCryptoSeed()
	seededRand = mathrand.New(mathrand.NewSource(seed))
}

func readCryptoSeed() int64 {
	var buf [8]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		return 1
	}
	return int64(binary.LittleEndian.Uint64(buf[:]))
}

// jitter 在 [t + lo, t + hi] 区间内取随机时间。
//
// 约束: t <= 返回值 <= expiresAt - SafetyMargin
//
// 当期望的抖动区间 [JitterStart, JitterStart+JitterRange] 超过
// 安全上限时，先收缩区间到合法范围再取随机（而不是钳位到端点）。
// 钳位在短 TTL 下会退化为确定值、引发惊群。
func jitter(t, expiresAt time.Time) time.Time {
	ceiling := expiresAt.Add(-SafetyMargin)
	if !ceiling.After(t) {
		return t
	}

	lo := JitterStart
	hi := JitterStart + JitterRange

	if room := ceiling.Sub(t); hi > room {
		hi = room
		if lo > hi {
			lo = 0
		}
	}

	if hi <= lo {
		return t
	}

	seededMu.Lock()
	delta := seededRand.Int63n(int64(hi - lo))
	seededMu.Unlock()

	return t.Add(lo + time.Duration(delta))
}
