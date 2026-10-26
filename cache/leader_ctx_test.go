package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
)

// TestDoRefresh_LeaderCtxCancel_StopsBlocking 验证:leader 同步刷新
// 路径下,调用方在刷新发起后取消 ctx 时,leader 经 `select{call.done|ctx.Done()}`
// 立即返回 ClientRequestCanceled(底层 ctx.Err() 经 %w 透传),不被 refreshFunc 阻塞。
// worker 仍 detached 运行,结果由 commitRefresh 提交给后续 waiter。
func TestDoRefresh_LeaderCtxCancel_StopsBlocking(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	release := make(chan struct{})
	started := make(chan struct{})
	refreshFunc := func(ctx context.Context) (*RefreshResult[string], error) {
		close(started)
		<-release // 模拟慢 IdP
		return &RefreshResult[string]{
			Value:     "fresh",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	ctx, cancel := context.WithCancel(context.Background())
	// leader 在后台发起
	type res struct {
		r   *RefreshResult[string]
		err error
	}
	leaderCh := make(chan res, 1)
	go func() {
		r, e := supplier.GetWithContext(ctx)
		leaderCh <- res{r, e}
	}()

	// 等 refreshFunc 启动(说明 leader 已过入口短路、已 spawn worker、已进 select)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not start within 2s")
	}

	// 此时 leader 阻塞在 select{call.done|ctx.Done()};取消 caller ctx。
	begin := time.Now()
	cancel()
	select {
	case got := <-leaderCh:
		elapsed := time.Since(begin)
		if got.err == nil {
			t.Fatal("expected ClientRequestCanceled after caller cancel, got nil error")
		}
		if got.r != nil {
			t.Errorf("expected nil result on cancel, got: %v", got.r)
		}
		// 经 CacheError.Unwrap 透传 ctx.Err() = context.Canceled
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("expected errors.Is(context.Canceled), got: %v", got.err)
		}
		// 不应阻塞到 refreshFunc 完成(release 尚未触发)
		if elapsed > 500*time.Millisecond {
			t.Errorf("leader blocked %v after cancel; expected prompt return", elapsed)
		}
		// 错误码归类为客户端类
		var ce interface{ ErrorCode() string }
		if errors.As(got.err, &ce) && ce.ErrorCode() != constants.ClientRequestCanceled {
			t.Errorf("error code = %s, want %s", ce.ErrorCode(), constants.ClientRequestCanceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return within 2s after caller cancel (blocked instead of ctx.Done)")
	}

	// 放行 worker,确认其 detached 完成、commitRefresh 提交结果供后续 waiter。
	close(release)
	// 后续 Get 应拿到 worker 提交的缓存(不再打 IdP)
	got2, err := supplier.GetWithContext(context.Background())
	if err != nil {
		t.Fatalf("subsequent Get after worker commit failed: %v", err)
	}
	if got2 == nil || got2.Value != "fresh" {
		t.Errorf("expected cached 'fresh' from detached worker commit, got: %v", got2)
	}
}

// TestDoRefresh_WaiterStillGetsResult 验证:waiter(ongoingRefresh != nil)
// 保持 waitInflight 不变,leader 的刷新完成后 waiter 拿到一致结果(不被 leader ctx 取消影响)。
func TestDoRefresh_WaiterStillGetsResult(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	release := make(chan struct{})
	started := make(chan struct{})
	refreshFunc := func(ctx context.Context) (*RefreshResult[string], error) {
		close(started)
		<-release
		return &RefreshResult[string]{
			Value:     "waiter-sees-this",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock

	// leader 用独立 ctx 发起(Background,不取消)
	type res struct {
		r   *RefreshResult[string]
		err error
	}
	leaderCh := make(chan res, 1)
	go func() {
		r, e := supplier.GetWithContext(context.Background())
		leaderCh <- res{r, e}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("leader refresh did not start within 2s")
	}

	// waiter 到来:ongoingRefresh != nil → waitInflight
	waiterCh := make(chan res, 1)
	go func() {
		// waiter 用一个会超时的 ctx,但超时窗口足够长,应在 release 后正常返回
		wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer wcancel()
		r, e := supplier.GetWithContext(wctx)
		waiterCh <- res{r, e}
	}()

	// 放行 worker
	close(release)

	// waiter 应拿到 worker 提交的 fresh 结果
	select {
	case got := <-waiterCh:
		if got.err != nil {
			t.Fatalf("waiter expected success, got: %v", got.err)
		}
		if got.r == nil || got.r.Value != "waiter-sees-this" {
			t.Errorf("waiter got: %v, want waiter-sees-this", got.r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not get result within 2s after release")
	}
	// leader 也应完成
	select {
	case <-leaderCh:
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not complete within 2s after release")
	}
}

// TestDoRefresh_LeaderAbandon_WaiterNeverGetsNilNil 验证 F1 修复:leader 入口
// ctx 已取消走 abandon 短路(不 spawn worker)时,并发 waiter 经 <-call.done 读到的
// 必是 (nil, cancelErr) 而非 (nil, nil)——否则 abstract_refreshed_provider.go:70 的
// result.Value 将 nil deref,panic 经同步调用栈逃逸宿主(worker 的顶层 recover 不覆盖此路径)。
//
// 修复前 clearOngoingIfMatch 只清槽不写 call.err,leader-abandon 与 waiter 进入
// waitInflight 的窗口内 waiter 会读 (nil,nil)。修复后持锁写 call.err(对齐 commitRefresh
// 的持锁写语义),保证 closeDone 后 waiter 必读非 nil err。
//
// 触发说明:F1 race 窗口为纳秒级(423 unlock→428 re-lock,仅 ctx.Err() 一行间隔),
// 无法确定性触发;此处用多轮并发 + 在线 race detector 压测,断言不变量
// "waiter 绝不收 (nil,nil)"——修复前在线 race 下可观察到 (nil,nil),修复后稳定为
// (nil, cancelErr)(读旧 call)或 fresh 结果(waiter 已成为新 leader,ongoingRefresh
// 已被清)。
func TestDoRefresh_LeaderAbandon_WaiterNeverGetsNilNil(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	// refreshFunc 立即返回有效结果:被 abandon 短路的 leader 不调用它;
	// 只有成为"新 leader"的 waiter(ongoingRefresh 已被清)才会调用,拿到 fresh 值。
	refreshFunc := func(ctx context.Context) (*RefreshResult[string], error) {
		return &RefreshResult[string]{
			Value:     "fresh",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	type res struct {
		r   *RefreshResult[string]
		err error
	}

	const iterations = 200
	const waitersPerIter = 4
	for iter := 0; iter < iterations; iter++ {
		// 每轮重建 supplier,确保 leader 入口即遇空槽 + 已取消 ctx(命中 abandon 短路)。
		supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
		supplier.clock = mock

		// leader 用预取消 ctx:doRefresh 入口 ctx.Err() != nil → abandon 短路(426),
		// 不 spawn worker,走 clearOngoingIfMatch+closeDone 返回 cancelErr。
		leaderCtx, leaderCancel := context.WithCancel(context.Background())
		leaderCancel()

		start := make(chan struct{})
		collect := make(chan res, waitersPerIter+1)

		// leader
		go func() {
			<-start
			r, e := supplier.GetWithContext(leaderCtx)
			collect <- res{r, e}
		}()

		// waiters:valid ctx(带超时,防止理论上的死锁拖垮测试),与 leader 同时发车,
		// 尽量挤进 leader set-ongoingRefresh(417) 与 closeDone 之间的窗口。
		var wwg sync.WaitGroup
		wwg.Add(waitersPerIter)
		for i := 0; i < waitersPerIter; i++ {
			go func() {
				defer wwg.Done()
				<-start
				wctx, wcancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer wcancel()
				r, e := supplier.GetWithContext(wctx)
				collect <- res{r, e}
			}()
		}

		close(start)
		wwg.Wait()

		// 收集 leader + waiters 的全部结果,逐个断言不变量:绝不收 (nil, nil)。
		for i := 0; i < waitersPerIter+1; i++ {
			select {
			case got := <-collect:
				if got.r == nil && got.err == nil {
					t.Fatalf("iter %d: goroutine %d got (nil, nil) — F1 regression: "+
						"waiter read abandoned call with unset err, would nil-deref at "+
						"abstract_refreshed_provider.go:70", iter, i)
				}
				// 可接受结果:
				//  (a) 读旧 call → (nil, cancelErr):errors.Is(context.Canceled)
				//  (b) 成为新 leader → (fresh, nil):result.Value == "fresh"
				//  (c) waiter ctx 超时 → (nil, ctx.DeadlineExceeded)——罕见,容忍
				if got.err != nil {
					// err 必须是 ctx 取消类或 CacheError 包裹的取消类,
					// 不得是 RefreshPanicRecovered(那是panic 路径,与本场景无关)。
					var ce interface{ ErrorCode() string }
					if errors.As(got.err, &ce) &&
						ce.ErrorCode() == constants.RefreshPanicRecovered {
						t.Errorf("iter %d goroutine %d: unexpected RefreshPanicRecovered: %v",
							iter, i, got.err)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("iter %d: goroutine %d did not return within 5s (deadlock?)", iter, i)
			}
		}
	}
}

// TestRunRefreshAndCommit_CommitRefreshPanic_ReleasesMuAndWaiters 验证
// commitRefresh 临界区 panic 时 scoped anon func 的 defer Unlock 释放 mu,
// runRefreshAndCommit 顶层 recover 写入 RefreshPanicRecovered 并 closeDone,waiter 不死锁。
//
// 注入手段:用 oncePanicClock(Now() 首次 panic,后续正常)。commitRefresh 失败分支
// 调用 s.nowLocked() 触发首次 panic;成功分支不调用 nowLocked,故须让 refreshFunc
// 返回 error 走失败分支。首次 panic 后 runRefreshAndCommit recover 调用 commitRefresh
// 再写 recErr,该次 nowLocked() 不再 panic,恢复路径写回 call.err 并 closeDone。
func TestRunRefreshAndCommit_CommitRefreshPanic_ReleasesMuAndWaiters(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	refreshFunc := func(ctx context.Context) (*RefreshResult[string], error) {
		return nil, errors.New("idp down")
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock)
	supplier.clock = mock
	// 注入 oncePanicClock:首次 nowLocked() panic,触发 commitRefresh 失败分支 panic。
	supplier.mu.Lock()
	supplier.clock = &oncePanicClock{fallback: mock.Now()}
	supplier.mu.Unlock()

	type res struct {
		r   *RefreshResult[string]
		err error
	}
	leaderCh := make(chan res, 1)
	go func() {
		r, e := supplier.GetWithContext(context.Background())
		leaderCh <- res{r, e}
	}()

	select {
	case got := <-leaderCh:
		// leader 拿到的应是 panic 恢复后的 RefreshPanicRecovered(非 (nil,nil))
		if got.err == nil {
			t.Fatal("expected RefreshPanicRecovered error, got nil")
		}
		var ce interface{ ErrorCode() string }
		if !errors.As(got.err, &ce) || ce.ErrorCode() != constants.RefreshPanicRecovered {
			t.Errorf("error code = %v, want %s", got.err, constants.RefreshPanicRecovered)
		}
		if got.r != nil {
			t.Errorf("expected nil result on panic recovery, got: %v", got.r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("leader did not return within 3s (waiter would deadlock if mu not released / done not closed)")
	}

	// 关键断言:mu 已释放 → 能再次加锁(否则死锁/测试 hang)。若 scoped anon 未释放 mu,
	// 下面的 Lock 会阻塞到测试超时。
	supplier.mu.Lock()
	ongoing := supplier.ongoingRefresh
	supplier.clock = mock // 恢复非 panic clock,供后续 Get
	supplier.mu.Unlock()
	if ongoing != nil {
		t.Errorf("ongoingRefresh should be cleared after panic recovery, got: %v", ongoing)
	}

	// 后续 Get 应能正常进行(supplier 未死锁)。
	_, err := supplier.GetWithContext(context.Background())
	if err == nil {
		t.Fatal("subsequent Get after panic recovery should still error (refreshFunc fails), but not deadlock")
	}
}

// TestInflightCall_CloseDone_Idempotent 验证:closeDone 幂等(sync.Once),
// 多次调用不双关 panic。
func TestInflightCall_CloseDone_Idempotent(t *testing.T) {
	call := &inflightCall[string]{done: make(chan struct{})}

	// 第一次 close
	call.closeDone()
	select {
	case <-call.done:
	default:
		t.Fatal("done not closed after first closeDone")
	}

	// 多次再 close,不得 panic
	for i := 0; i < 5; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("closeDone double-close panicked on iter %d: %v", i, r)
				}
			}()
			call.closeDone()
		}()
	}

	// done 仍可读(已 close 的 channel 反复读不 panic)
	for i := 0; i < 3; i++ {
		<-call.done
	}
}

// TestSupplier_BaseContextCancel_StopsWorker 验证:baseCtx 取消
// 传播到 worker 的 refreshCtx(WithTimeout(baseCtx,...)),refreshFunc 收到 ctx.Done
// 提前返回,worker 不挂到 asyncRefreshTimeout。
func TestSupplier_BaseContextCancel_StopsWorker(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	started := make(chan struct{})
	sawDone := make(chan struct{}, 1)
	refreshFunc := func(ctx context.Context) (*RefreshResult[string], error) {
		close(started)
		select {
		case <-ctx.Done():
			sawDone <- struct{}{}
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
			return &RefreshResult[string]{Value: "late", ExpiresAt: mock.Now().Add(time.Hour)}, nil
		}
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorBlock).
		WithAsyncRefreshTimeout(30 * time.Second).
		WithBaseContext(baseCtx)
	supplier.clock = mock

	type res struct {
		r   *RefreshResult[string]
		err error
	}
	leaderCh := make(chan res, 1)
	go func() {
		r, e := supplier.GetWithContext(context.Background())
		leaderCh <- res{r, e}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not start within 2s")
	}

	// 取消 baseCtx → worker refreshCtx 取消 → refreshFunc 看到 ctx.Done
	begin := time.Now()
	baseCancel()

	select {
	case <-sawDone:
		elapsed := time.Since(begin)
		if elapsed > 500*time.Millisecond {
			t.Errorf("refreshFunc took %v to observe baseCtx cancel", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refreshFunc did not observe ctx.Done within 2s of baseCtx cancel")
	}

	// leader 经 call.done 收到 worker 提交的结果(refreshFunc 返回 ctx.Err())
	select {
	case got := <-leaderCh:
		if got.err == nil {
			t.Fatal("expected error from canceled refresh, got nil")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("expected errors.Is(context.Canceled), got: %v", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return within 2s after baseCtx cancel")
	}
}

// TestDoRefresh_Concurrent_Race 验证 singleflight:并发 Get 仅触发 1 次 refreshFunc
// 调用(race 下复跑)。同时验证无 data race(race detector 已在线)。
func TestDoRefresh_Concurrent_Race(t *testing.T) {
	mock := NewMockClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	var callCount int32
	refreshFunc := func(ctx context.Context) (*RefreshResult[string], error) {
		atomic.AddInt32(&callCount, 1)
		// 轻微延迟让并发请求窗口拉长,确保多个 Get 都落在同一个 in-flight 槽
		time.Sleep(20 * time.Millisecond)
		return &RefreshResult[string]{
			Value:     "concurrent",
			ExpiresAt: mock.Now().Add(1 * time.Hour),
		}, nil
	}

	supplier := NewCachedResultSupplier(refreshFunc, enums.StaleValueBehaviorRefresh)
	supplier.clock = mock

	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	results := make([]string, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			r, e := supplier.GetWithContext(context.Background())
			if r != nil {
				results[idx] = r.Value
			}
			errs[idx] = e
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("refreshFunc callCount = %d, want 1 (singleflight)", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d got err: %v", i, errs[i])
		}
		if results[i] != "concurrent" {
			t.Errorf("goroutine %d got value %q, want concurrent", i, results[i])
		}
	}
}

// oncePanicClock 实现 Clock,Now() 仅第一次调用 panic,后续返回 mock 的固定时间。
// 用于注入 commitRefresh 失败分支的一次性 panic:首次 commitRefresh(nowLocked) panic
// → runRefreshAndCommit recover → 再次 commitRefresh(nowLocked) 正常返回并写 recErr,
// 模拟真实"瞬态 panic 后恢复路径仍可用"的语义(恒 panic 会让恢复路径也失败)。
type oncePanicClock struct {
	fired    int32
	fallback time.Time
}

func (c *oncePanicClock) Now() time.Time {
	if atomic.CompareAndSwapInt32(&c.fired, 0, 1) {
		panic("oncePanicClock: injected one-time panic in nowLocked")
	}
	return c.fallback
}
