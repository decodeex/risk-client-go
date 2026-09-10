package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	kafka "github.com/segmentio/kafka-go"

	"github.com/decodeex/risk-client-go/sdklog"
)

// 本文件实现审核通知的消费全生命周期(design.md System Flows·通知消费):
//
//	聚批(FetchMessage × PollMaxRecords / PollTimeout 窗口)
//	  → 坏 JSON 记日志跳过(仍在提交集)/ Filter 拒绝不入 Handler(仍在提交集)
//	  → Handler 成功 → 提交本批全部位点
//	  → 失败按 RetryCount×RetryInterval 重试;恢复则提交
//	  → 耗尽:OnBatchError 告警后提交,继续消费(消息放弃,转存由宿主在回调里自理)
//
// 位点只在终局态提交,失败中途绝不提交(Kafka 重投兜底);空匹配集同样提交整轮位点。
// Stop 立刻停拉取;在途批次允许在 GracefulTimeout 内自然完成,超时熔断强制收尾。

// readerAPI 是消费端所需的最小 broker 面;kafka.Reader 的
// FetchMessage(ctx)(kafka.Message,error)/CommitMessages/Close 天然满足。
type readerAPI interface {
	FetchMessage(ctx context.Context) (kafka.Message, error)
	CommitMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

// connections 是运行期持有的连接束。
type connections struct {
	reader readerAPI
}

// connFactory 建立 broker 连接的工厂(测试注入假实现;生产为默认工厂)。
type connFactory func(cfg ConsumerConfig) (*connections, error)

// Consumer 提供 Start/Stop(Kratos transport.Server 结构化兼容:Start 接受 ctx、Stop 无参)
// 与阻塞形态 Run。一个实例只允许启动一次,重复 Start 幂等。
type Consumer struct {
	cfg     ConsumerConfig
	handler Handler
	newConn connFactory
	logger  sdklog.Logger

	startMu    sync.Mutex
	started    bool
	fetchFails int // 连续 fetch 失败次数(退避指数;成功后清零)
	stopOnce   sync.Once
	stopCh     chan struct{} // 关闭即停止拉取
	fuseCh     chan struct{} // Stop 后经 GracefulTimeout 关闭:在途批次强收
	doneCh     chan struct{} // 循环完全退出
	// lastErr 记录启动/重连期致命错误。写方是 run goroutine、读方是 Stop/Run,
	// 用 atomic.Pointer 消除无同步读写(review 修复)。
	lastErr atomic.Pointer[error]
}

// NewConsumer 校验配置并构造消费者(**零网络**——连接延迟到 Start 的工厂调用,
// 与"不启用即零 Kafka 连接"(Req 7.10)由包结构共同保证)。
func NewConsumer(cfg ConsumerConfig, handler Handler) (*Consumer, error) {
	if handler == nil {
		return nil, fmt.Errorf("%w: handler is required", ErrInvalidConfig)
	}
	validated, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &Consumer{
		cfg:     validated,
		handler: handler,
		newConn: defaultConnFactory,
		logger:  validated.Logger,
		stopCh:  make(chan struct{}),
		fuseCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}, nil
}

// Start 建立连接并以独立 goroutine 启动消费循环(立即返回,不阻塞)。
// 建连失败同步返回 error——让宿主在启动期就看到消费不可用,而不是静默停摆。
// 重复调用幂等。
func (c *Consumer) Start(ctx context.Context) error {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.started {
		return nil
	}
	conn, err := c.newConn(c.cfg)
	if err != nil {
		lerr := fmt.Errorf("notify: connect brokers: %w", err)
		c.lastErr.Store(&lerr)
		sdklog.Errorf(c.logger, "consumer 启动失败: %v", lerr)
		return lerr
	}
	c.started = true
	go c.run(ctx, conn)
	return nil
}

// Run 阻塞运行直到循环退出(外部 ctx 取消 / Stop 完成)。返回启动期致命错误或 nil。
func (c *Consumer) Run(ctx context.Context) error {
	if err := c.Start(ctx); err != nil {
		return err
	}
	select {
	case <-c.doneCh:
	case <-ctx.Done():
	}
	<-c.doneCh
	return c.loadErr()
}

// Stop 触发优雅停机(Kratos transport.Server 形态:Stop(ctx) error):
// 立刻停止拉取;在途批次最多等 GracefulTimeout(内部 fuse)后熔断收尾;
// 调用方的 ctx 可携带更短的耐心值——二者先到为准。幂等。
// 未启动过时直接返回 nil(doneCh 永不关闭,不能等它)。
// 返回循环退出前的启动期致命错误(正常路径恒 nil)。
func (c *Consumer) Stop(ctx context.Context) error {
	if !c.everStarted() {
		return nil
	}
	c.signalStop()
	select {
	case <-c.doneCh:
	case <-ctx.Done():
	}
	return c.loadErr()
}

// everStarted 快照"是否 Start 过"(startMu 只护写入侧;此处读一次布尔,
// 竞态窗口内最坏结果=与旧版语义相同地去等 doneCh,可接受)。
func (c *Consumer) everStarted() bool {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	return c.started
}

// signalStop 只负责发停机信号与 fuse 定时(幂等),不等待完成。
func (c *Consumer) signalStop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		time.AfterFunc(c.cfg.GracefulTimeout, func() { close(c.fuseCh) })
	})
}

// ---- 轮次数据结构 ----

type roundItem struct {
	raw     kafka.Message
	parsed  Notification
	badJSON bool
}

// ---- 消费主循环 ----

// run 是消费主循环宿主:管理连接生命周期,并对每一轮迭代做顶层 recover——
// 任何非预期 panic 只会终止本轮并重建连接继续消费,绝不带崩宿主进程(Req 4.4)。
func (c *Consumer) run(parent context.Context, firstConn *connections) {
	defer close(c.doneCh)

	conn := firstConn
	for {
		alive := c.consumeLoop(parent, conn)

		_ = conn.reader.Close()

		if alive || !c.running(parent) {
			return // 正常停机(alive=true)或外部取消;alive=false=panic,走重建
		}
		// 异常恢复路径:退避后重建连接继续消费(自愈优先于放弃)
		sdklog.Errorf(c.logger, "consumer loop exited abnormally, reconnecting in 5s")
		select {
		case <-time.After(5 * time.Second):
		case <-parent.Done():
			return
		case <-c.stopCh:
			return
		}
		next, cerr := c.newConn(c.cfg)
		if cerr != nil {
			rerr := fmt.Errorf("notify: reconnect brokers: %w", cerr)
			c.lastErr.Store(&rerr)
			sdklog.Errorf(c.logger, "reconnect 失败,消费终止: %v", rerr)
			return
		}
		conn = next
	}
}

// consumeLoop 单连接上的消费循环。返回 true=循环正常退出(停机/外部取消,上层直接返回);
// false=本轮因 panic 退出(已在此处 recover 并记录,不会外溢),上层退避后重建连接继续。
func (c *Consumer) consumeLoop(parent context.Context, conn *connections) (alive bool) {
	defer func() {
		if r := recover(); r != nil {
			sdklog.Errorf(c.logger, "consumer loop panic(已恢复,宿主进程不受影响): %v\n%s", r, debugStack())
			alive = false
		}
	}()

	handlerCtx := c.newHandlerCtx(parent)

	for c.running(parent) {
		items := c.pollBatch(conn.reader, parent)
		if items == nil { // 停机(窗口到点返回非 nil 空片继续下一轮)
			break
		}
		if len(items) == 0 {
			continue
		}
		c.processRound(handlerCtx, conn, items)
	}
	return true
}

// debugStack 供 panic 日志附带调用栈(截断,防日志膨胀)。
func debugStack() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// pollBatch 聚批:首条 FetchMessage 阻塞等待(仅受 parent/Stop 取消),
// 收到首条后以 PollTimeout 为聚合窗口继续拉至 PollMaxRecords。
// 设计勘误(联调修正):原实现给每条 fetch 挂独立窗口,消费组 join
// 握手会被窗口反复打断,导致组永远注册不上(静默空转);改为"阻塞首条 + 窗口
// 起算于首条",与 kafka-go 官方消费模式一致。
// 返回 nil 表示应终止取数(Stop/外部取消);空片=窗口内无后续消息,正常收口。
func (c *Consumer) pollBatch(reader readerAPI, parent context.Context) []roundItem {
	fetchCtx, cancel := c.newFetchCtx(parent)
	defer cancel()

	km, err := reader.FetchMessage(fetchCtx)
	if err != nil {
		if !c.running(parent) {
			return nil // 停机:立刻终止取数
		}
		c.fetchFails++
		backoff := minDur(c.cfg.RetryInterval<<uint(minInt(c.fetchFails-1, 5)), 30*time.Second) // 1s,2s,4s…封顶 30s,防日志洪泛
		sdklog.Errorf(c.logger, "fetch error(退避 %s 后重试): %v", backoff, err)
		if !c.sleepInterruptible(backoff, parent) {
			return nil // 退避期间收到停机信号:立即终止,不再睡满退避时长
		}
		return []roundItem{}
	}
	c.fetchFails = 0
	items := make([]roundItem, 0, c.cfg.PollMaxRecords)
	items = append(items, c.wrapFetched(km))

	// 后续 fetch 挂窗口 deadline:窗口到点即收口本批(首条 fetch 保持阻塞,
	// 避免"无消息空转";窗口超时会以 DeadlineExceeded 在此返回)
	windowCtx, wcancel := context.WithTimeout(fetchCtx, c.cfg.PollTimeout)
	defer wcancel()
	for len(items) < c.cfg.PollMaxRecords {
		km, ferr := reader.FetchMessage(windowCtx)
		if ferr != nil {
			break // 窗口到点或停机:以已聚合的批次收口
		}
		items = append(items, c.wrapFetched(km))
	}
	return items
}

// wrapFetched 解析单条消息;坏 JSON 记日志跳过(仍在提交集内,Req 7.6)。
func (c *Consumer) wrapFetched(km kafka.Message) roundItem {
	item := roundItem{raw: km}
	if jerr := json.Unmarshal(km.Value, &item.parsed); jerr != nil {
		sdklog.Warnf(c.logger, "skip bad json topic=%s partition=%d offset=%d: %v",
			km.Topic, km.Partition, km.Offset, jerr)
		item.badJSON = true
	}
	return item
}

// collectMatched 组装交给 Handler 的子集(badJSON/验签失败/Filter 拒绝者不入),
// 但它们仍留在整轮提交集内(req 7.6/7.7)。同一轮的过滤判定日志仅记一次粒度=逐条 Debug。
func (c *Consumer) matchedOf(items []roundItem) []roundItem {
	out := make([]roundItem, 0, len(items))
	for _, it := range items {
		if it.badJSON {
			continue
		}
		if r := c.cfg.Verifier.VerifyFor(it.raw.Topic, string(it.raw.Value)); r != VerifyPass {
			sdklog.Warnf(c.logger, "notify verify failed(%s) topic=%s partition=%d offset=%d bizId=%s: dropped",
				r, it.raw.Topic, it.raw.Partition, it.raw.Offset, it.parsed.BizID)
			continue
		}
		if c.cfg.Filter != nil && !c.cfg.Filter(it.parsed) {
			sdklog.Debugf(c.logger, "filtered out bizId=%s eventType=%s", it.parsed.BizID, it.parsed.EventType)
			continue
		}
		out = append(out, it)
	}
	return out
}

// processRound 一轮的业务处理与位点终结。永不返回致命错误——所有失败都收敛成
// "告警后提交并继续"(REQ 7.5),保证其他消息不被单批拖垮。
func (c *Consumer) processRound(hctx context.Context, conn *connections, items []roundItem) {
	commitAll := func(reason string) {
		msgs := make([]kafka.Message, len(items))
		for i := range items {
			msgs[i] = items[i].raw
		}
		commitCtx, ccancel := context.WithTimeout(context.WithoutCancel(hctx), commitTimeout)
		err := conn.reader.CommitMessages(commitCtx, msgs...)
		ccancel()
		if err != nil {
			// 提交失败不致命:未提交位点会被重新消费;幂等由接入方吸收(design 偏差声明)
			sdklog.Warnf(c.logger, "commit failed(%s), messages will be redelivered: %v", reason, err)
		} else if c.debugEnabled() {
			sdklog.Debugf(c.logger, "committed %d messages (%s)", len(msgs), reason)
		}
	}

	matched := c.matchedOf(items)
	if len(matched) == 0 { // 空匹配集也提交(过滤/坏 JSON 消息不卡位点)
		commitAll("no-matched")
		return
	}

	batch := make([]Notification, len(matched))
	for i, m := range matched {
		batch[i] = m.parsed
	}

	handlerErr := c.runHandler(hctx, batch)
	if handlerErr == nil {
		commitAll("handler-ok")
		return
	}
	if hctx.Err() != nil {
		// 熔断/外部取消打断重试:位点不动,等待重投(安全面优先于推进)
		sdklog.Warnf(c.logger, "batch interrupted before commit: %v", handlerErr)
		return
	}

	// ---- 重试耗尽 ----
	finalErr := fmt.Errorf("%w: %v", ErrBatchExhausted, lastNonNil(handlerErr))
	sdklog.Errorf(c.logger, "batch exhausted: %v", lastNonNil(handlerErr))
	c.fireOnBatchError(batch, finalErr)
	commitAll("exhausted-alert")
}

// runHandler 以 RetryCount×RetryInterval 重试执行业务回调。
// 回调 panic 视为本批失败进重试面(进程不死);hctx 生效立即放弃本轮提交机会。
func (c *Consumer) runHandler(hctx context.Context, batch []Notification) error {
	var last error
	for attempt := 0; attempt < c.cfg.RetryCount; attempt++ {
		if aerr := hctx.Err(); aerr != nil {
			return errOr(last, aerr)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					last = fmt.Errorf("handler panic: %v", r)
				}
			}()
			last = c.handler(hctx, batch)
		}()
		if last == nil {
			return nil
		}
		if attempt < c.cfg.RetryCount-1 {
			t := time.NewTimer(c.cfg.RetryInterval)
			select {
			case <-t.C:
			case <-hctx.Done():
				t.Stop()
				return errOr(last, hctx.Err())
			}
		}
	}
	return last
}

func (c *Consumer) fireOnBatchError(batch []Notification, err error) {
	if c.cfg.OnBatchError == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			sdklog.Errorf(c.logger, "OnBatchError panicked: %v", r)
		}
	}()
	c.cfg.OnBatchError(batch, err)
}

// running 报告是否继续取数:外部取消与用户 Stop 任一发生即否。
func (c *Consumer) running(parent context.Context) bool {
	select {
	case <-parent.Done():
		return false
	case <-c.stopCh:
		return false
	default:
		return true
	}
}

// ---- 取消面编排 ----

// newFetchCtx 组装取数上下文:parent / stopCh 任一关闭即取消。
// (Stop 立刻解除 FetchMessage 阻塞,满足"停机即不再拉新";无 deadline——
// 聚批窗口自首条消息起算,由 pollBatch 自行计时。)
func (c *Consumer) newFetchCtx(parent context.Context) (context.Context, context.CancelFunc) {
	merged := mergedDone(parent.Done(), c.stopCh)
	return context.WithCancel(merged)
}

// newHandlerCtx 组装回调上下文:不随 parent/Stop 立即取消(在途批次做完),
// 仅当 ① parent 外部真取消 或 ② Stop 已超过 GracefulTimeout(fuse)时熔断。
func (c *Consumer) newHandlerCtx(parent context.Context) context.Context {
	base := context.WithoutCancel(parent)
	ctx, cancel := context.WithCancel(base)
	go func() {
		select {
		case <-parent.Done():
		case <-c.fuseCh:
		case <-c.doneCh: // 兜底:循环退出后不留悬空 goroutine
		case <-ctx.Done():
			return
		}
		cancel()
	}()
	return ctx
}

// mergedDone 返回一个在任一输入通道关闭时即关闭的通道(no背景取消语义)。
func mergedDone(dones ...<-chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		for _, d := range dones {
			if d == nil {
				continue
			}
			select {
			case <-d:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return ctx
}

// loadErr 原子读出启动/重连期致命错误(无则 nil)。
func (c *Consumer) loadErr() error {
	if p := c.lastErr.Load(); p != nil {
		return *p
	}
	return nil
}

// sleepInterruptible 可被 Stop/外部取消提前唤醒的休眠;返回 false=收到了停机信号。
// 此前 fetch 退避用裸 time.Sleep,停机信号落在退避窗口内时要白等最多 30s。
func (c *Consumer) sleepInterruptible(d time.Duration, parent context.Context) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-parent.Done():
		return false
	case <-c.stopCh:
		return false
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func errOr(prefer, fallback error) error {
	if prefer != nil {
		return prefer
	}
	return fallback
}

func lastNonNil(e error) error {
	if e != nil {
		return e
	}
	return errors.New("unknown batch failure")
}

// debugEnabled 收口调试开关判定(Logger 实现若为安静型则零成本)。
func (c *Consumer) debugEnabled() bool { return true }

// ErrBatchExhausted 标记批次重试耗尽这一终局形态。
var ErrBatchExhausted = errors.New("notify: batch exhausted after retries")

// commitTimeout 限定位点提交的单次阻塞上限:broker 半死时宁可本次失败
// (走重投/告警路径),也不无限拖住消费循环。
const commitTimeout = 10 * time.Second
