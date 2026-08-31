package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	kafka "github.com/segmentio/kafka-go"

	"github.com/decodeex/bifu-risk-sdk/sdklog"
)

// 本文件实现审核通知的消费全生命周期(design.md System Flows·通知消费):
//
//	聚批(FetchMessage × PollMaxRecords / PollTimeout 窗口)
//	  → 坏 JSON 记日志跳过(仍在提交集)/ Filter 拒绝不入 Handler(仍在提交集)
//	  → Handler 成功 → 提交本批全部位点
//	  → 失败按 RetryCount×RetryInterval 重试;恢复则提交
//	  → 耗尽:配了 DLQ 先投死信再提交;未配 OnBatchError 告警后提交,继续消费
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

// writerAPI 是死信生产所需的最小 broker 面;kafka.Writer 天然满足。
type writerAPI interface {
	WriteMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

// connections 是运行期持有的连接束。
type connections struct {
	reader readerAPI
	dlq    writerAPI // 未配 DLQ 时为 nil
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

	startMu  sync.Mutex
	started  bool
	stopOnce sync.Once
	stopCh   chan struct{} // 关闭即停止拉取
	fuseCh   chan struct{} // Stop 后经 GracefulTimeout 关闭:在途批次强收
	doneCh   chan struct{} // 循环完全退出
	lastErr  error
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

// Start 以独立 goroutine 启动消费循环并立即返回 nil(已受理);重复调用幂等。
func (c *Consumer) Start(ctx context.Context) error {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.started {
		return nil
	}
	c.started = true
	go c.run(ctx)
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
	return c.lastErr
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
	return c.lastErr
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
	raw       kafka.Message
	parsed    Notification
	badJSON   bool
	skipParse bool
}

// ---- 消费主循环 ----

func (c *Consumer) run(parent context.Context) {
	defer close(c.doneCh)

	conn, cerr := c.newConn(c.cfg)
	if cerr != nil {
		c.lastErr = fmt.Errorf("notify: connect brokers: %w", cerr)
		sdklog.Errorf(c.logger, "consumer 启动失败: %v", c.lastErr)
		return
	}
	defer func() { _ = conn.reader.Close() }()
	if conn.dlq != nil {
		defer func() { _ = conn.dlq.Close() }()
	}

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
}

// pollBatch 聚批:首条 FetchMessage 阻塞等待(仅受 parent/Stop 取消),
// 收到首条后以 PollTimeout 为聚合窗口继续拉至 PollMaxRecords。
// 设计勘误(联调修正,2026-08-31):原实现给每条 fetch 挂独立窗口,消费组 join
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
		sdklog.Errorf(c.logger, "fetch error(退避重试): %v", err)
		time.Sleep(minDur(c.cfg.RetryInterval, 5*time.Second))
		return []roundItem{}
	}
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

// collectMatched 组装交给 Handler 的子集(badJSON/Filter 拒绝者不入),
// 但它们仍留在整轮提交集内(req 7.6/7.7)。同一轮的过滤判定日志仅记一次粒度=逐条 Debug。
func (c *Consumer) matchedOf(items []roundItem) []roundItem {
	out := make([]roundItem, 0, len(items))
	for _, it := range items {
		if it.badJSON {
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
		if err := conn.reader.CommitMessages(context.WithoutCancel(hctx), msgs...); err != nil {
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
	rawFailed := make([]kafka.Message, 0, len(matched))
	for _, m := range matched {
		rawFailed = append(rawFailed, m.raw)
	}
	if conn.dlq != nil {
		werr := conn.dlq.WriteMessages(context.WithoutCancel(hctx), rawFailed...)
		if werr == nil {
			sdklog.Errorf(c.logger, "batch exhausted → DLQ(%s): %v", c.cfg.DLQTopic, lastNonNil(handlerErr))
			c.fireOnBatchError(batch, finalErr)
			commitAll("dlq-done")
			return
		}
		finalErr = fmt.Errorf("%v; dlq write failed: %v", finalErr.Error(), werr)
		sdklog.Errorf(c.logger, "%v", finalErr)
		c.fireOnBatchError(batch, finalErr)
		commitAll("dlq-fail-alert")
		return
	}
	sdklog.Errorf(c.logger, "batch exhausted(no DLQ): %v", lastNonNil(handlerErr))
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
