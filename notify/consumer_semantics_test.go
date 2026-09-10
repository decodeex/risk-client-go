package notify

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"encoding/json"
	"strconv"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

// ---------------------------------------------------------------------------
// 消费语义全分支(任务 4.5):每个分支对应消费流程图的一个节点。
// ---------------------------------------------------------------------------

// TestConfigValidateMatrix 覆盖 4.1 的 Validate 与默认值落位。
func TestConfigValidateMatrix(t *testing.T) {
	base := ConsumerConfig{Brokers: []string{"b:9092"}, GroupID: "g", Topics: []string{"t"},
		Verifier: flowVerifier(t)}
	for name, mutate := range map[string]func(*ConsumerConfig){
		"缺 brokers":  func(c *ConsumerConfig) { c.Brokers = nil },
		"空 broker":   func(c *ConsumerConfig) { c.Brokers = []string{" "} },
		"缺 group":    func(c *ConsumerConfig) { c.GroupID = " " },
		"缺 topics":   func(c *ConsumerConfig) { c.Topics = nil },
		"缺 verifier": func(c *ConsumerConfig) { c.Verifier = nil },
		"坏 sasl":     func(c *ConsumerConfig) { c.SASL.Mechanism = "kerberos" },
	} {
		c := base
		mutate(&c)
		if _, err := c.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s 应报 ErrInvalidConfig,得 %v", name, err)
		}
	}
	got, err := base.Validate() // 零值可选字段全部落默认
	if err != nil {
		t.Fatal(err)
	}
	if got.PollMaxRecords != 10 || got.RetryCount != 3 || got.RetryInterval.String() != "1s" ||
		got.GracefulTimeout != 10*1e9 || got.Logger == nil {
		t.Fatalf("默认值落位不符:%+v", got)
	}
}

// TestNotificationAuditTimeStringTolerance:auditTime 字符串形态兼容。
func TestNotificationAuditTimeStringTolerance(t *testing.T) {
	var n Notification
	raw := `{"bizId":"b","riskId":"r","eventType":"e","auditResult":"accept","auditTime":"1756272000000"}`
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatal(err)
	}
	if n.AuditTime != 1756272000000 || n.BizID != "b" {
		t.Fatalf("%+v", n)
	}
	bad := &Notification{}
	if json.Unmarshal([]byte(`{"auditTime":"abc"}`), bad) == nil {
		t.Fatal("不可解析字符串应报错")
	}
}

// TestNormalAndSkipCommit 主链路:好消息进 Handler,坏 JSON/过滤掉的仍在提交集内,
// 位点整批提交不丢(req 7.1/7.2/7.6/7.7)。Filter 拒绝的 bizId=skip-me 不出现在回调里。
func TestNormalAndSkipCommit(t *testing.T) {
	r := &fakeReader{queue: []kafka.Message{
		msg(notifJSON("a-1", "accept")),
		msg(`not-json`),
		msg(notifJSON("a-2", "reject")),
		msg(notifJSON("skip-me", "accept")),
	}}
	var (
		gmu sync.Mutex
		got []string
	)
	cfg := fastCfg()
	cfg.Filter = func(n Notification) bool { return !strings.HasPrefix(n.BizID, "skip") }
	cli := newTestConsumer(t, cfg, func(_ context.Context, b []Notification) error {
		gmu.Lock()
		for _, n := range b {
			got = append(got, n.BizID)
		}
		n := len(got)
		gmu.Unlock()
		_ = n
		return nil
	}, r)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitFor(t, time.Second*3, func() bool {
			gmu.Lock()
			defer gmu.Unlock()
			return len(got) == 2
		}, "处理完成")
		cancel()
	}()
	if err := cli.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	gmu.Lock()
	defer gmu.Unlock()
	if len(got) != 2 || strings.Join(got, ",") != "a-1,a-2" {
		t.Fatalf("回调应只收到放行消息:%v", got)
	}
	fetches, _, committed := r.stats()
	if committed != 4 {
		t.Fatalf("位点必须覆盖全部 4 条(含坏与过滤),实际 %d", committed)
	}
	_ = fetches
}

// TestRetryRecoverThenCommit:第 1、2 次失败,第 3 次成功 → 提交(req 7.3)。
func TestRetryRecoverThenCommit(t *testing.T) {
	r := &fakeReader{queue: []kafka.Message{msg(notifJSON("r-1", "reject"))}}
	var attempts atomic.Int32
	cli := newTestConsumer(t, fastCfg(), func(_ context.Context, _ []Notification) error {
		if attempts.Add(1) < 3 {
			return errors.New("transient")
		}
		return nil
	}, r)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 3 }, "重试收敛")
		cancel()
	}()
	if err := cli.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_, _, committed := r.stats()
	if attempts.Load() != 3 || committed != 1 {
		t.Fatalf("重试后应恢复并提交:attempts=%d committed=%d", attempts.Load(), committed)
	}
}

// TestExhaustedAlertOnly:耗尽=告警+照常提交+继续(req 7.4/7.5)。
// SDK 不内置死信:失败批次由宿主在 OnBatchError 里自行转存,恢复靠案件查询补偿。
func TestExhaustedAlertOnly(t *testing.T) {
	r := &fakeReader{queue: []kafka.Message{
		msg(notifJSON("bad", "reject")),
		msg(notifJSON("good-after", "accept")),
	}}
	alerts := 0
	var doneOnce sync.Once
	done := make(chan struct{})
	firstFailDone := false
	cli := newTestConsumer(t, fastCfg(), func(_ context.Context, b []Notification) error {
		if b[0].BizID == "bad" {
			firstFailDone = true
			doneOnce.Do(func() { close(done) })
			return errors.New("boom")
		}
		return nil
	}, r)
	cli.cfg.OnBatchError = func(_ []Notification, err error) {
		alerts++
		if !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "batch exhausted") {
			t.Errorf("告警错误链不符:%v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-done
		time.Sleep(60 * time.Millisecond) // 给第二轮留时间
		cancel()
	}()
	if err := cli.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if alerts != 1 || !firstFailDone {
		t.Fatalf("耗尽必须触发一次告警(%d)", alerts)
	}
	_, _, committed := r.stats()
	if committed != 2 {
		t.Fatalf("告警路径也要提交位点,保证继续消费:%d", committed)
	}
}

// TestGracefulStopCompletesInFlight:Stop 立即停拉取;在途回调完成后照常提交(req 7.8)。
func TestGracefulStopCompletesInFlight(t *testing.T) {
	r := &fakeReader{queue: []kafka.Message{
		msg(notifJSON("inflight", "accept")),
		msg(notifJSON("never-seen", "accept")), // Stop 后不应再被消费
	}}
	handlerDone := make(chan struct{})
	cfg := fastCfg()
	cfg.PollMaxRecords = 1 // 每轮恰好一条,保证"在途=第一条、Stop 挡住第二条"
	cli := newTestConsumer(t, cfg, func(_ context.Context, b []Notification) error {
		<-handlerDone // 人为拖住在途批次,等 Stop 先发生
		return nil
	}, r)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- cli.Run(ctx) }()

	// 等 in-flight 进入 handler 后触发 Stop
	waitFor(t, 2*time.Second, func() bool {
		f, _, _ := r.stats()
		return f >= 1
	}, "进入在途批次")
	stopReturned := make(chan error, 1)
	go func() { stopReturned <- cli.Stop(context.Background()) }()
	<-cli.stopCh // 同包直读:确保"停止拉取"信号确实已生效再放开在途回调
	close(handlerDone)

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("优雅退出不应有致命错:%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未在 GracefulTimeout 内退出")
	}
	if serr := <-stopReturned; serr != nil {
		t.Fatalf("Stop 返回不应有致命错:%v", serr)
	}
	_, _, committed := r.stats()
	if committed != 1 { // 在途批次提交;第二条 never-seen 不再拉取
		t.Fatalf("只应提交在途的 1 条:%d", committed)
	}
	if len(r.queue) != 1 {
		t.Fatalf("Stop 后剩余消息应留在 broker,不该被取走")
	}
}

// TestZeroConnectionBeforeStart:req 7.10 —— 构造零连接;Start 触发工厂才建立。
func TestZeroConnectionBeforeStart(t *testing.T) {
	var connected atomic.Int32
	cli := newTestConsumer(t, fastCfg(), func(context.Context, []Notification) error {
		return nil
	}, &fakeReader{})
	cli.newConn = func(cfg ConsumerConfig) (*connections, error) {
		connected.Add(1)
		return &connections{reader: &fakeReader{blockMode: true}}, nil
	}
	if connected.Load() != 0 {
		t.Fatal("NewConsumer 不得建立任何连接")
	}
	_ = cli.Start(context.Background())
	waitFor(t, time.Second, func() bool { return connected.Load() == 1 }, "Start 建连")
	_ = cli.Stop(context.Background())
}

// TestTwoConsumersShareLoad:同组多实例分摊——共享队列的两消费者合计恰好各消费一遍(req 7.9 行为面)。
func TestTwoConsumersShareLoad(t *testing.T) {
	const total = 8
	var (
		mu   sync.Mutex
		seen sync.Map
		cnt  int
	)
	makeHandler := func() Handler {
		return func(_ context.Context, b []Notification) error {
			for _, n := range b {
				mu.Lock()
				if _, dup := seen.LoadOrStore(n.BizID, true); !dup {
					cnt++
				}
				mu.Unlock()
			}
			return nil
		}
	}

	shared := &sharedQueue{}
	for i := 0; i < total; i++ {
		shared.push(msg(notifJSON("biz-"+strconv.Itoa(i), "accept")))
	}
	factory := func() *Consumer {
		reader := shared.newReader()
		c := newTestConsumer(t, fastCfg(), makeHandler(), reader)
		return c
	}
	c1, c2 := factory(), factory()

	var wg sync.WaitGroup
	wg.Add(2)
	for _, c := range []*Consumer{c1, c2} {
		cc := c
		go func() { defer wg.Done(); _ = cc.Run(context.Background()) }()
	}
	waitFor(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return cnt == total
	}, "两组合计消费完全部消息")
	stopCtx, sc := context.WithTimeout(context.Background(), time.Second)
	go func() { // 收尾
		_ = c1.Stop(stopCtx)
		_ = c2.Stop(stopCtx)
		sc()
	}()
	wg.Wait()
	_ = stopCtx
	mu.Lock()
	defer mu.Unlock()
	if cnt != total {
		t.Fatalf("应有且仅有 %d 条被处理:%d", total, cnt)
	}
}

// sharedQueue 是两个假 reader 共享的原子队列(同一"分区"被组内成员分摊)。
type sharedQueue struct {
	mu    sync.Mutex
	items []kafka.Message
}

func (s *sharedQueue) push(m kafka.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, m)
}

func (s *sharedQueue) pop() (kafka.Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) == 0 {
		return kafka.Message{}, false
	}
	m := s.items[0]
	s.items = s.items[1:]
	return m, true
}

func (s *sharedQueue) newReader() *fakeReader {
	f := &fakeReader{}
	f.hijack(func() (kafka.Message, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.items) == 0 {
			return kafka.Message{}, false
		}
		m := s.items[0]
		s.items = s.items[1:]
		return m, true
	})
	return f
}

// panickyReader:FetchMessage 直接 panic,模拟引擎层非预期异常(验证顶层 recover)。
type panickyReader struct{ fakeReader }

func (p *panickyReader) FetchMessage(ctx context.Context) (kafka.Message, error) {
	panic("boom: unexpected internal error")
}

// TestConsumeLoopRecoversPanicWithoutKillingProcess:循环内任何 panic 被 recover,
// 记录后走"重建连接继续消费"路径,宿主进程绝不带崩(Req 4.4 的消费侧兜底)。
func TestConsumeLoopRecoversPanicWithoutKillingProcess(t *testing.T) {
	cfg := fastCfg()
	cfg.PollTimeout = 50 * time.Millisecond
	cli := newTestConsumer(t, cfg, func(context.Context, []Notification) error {
		return nil
	}, &fakeReader{})
	cli.newConn = func(cfg ConsumerConfig) (*connections, error) {
		return &connections{reader: &panickyReader{fakeReader: fakeReader{}}}, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic 漏出到 consumeLoop 之外:%v", r)
				}
			}()
			c := cli
			conn, err := c.newConn(c.cfg)
			if err != nil {
				t.Error(err)
				return
			}
			_ = c.consumeLoop(context.Background(), conn) // 期待:内部 recover,正常返回
		}()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("consumeLoop 未在预期时间内返回")
	}
}

// oncePanickyReader:第一次 Fetch panic(模拟非预期异常),之后交给正常队列。
type oncePanickyReader struct {
	fakeReader
	panicked atomic.Bool
}

func (p *oncePanickyReader) FetchMessage(ctx context.Context) (kafka.Message, error) {
	if p.panicked.CompareAndSwap(false, true) {
		panic("boom: kafka-go internal surprise")
	}
	return p.fakeReader.FetchMessage(ctx)
}

// TestRunReconnectsAfterPanic:🔴 级回归——panic 后必须重建连接继续消费,
// 而不是静默停止消费(此前重连条件写反,panic 即消费永久停摆)。
func TestRunReconnectsAfterPanic(t *testing.T) {
	shared := &sharedQueue{}
	shared.push(msg(notifJSON("after-reconnect", "accept")))

	var got atomic.Int32
	cli := newTestConsumer(t, fastCfg(), func(_ context.Context, b []Notification) error {
		got.Add(int32(len(b)))
		return nil
	}, nil)
	reader := &oncePanickyReader{fakeReader: fakeReader{}}
	reader.hijack(shared.pop) // 首连 panic;重连后的同一 reader 从共享队列取消息
	cli.newConn = func(cfg ConsumerConfig) (*connections, error) {
		return &connections{reader: reader}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = cli.Run(ctx) }()

	waitFor(t, 8*time.Second, func() bool { return got.Load() >= 1 }, "panic 后重连并消费到消息")
	cancel()
	<-runDone
}

// sharedQueue.push/pop 供分摊测试与重连测试共用。
