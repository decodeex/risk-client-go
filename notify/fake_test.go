package notify

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	kafka "github.com/segmentio/kafka-go"

	"github.com/decodeex/bifu-risk-sdk/sdklog"
)

// ---------------------------------------------------------------------------
// 假 broker 设施:与真实 kafka.Reader/Writer 无关的内存实现,
// 供消费循环语义测试一次性定形(任务 4.2 首条交付物,4.3/4.5 复用)。
// ---------------------------------------------------------------------------

// fakeReader 按 FIFO 吐出队列消息;支持注入一次性的错误序列与提交记录。
type fakeReader struct {
	mu sync.Mutex

	queue     []kafka.Message
	errQueue  []error // 每次Fetch先弹一个(nil 表示成功)
	fetches   int
	commits   [][]kafka.Message
	closeCnt  int
	blockMode bool // true 时 Fetch 阻塞直到 ctx 取消(模拟空 topic 等待)

	hijackFn func() (kafka.Message, bool) // 测试注入的自定义弹队策略(优先于 queue)
}

// hijack 注入自定义弹队逻辑(fn 返回 false 时按"窗口无消息"处理)。
func (f *fakeReader) hijack(fn func() (kafka.Message, bool)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hijackFn = fn
}

func (f *fakeReader) FetchMessage(ctx context.Context) (kafka.Message, error) {
	f.mu.Lock()
	if f.fetches++; f.hijackFn != nil {
		m, ok := f.hijackFn()
		f.mu.Unlock()
		if !ok {
			select {
			case <-ctx.Done():
				return kafka.Message{}, context.Canceled
			case <-time.After(20 * time.Millisecond):
				return kafka.Message{}, context.DeadlineExceeded
			}
		}
		time.Sleep(2 * time.Millisecond)
		return m, nil
	}
	if len(f.errQueue) > 0 {
		e := f.errQueue[0]
		f.errQueue = f.errQueue[1:]
		f.mu.Unlock()
		return kafka.Message{}, e
	}
	if len(f.queue) > 0 {
		m := f.queue[0]
		f.queue = f.queue[1:]
		f.mu.Unlock()
		time.Sleep(2 * time.Millisecond) // 轻微间隔让聚批窗口有机会合批
		return m, nil
	}
	block := f.blockMode
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return kafka.Message{}, context.Canceled
	}
	select { // 无消息:模拟窗口到期
	case <-ctx.Done():
		return kafka.Message{}, context.Canceled
	case <-time.After(20 * time.Millisecond):
		return kafka.Message{}, context.DeadlineExceeded
	}
}

func (f *fakeReader) CommitMessages(_ context.Context, msgs ...kafka.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]kafka.Message, len(msgs))
	copy(cp, msgs)
	f.commits = append(f.commits, cp)
	return nil
}

func (f *fakeReader) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCnt++
	return nil
}

func (f *fakeReader) stats() (fetches, closeCnt int, committed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commits {
		committed += len(c)
	}
	return f.fetches, f.closeCnt, committed
}

type fakeWriter struct {
	mu     sync.Mutex
	msgs   []kafka.Message
	failN  int // 前 N 次写失败(验证回落告警路径)
	writes int
}

func (w *fakeWriter) WriteMessages(_ context.Context, msgs ...kafka.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writes++; w.failN >= w.writes {
		return errors.New("forced dlq failure")
	}
	w.msgs = append(w.msgs, msgs...)
	return nil
}
func (w *fakeWriter) Close() error { return nil }
func (w *fakeWriter) size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.msgs)
}

// msg 快捷构造。
func msg(val string) kafka.Message {
	return kafka.Message{Topic: "RISK_AUDIT_RESULT_NOTIFY", Partition: 0,
		Key: []byte("k"), Value: []byte(val)}
}
func notifJSON(bizID string, result string) string {
	return `{"bizId":"` + bizID + `","riskId":"r","eventType":"withdraw","auditResult":"` +
		result + `","auditRemark":"","auditUser":"a","auditTime":1756272000000}`
}

// newTestConsumer 构造注入了假连接的消费器(覆盖工厂字段是同包测试特权)。
func newTestConsumer(t *testing.T, cfg ConsumerConfig, h Handler,
	reader *fakeReader, dlq *fakeWriter) *Consumer {
	t.Helper()
	validated, verr := cfg.Validate()
	if verr != nil {
		t.Fatal(verr)
	}
	c := &Consumer{
		cfg: validated, handler: h,
		logger: sdklog.Default(),
		stopCh: make(chan struct{}),
		fuseCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	c.newConn = func(cc ConsumerConfig) (*connections, error) {
		conn := &connections{reader: reader}
		if cc.DLQTopic != "" && dlq != nil {
			conn.dlq = dlq
		}
		return conn, nil
	}
	return c
}

// fastCfg 快节奏配置:窗口/重试都毫秒级,方便测试在秒内收敛。
func fastCfg(dlqTopic string) ConsumerConfig {
	return ConsumerConfig{
		Brokers:         []string{"127.0.0.1:9092"},
		GroupID:         "it-" + time.Now().Format("150405"),
		Topics:          []string{"RISK_AUDIT_RESULT_NOTIFY"},
		PollMaxRecords:  10,
		PollTimeout:     60 * time.Millisecond,
		RetryCount:      3,
		RetryInterval:   15 * time.Millisecond,
		DLQTopic:        dlqTopic,
		GracefulTimeout: 1500 * time.Millisecond,
		StartOffset:     OffsetEarliest,
	}
}

// waitFor 轮询条件直到满足或超时(t.Fatal)。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时:%s", what)
}

var _ writerAPI = (*fakeWriter)(nil)
var _ readerAPI = (*fakeReader)(nil)

// alertSnapshot 在互斥下读告警文案(测试用小助手)。
func alertSnapshot(mu *sync.Mutex, s *string) string {
	mu.Lock()
	defer mu.Unlock()
	return *s
}
