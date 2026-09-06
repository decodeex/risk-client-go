package riskclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/decodeex/risk-client-go/sdklog"
)

// memLogger 收集全部输出行,供开关语义断言;编译期锁定 sdklog.Logger 接口契约。
var _ sdklog.Logger = (*memLogger)(nil)

type memLogger struct {
	mu   sync.Mutex
	rows []string
}

func (m *memLogger) Debugf(format string, args ...any) {
	m.append("DEBUG " + fmt.Sprintf(format, args...))
}
func (m *memLogger) Infof(format string, args ...any) {
	m.append("INFO " + fmt.Sprintf(format, args...))
}
func (m *memLogger) Warnf(format string, args ...any) {
	m.append("WARN " + fmt.Sprintf(format, args...))
}
func (m *memLogger) Errorf(format string, args ...any) {
	m.append("ERROR " + fmt.Sprintf(format, args...))
}
func (m *memLogger) append(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, s)
}
func (m *memLogger) all() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Join(m.rows, "\n")
}

// TestLogDetailSwitchSemantics 锁定 Req 8.1/8.2:
// 开 → 输出含 [detail] 前缀的报文行(URL/头/body);关 → 无报文内容、仅调用摘要与错误。
func TestLogDetailSwitchSemantics(t *testing.T) {
	spkiB64, _ := fixturePublicKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":"200","msg":"","data":{"riskId":"R","strategy":"accept"}}`)
	}))
	defer srv.Close()

	run := func(detail bool) string {
		mem := &memLogger{}
		cli, err := New(Config{
			BaseURL: srv.URL, ClientID: "c", ClientSecret: "s", PublicKey: spkiB64,
			EventTimeoutMs: map[string]int64{"login": 2000}, LogDetail: detail,
		}, WithLogger(mem), WithRequestIP("127.0.0.1"),
			WithTraceIDFunc(func() (string, error) { return "t", nil }))
		if err != nil {
			t.Fatal(err)
		}
		if _, rerr := cli.Risk(context.Background(),
			BasicParam{BizID: "b-1", EventType: "login"}, map[string]any{"amount": "9"}, nil); rerr != nil {
			t.Fatal(rerr)
		}
		return mem.all()
	}

	on := run(true)
	off := run(false)

	for _, marker := range []string{"[detail]", `"amount":"9"`, "headers="} {
		if !strings.Contains(on, marker) {
			t.Fatalf("明细开应包含 %q\n日志:\n%s", marker, on)
		}
	}
	if strings.Contains(off, "[detail]") || strings.Contains(off, `"amount"`) ||
		strings.Contains(off, "X-SIGNATURE") {
		t.Fatalf("明细开关闭时不得泄露报文内容:\n%s", off)
	}
	if !strings.Contains(off, "[risk] POST") || !strings.Contains(off, `code=200`) {
		t.Fatalf("摘要日志始终存在:\n%s", off)
	}
	var _ = fmt.Sprint // 保持 fmt 引用(测试体使用 Fprintf 之外的场景)
}
