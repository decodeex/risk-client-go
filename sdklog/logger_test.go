package sdklog_test

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/decodeex/bifu-risk-sdk/sdklog"
)

// hostLogAdapter 模拟接入方（宿主服务）自带日志设施的一行适配桥，
// 用于验证最小接口足够小、宿主无需妥协即可接入。
type hostLogAdapter struct {
	calls []string
}

func (h *hostLogAdapter) Debugf(format string, args ...any) {
	h.calls = append(h.calls, "DEBUG:"+format)
}
func (h *hostLogAdapter) Infof(format string, args ...any) { h.calls = append(h.calls, "INFO:"+format) }
func (h *hostLogAdapter) Warnf(format string, args ...any) { h.calls = append(h.calls, "WARN:"+format) }
func (h *hostLogAdapter) Errorf(format string, args ...any) {
	h.calls = append(h.calls, "ERROR:"+format)
}

// 编译期契约：默认实现必须满足 Logger 接口；宿主适配器也必须能满足该接口。
var (
	_ sdklog.Logger = sdklog.NewStdLogger()
	_ sdklog.Logger = (*sdklog.StdLogger)(nil)
	_ sdklog.Logger = &hostLogAdapter{}
)

// captureStdLog 用干净的缓冲区替换标准库 log 的输出与标志位，返回恢复函数。
// 关闭时间戳等标志位后即可对整行做精确断言。
func captureStdLog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prevWriter, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	return buf, func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	}
}

func TestStdLoggerLevelsAndFormatting(t *testing.T) {
	buf, restore := captureStdLog(t)
	defer restore()

	l := sdklog.NewStdLogger()
	l.Debugf("detail body=%v", map[string]int{"k": 1})
	l.Infof("call done in %d ms", 3)
	l.Warnf("no timeout configured for event %q", "LOGIN")
	l.Errorf("gateway returned code=%d", 500)

	got := buf.String()
	for _, want := range []string{
		"DEBUG detail body=map[k:1]\n",
		"INFO call done in 3 ms\n",
		"WARN no timeout configured for event \"LOGIN\"\n",
		"ERROR gateway returned code=500\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("标准库日志输出缺少期望行\nwant: %q\ngot : %q", want, got)
		}
	}
	if lines := strings.Count(got, "\n"); lines != 4 {
		t.Fatalf("四条日志应各占一行,实际换行数=%d,输出=%q", lines, got)
	}
}

func TestStdLoggerFormatVerbsPassThrough(t *testing.T) {
	buf, restore := captureStdLog(t)
	defer restore()

	sdklog.NewStdLogger().Infof("percent%%literal-%s-%02d", "ok", 7)

	want := "INFO percent%literal-ok-07\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("格式化动词未被透传\nwant: %q\ngot : %q", want, buf.String())
	}
}

func TestStdLoggerNoArgsKeepsPercentLiterals(t *testing.T) {
	buf, restore := captureStdLog(t)
	defer restore()

	// 格式串动态拼出字面 %（报文/URL 里常见），模拟“无参数但正文含 %”的真实调用。
	format := "progress " + string(rune('%')) + " done, ratio" + string(rune('%')) + "3f"
	sdklog.NewStdLogger().Warnf(format)

	want := "WARN progress % done, ratio%3f\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("无参数时不应再做一次 Sprintf 以免吞掉 %% 字符\nwant: %q\ngot : %q", want, buf.String())
	}
}

func TestStdLoggerConcurrentUse(t *testing.T) {
	_, restore := captureStdLog(t)
	defer restore()

	l := sdklog.NewStdLogger()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				l.Infof("g=%d i=%d", id, i)
				l.Errorf("g=%d failed", id)
			}
		}(g)
	}
	wg.Wait()
}

func TestHostAdapterSatisfiesInterface(t *testing.T) {
	var l sdklog.Logger = &hostLogAdapter{}
	l.Infof("bridge")
	l.Errorf("boom")
	l.Warnf("careful")
	l.Debugf("trace")
}
