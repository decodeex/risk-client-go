package protocol

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// uuidV4Pattern 是 RFC 4122 v4 的完整形态:版本位必须 '4',变体位必须是 8/9/a/b。
var uuidV4Pattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewUUIDv4FormatAndBits(t *testing.T) {
	for i := 0; i < 200; i++ {
		id, err := NewUUIDv4()
		if err != nil {
			t.Fatalf("第 %d 次: NewUUIDv4 报错 %v", i, err)
		}
		if !uuidV4Pattern.MatchString(id) {
			t.Fatalf("UUID 形态非法(版本/变体位或字符集): %q", id)
		}
		if len(id) != 36 { // 32 hex + 4 连字符
			t.Fatalf("UUID 长度应为 36,得 %d(%q)", len(id), id)
		}
	}
}

func TestNewUUIDv4UniquenessSmoke(t *testing.T) {
	seen := make(map[string]struct{}, 2000)
	for i := 0; i < 2000; i++ {
		id, err := NewUUIDv4()
		if err != nil {
			t.Fatalf("NewUUIDv4 报错 %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("2000 次采样内出现重复 %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestNowMillisIsNearWallClock(t *testing.T) {
	before := timeNowUnixMilli()
	got := NowMillis()
	after := timeNowUnixMilli()
	if got < before || got > after {
		t.Fatalf("NowMillis=%d 不在毫秒墙钟区间 [%d,%d]", got, before, after)
	}
}

// TestInjectSystemFieldsMatchesGoldenSampleShape 用 case_payload.json 的 sysFields
// 夹具值注入后,五个键的键名/类型/取值与 golden 完全一致(*Note 说明键除外)。
func TestInjectSystemFieldsMatchesGoldenSampleShape(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/case_payload.json")
	if err != nil {
		t.Fatalf("读取 golden 失败: %v", err)
	}
	var doc struct {
		Samples []struct {
			SysFields map[string]any `json:"sysFields"`
		} `json:"samples"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}
	golden := doc.Samples[0].SysFields // sample A:固定夹具值

	m := map[string]any{"bizData": "keep-me"} // 业务键不应被动
	str := func(k string) string { v, _ := golden[k].(string); return v }
	num := func(k string) float64 { v, _ := golden[k].(float64); return v }

	InjectSystemFields(m, SystemFields{
		RequestTime:   int64(num("requestTime")),
		TraceID:       str("traceId"),
		ClientID:      str("clientId"),
		ClientVersion: str("clientVersion"),
		RequestIP:     str("requestIp"),
	})

	wantKeys := map[string]bool{
		"bizData": true,
		// 注入五键白名单(README §3.4:*Note 键是文档说明,不属于协议载荷)
		"requestTime": true, "traceId": true, "clientId": true,
		"clientVersion": true, "requestIp": true,
	}
	for k := range m {
		if !wantKeys[k] {
			t.Fatalf("出现预期外键 %q,完整 map=%v", k, m)
		}
	}
	for _, k := range []string{"requestTime", "traceId", "clientId", "clientVersion", "requestIp"} {
		switch k {
		case "requestTime":
			v, ok := m[k].(int64)
			if !ok {
				t.Fatalf("requestTime 必须是 int64 毫秒(Long 形态),得 %T(%v)", m[k], m[k])
			}
			if v != int64(num("requestTime")) {
				t.Fatalf("requestTime=%d,want %f", v, num("requestTime"))
			}
		default:
			if m[k] != golden[k] {
				t.Fatalf("%s=%v,want %v", k, m[k], golden[k])
			}
		}
	}
}

func TestReservedFieldNamesCoverInjectionAndProtocolFields(t *testing.T) {
	injected := []string{"requestTime", "traceId", "requestIp", "clientId", "clientVersion"}
	joined := strings.Join(ReservedFieldNames, ",")
	for _, name := range injected {
		if !strings.Contains(joined, name) {
			t.Fatalf("保留字段表缺少注入键 %q", name)
		}
	}
	if !strings.Contains(joined, "bizId") || !strings.Contains(joined, "eventType") {
		t.Fatal("保留字段表应覆盖 basicParam 协议字段")
	}
}

func timeNowUnixMilli() int64 { return NowMillis() }
