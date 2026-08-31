package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStatusOutcomeMatchesJavaHandler 逐档核对状态映射与中文文案(逐字对齐
// DefaultRiskResponseHandler.handleHttpStatus,含全角逗号)。
func TestStatusOutcomeMatchesJavaHandler(t *testing.T) {
	cases := []struct {
		status int
		code   string
		msg    string
	}{
		{429, "429", "请求过于频繁，请稍后再试"},
		{403, "403", "请求被拒绝，请检查权限"},
		{401, "401", "请求未授权，请先登录"},
		{408, "408", "请求风控服务超时，请稍后再试"},
		{400, "500", "服务异常，请稍后再试"}, // 其余非 200 一律 500 兜底
		{500, "500", "服务异常，请稍后再试"},
		{302, "500", "服务异常，请稍后再试"},
	}
	for _, tc := range cases {
		got := StatusOutcome(tc.status)
		if got.Code != tc.code || got.Msg != tc.msg {
			t.Fatalf("status %d: got {%s,%s} want {%s,%s}", tc.status, got.Code, got.Msg, tc.code, tc.msg)
		}
		if got.IsSuccess() {
			t.Fatalf("status %d 不应被判为成功", tc.status)
		}
	}
}

func TestTransportOutcomesMatchJavaCatchBranches(t *testing.T) {
	tm := TransportTimeoutOutcome("查询通用审核案件超时，请稍后再试")
	if tm.Code != "408" || tm.Msg != "查询通用审核案件超时，请稍后再试" {
		t.Fatalf("案件超时形态不符:%+v", tm)
	}
	ex := TransportExceptionOutcome("同步风控问询", errPipeline)
	if ex.Code != "500" || !strings.HasPrefix(ex.Msg, "同步风控问询异常:") {
		t.Fatalf("传输异常形态不符:%+v", ex)
	}
	if got := EmptyBodyOutcome(); got.Code != "500" || got.Msg != "服务异常，响应为空" {
		t.Fatalf("空响应分支不符:%+v", got)
	}
}

// TestParseRiskBodyDoubleForm 锁定问询 envelope 的四条路径:
// 成功携带 data / 失败码透传 / code null 视作格式错 / 非法 JSON 折叠 500。
func TestParseRiskBodyDoubleForm(t *testing.T) {
	ok := ParseRiskBody([]byte(`{"code":"200","msg":"ok","data":{"riskId":"9001","strategy":"accept"},"extra":true}`))
	if !ok.IsSuccess() || ok.Code != "200" || ok.Data == nil {
		t.Fatalf("成功路径不符:%+v", ok)
	}
	var data map[string]any
	if json.Unmarshal(ok.Data, &data) != nil || data["strategy"] != "accept" {
		t.Fatalf("data 字节应原样带出且可解码:%s", ok.Data)
	}

	fail := ParseRiskBody([]byte(`{"code":"10001","msg":"命中黑名单","bizExtra":1}`))
	if fail.Code != "10001" || fail.Msg != "命中黑名单" || fail.IsSuccess() {
		t.Fatalf("失败码应透传:%+v", fail)
	}

	for name, body := range map[string]string{
		"code 为 null":   `{"code":null,"msg":"x"}`,
		"code 缺失":       `{"msg":"x"}`,
		"非法 JSON":       `{bad`,
		"空串":            ``,
		"data 类型非对象也接受": `{"code":"200","data":[1,2]}`,
	} {
		got := ParseRiskBody([]byte(body))
		isFormatError := name != "data 类型非对象也接受"
		if isFormatError && (got.Code != CodeInternalServerError || got.Msg != msgBadFormat) {
			t.Fatalf("%s: 应折叠为格式错误,得 %+v", name, got)
		}
	}
}

// TestParseCaseBodyCommonResultForm 锁定 CommonResult 布尔成功标志与 int→string 码转换。
func TestParseCaseBodyCommonResultForm(t *testing.T) {
	ok := ParseCaseBody([]byte(`{"success":true,"code":200,"msg":"OK","data":{"caseNo":"C-9"}}`))
	if !ok.IsSuccess() || ok.Code != "200" || !strings.Contains(string(ok.Data), "C-9") {
		t.Fatalf("案件成功路径不符:%+v", ok)
	}
	fail := ParseCaseBody([]byte(`{"success":false,"code":30001,"msg":"案件不存在"}`))
	if fail.Code != "30001" || fail.Msg != "案件不存在" || fail.IsSuccess() {
		t.Fatalf("案件失败码应转字符串透传:%+v", fail)
	}
	bad := ParseCaseBody([]byte(`not-json`))
	if bad.Code != CodeInternalServerError || bad.Msg != msgBadFormat {
		t.Fatalf("案件解析失败应折叠格式错误:%+v", bad)
	}
	// unknown 字段忽略
	withExtra := ParseCaseBody([]byte(`{"success":false,"code":30001,"msg":"m","trace":"abc"}`))
	if withExtra.Code != "30001" {
		t.Fatalf("未知字段应忽略:%+v", withExtra)
	}
}
