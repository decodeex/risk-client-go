package protocol

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// loadGoldenCaseSamples 读取 case_payload.json 全部样本。
func loadGoldenCaseSamples(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/case_payload.json")
	if err != nil {
		t.Fatalf("读取 case_payload 失败: %v", err)
	}
	var doc struct {
		Samples []map[string]any `json:"samples"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 case_payload 失败: %v", err)
	}
	return doc.Samples
}

// goldenSysFields 抽取 *Note 说明键之外的五个注入键白名单。
func goldenSysFields(t *testing.T, sample map[string]any) SystemFields {
	t.Helper()
	raw, err := json.Marshal(sample["sysFields"])
	if err != nil {
		t.Fatalf("sysFields 重编码失败: %v", err)
	}
	var s struct {
		RequestTime   float64 `json:"requestTime"`
		TraceID       string  `json:"traceId"`
		ClientID      string  `json:"clientId"`
		ClientVersion string  `json:"clientVersion"`
		RequestIP     string  `json:"requestIp"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("sysFields 解析失败: %v", err)
	}
	return SystemFields{
		RequestTime: int64(s.RequestTime), TraceID: s.TraceID, ClientID: s.ClientID,
		ClientVersion: s.ClientVersion, RequestIP: s.RequestIP,
	}
}

// TestBuildCaseQueryRequestMatchesGolden 是本任务主门禁:
// 两份样本(正常 bizId + 中文 bizId)四件套全部逐字节复现——签名输入恒 7 键升序、
// body 恒 eventType/bizId 双键、头 JSON 走默认值基础参数的 bean 序。
func TestBuildCaseQueryRequestMatchesGolden(t *testing.T) {
	pub, _ := loadGatewayKeys(t)
	sgn, err := NewSigner(pub)
	if err != nil {
		t.Fatal(err)
	}
	eph := goldenReplayEphemeral(t)

	for _, sample := range loadGoldenCaseSamples(t) {
		name := sample["name"].(string)
		sys := goldenSysFields(t, sample)
		eventType := sample["eventType"].(string)
		bizID := sample["bizId"].(string)

		eff := applyRiskDefaults(RiskParams{BizID: bizID, EventType: eventType})
		got, err := buildCaseQueryWithEphemeral(eff, sgn, eph, sys)
		if err != nil {
			t.Fatalf("%s: 装配失败 %v", name, err)
		}

		wantSorted := sample["sortedSignJson"].(string)
		if got.SortedSignJSON != wantSorted {
			t.Fatalf("%s 签名输入不一致:\n got  = %s\n want = %s",
				name, got.SortedSignJSON, wantSorted)
		}
		wantSig := sample["signatureInputs"].(map[string]any)["signatureBase64Std"].(string)
		if got.Signature != wantSig {
			t.Fatalf("%s X-SIGNATURE 不一致:\n got  = %s\n want = %s",
				name, got.Signature, wantSig)
		}
		wantHeader := sample["headerJson"].(string)
		if got.HeaderJSON != wantHeader {
			t.Fatalf("%s 头 JSON 不一致:\n got  = %s\n want = %s",
				name, got.HeaderJSON, wantHeader)
		}
		wantBody := sample["bodyJson"].(string)
		canonicalBody, mErr := Marshal(got.Body)
		if mErr != nil {
			t.Fatal(mErr)
		}
		if string(canonicalBody) != wantBody && !sameJSONObject(canonicalBody, []byte(wantBody)) {
			t.Fatalf("%s body 不一致:\n got  = %s\n want = %s", name, canonicalBody, wantBody)
		}
	}
}

// TestBuildCaseQueryRequestRequiresParams 缺参直接拒绝(ErrParam,不发网)。
func TestBuildCaseQueryRequestRequiresParams(t *testing.T) {
	pub, _ := loadGatewayKeys(t)
	sgn, _ := NewSigner(pub)
	sys := SystemFields{TraceID: "t", ClientID: "c", ClientVersion: "1.0.7", RequestIP: "ip"}

	for _, tc := range []struct{ et, bid string }{
		{"", "B1"}, {"login", ""}, {"", ""},
	} {
		_, err := BuildCaseQueryRequest(tc.et, tc.bid, sgn, sys)
		if !errors.Is(err, ErrParam) {
			t.Fatalf("eventType=%q bizId=%q 应报 ErrParam,得 %v", tc.et, tc.bid, err)
		}
	}
}
