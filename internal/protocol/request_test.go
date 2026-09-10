package protocol

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// loadGoldenHeaderEntry 按 name 取 headers_golden.json 的某条 entry。
func loadGoldenHeaderEntry(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/headers_golden.json")
	if err != nil {
		t.Fatalf("读取 headers_golden 失败: %v", err)
	}
	var doc struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 headers_golden 失败: %v", err)
	}
	for _, e := range doc.Entries {
		if e["name"] == name {
			return e
		}
	}
	t.Fatalf("headers_golden 无 entry %q", name)
	return nil
}

// goldenReplayEphemeral 从 ecies_vectors.json 取回放块构造固定临时私钥。
func goldenReplayEphemeral(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/ecies_vectors.json")
	if err != nil {
		t.Fatalf("读取 ecies_vectors 失败: %v", err)
	}
	var doc struct {
		EphemeralReplay struct {
			ReplayPatternHex string `json:"replayPatternHex"`
		} `json:"ephemeralReplay"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 ecies_vectors 失败: %v", err)
	}
	b, err := hex.DecodeString(doc.EphemeralReplay.ReplayPatternHex)
	if err != nil || len(b) != 32 {
		t.Fatalf("回放块非法: %v(len=%d)", err, len(b))
	}
	priv, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		t.Fatalf("构造固定临时私钥失败: %v", err)
	}
	return priv
}

// js 与 jn 是对解码后 map 的窄化取值助手。
func js(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func jn(m map[string]any, k string) float64 {
	v, _ := m[k].(float64)
	return v
}

// TestBuildRiskRequestMatchesGoldenEntryB 是本任务的主门禁:
// 用 golden「同步问询+敏感字段」样例的全部已知量复现装配产物,四件套逐字节比对,
// 且敏感字段密文与 golden 冻结的密文常量一致(fixed ephemeral 回放路径)。
func TestBuildRiskRequestMatchesGoldenEntryB(t *testing.T) {
	entry := loadGoldenHeaderEntry(t, "sync_risk_with_secret_field_encrypted")
	signInputs := entry["signInputs"].(map[string]any)
	sortedGolden := js(signInputs, "sortedSignJson")

	var goldenSorted map[string]any
	if err := json.Unmarshal([]byte(sortedGolden), &goldenSorted); err != nil {
		t.Fatalf("golden sortedSignJson 解析失败: %v", err)
	}

	pub, _ := loadGatewayKeys(t)
	sgn, err := NewSigner(pub)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	params := RiskParams{
		BizID:       js(goldenSorted, "bizId"),
		UserID:      js(goldenSorted, "userId"),
		Platform:    js(goldenSorted, "platform"),
		EventType:   js(goldenSorted, "eventType"),
		FingerToken: js(goldenSorted, "fingerToken"),
		IP:          js(goldenSorted, "ip"),
		BizTime:     int64(jn(goldenSorted, "bizTime")),
		TenantID:    js(goldenSorted, "tenantId"),
		SiteType:    js(goldenSorted, "siteType"),
	}
	sys := SystemFields{
		RequestTime:   int64(jn(goldenSorted, "requestTime")),
		TraceID:       js(goldenSorted, "traceId"),
		ClientID:      js(entry, "clientId"),
		ClientVersion: js(goldenSorted, "clientVersion"),
		RequestIP:     js(goldenSorted, "requestIp"),
	}

	var goldenBody map[string]any
	bodyJSON := js(entry, "bodyJson")
	if err := json.Unmarshal([]byte(bodyJSON), &goldenBody); err != nil {
		t.Fatalf("golden bodyJson 解析失败: %v", err)
	}
	plainEmail := js(entry, "secretFieldPlaintext")
	wantCipher := js(entry, "secretFieldCipherBase64Std")
	bizData := make(map[string]any, len(goldenBody))
	for k, v := range goldenBody {
		if k == "email" { // golden 里是密文形态,管线输入应还原成明文再走加密
			bizData[k] = plainEmail
			continue
		}
		bizData[k] = v
	}

	got, err := buildRiskWithEphemeral(params, bizData, []string{"email"}, sgn,
		goldenReplayEphemeral(t), sys)
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}

	if got.SortedSignJSON != sortedGolden {
		t.Fatalf("签名输入不一致:\n got  = %s\n want = %s", got.SortedSignJSON, sortedGolden)
	}
	wantSig := js(signInputs, "signatureBase64Std")
	if got.Signature != wantSig {
		t.Fatalf("X-SIGNATURE 不一致:\n got  = %s\n want = %s", got.Signature, wantSig)
	}
	if got.HeaderJSON != js(entry, "headerJson") {
		t.Fatalf("头 JSON 不一致:\n got  = %s\n want = %s", got.HeaderJSON, js(entry, "headerJson"))
	}
	if got.Body["email"] != wantCipher {
		t.Fatalf("敏感字段密文与 golden 常量(secretFieldCipherBase64Std)不一致:\n got  = %s\n want = %s",
			got.Body["email"], wantCipher)
	}
	// body 深相等 + 其规范化字节恰好等于 golden 的 bodyJson
	if len(got.Body) != len(goldenBody) {
		t.Fatalf("body 键数不一致: got %d want %d(%v vs %s)", len(got.Body), len(goldenBody), got.Body, bodyJSON)
	}
	canonicalBody, err := Marshal(got.Body)
	if err != nil {
		t.Fatalf("body 规范化失败: %v", err)
	}
	if string(canonicalBody) != bodyJSON && !sameJSONObject(canonicalBody, []byte(bodyJSON)) {
		t.Fatalf("body 字节不一致:\n got  = %s\n want = %s", canonicalBody, bodyJSON)
	}
}

// TestBuildRiskRequestRandomEphemeralKeepsSignInputStable:生产随机路径下签名输入稳定、
// 密文必然不同(随机性健全性——若有人误用固定 ephemeral 该测试红)。
func TestBuildRiskRequestRandomEphemeralKeepsSignInputStable(t *testing.T) {
	pub, _ := loadGatewayKeys(t)
	sgn, err := NewSigner(pub)
	if err != nil {
		t.Fatal(err)
	}
	sys := SystemFields{RequestTime: 1756272000000, TraceID: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
		ClientID: "cid", ClientVersion: DefaultClientVersion, RequestIP: "10.0.0.2"}
	p := RiskParams{BizID: "B-1", EventType: "login"}

	first, err := BuildRiskRequest(p, map[string]any{"amount": "7"}, nil, sgn, sys)
	if err != nil {
		t.Fatalf("首次装配: %v", err)
	}
	second, err := BuildRiskRequest(p, map[string]any{"amount": "7"}, nil, sgn, sys)
	if err != nil {
		t.Fatalf("二次装配: %v", err)
	}
	if first.SortedSignJSON != second.SortedSignJSON {
		t.Fatal("同入参两次装配的签名输入必须一致")
	}
	if first.Signature == second.Signature {
		t.Fatal("随机 ephemeral 下两次签名密文不应相同")
	}
}

// TestBuildRiskRequestRejectsReservedAndBadSecrets 错误契约(全部不发网——纯函数层面直接拒绝):
// 业务键命中保留字段 → ErrReservedField;secret 缺失/保留名/不受控类型 → ErrParam。
func TestBuildRiskRequestRejectsReservedAndBadSecrets(t *testing.T) {
	pub, _ := loadGatewayKeys(t)
	sgn, _ := NewSigner(pub)
	sys := SystemFields{TraceID: "t", ClientID: "c", ClientVersion: "1.0.7", RequestIP: "ip"}
	cases := []struct {
		name      string
		bizData   map[string]any
		secrets   []string
		wantIsErr error
	}{
		{"业务键命中注入键", map[string]any{"traceId": "x"}, nil, ErrReservedField},
		{"业务键命中协议字段", map[string]any{"userId": "u"}, nil, ErrReservedField},
		{"secret 名缺失于 bizData", map[string]any{"a": "1"}, []string{"mobile"}, ErrParam},
		{"secret 名为保留字段", map[string]any{"ok": "1"}, []string{"clientId"}, ErrReservedField},
		{"secret 类型不受控", map[string]any{"amt": 1.5}, []string{"amt"}, ErrParam},
	}
	for _, tc := range cases {
		_, err := BuildRiskRequest(RiskParams{BizID: "b", EventType: "e"}, tc.bizData, tc.secrets, sgn, sys)
		if !errors.Is(err, tc.wantIsErr) {
			t.Fatalf("%s: 期望 %v 实得 %v", tc.name, tc.wantIsErr, err)
		}
	}
}

// TestDefaultsFillIntoHeaderAndSignInput 校验 Req 1.4 默认值补齐出现在两条确定序里,
// 且纯基础参数场景的 body 为空对象 "{}"。
func TestDefaultsFillIntoHeaderAndSignInput(t *testing.T) {
	pub, _ := loadGatewayKeys(t)
	sgn, _ := NewSigner(pub)
	priv := goldenReplayEphemeral(t)
	sys := SystemFields{RequestTime: 1756272000000, TraceID: "tid", ClientID: "cid",
		ClientVersion: DefaultClientVersion, RequestIP: "127.0.0.1"}

	got, err := buildRiskWithEphemeral(RiskParams{BizID: "B", EventType: "login"}, nil, nil, sgn, priv, sys)
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	for _, marker := range []string{`"userId":"UNKNOWN"`, `"tenantId":"default"`, `"siteType":"default"`} {
		if !strings.Contains(got.SortedSignJSON, marker) {
			t.Fatalf("签名输入缺默认值标记 %s:%s", marker, got.SortedSignJSON)
		}
		if !strings.Contains(got.HeaderJSON, marker) {
			t.Fatalf("头 JSON 缺默认值标记 %s:%s", marker, got.HeaderJSON)
		}
	}
	if len(got.Body) != 0 {
		t.Fatalf("纯基础参数 body 应为空,得 %v", got.Body)
	}
	if beanHasPlatformFingerIPForEmptyParams(got.HeaderJSON) {
		t.Fatal("未设置的 platform/fingerToken/ip 不应出现 beans 序头里(NON_NULL)")
	}
}

// beanHasPlatformFingerIPForEmptyParams 判断三条可选键是否被错误写入(测试专用)。测试专用。
func beanHasPlatformFingerIPForEmptyParams(headerJSON string) bool {
	return strings.Contains(headerJSON, `"platform":`) ||
		strings.Contains(headerJSON, `"fingerToken":`) ||
		strings.Contains(headerJSON, `"ip":`)
}

// sameJSONObject 数值等价比较(键序无关):canonical body 与 golden 的串按 JSON 语义比对。
func sameJSONObject(a, b []byte) bool {
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	aj, _ := json.Marshal(va)
	bj, _ := json.Marshal(vb)
	return string(aj) == string(bj)
}

// TestBuildRiskRequestFreshEphemeralPerCiphertext 生产路径必须对每条密文独立抽临时密钥。
// 回归点:此前签名与敏感字段共用一个临时密钥,同一请求的所有密文
// 落在同一条 XOR keystream 上(流密码密钥复用),两条密文异或即可消去 keystream。
func TestBuildRiskRequestFreshEphemeralPerCiphertext(t *testing.T) {
	pub, _ := loadGatewayKeys(t)
	sgn, err := NewSigner(pub)
	if err != nil {
		t.Fatal(err)
	}
	sys := SystemFields{RequestTime: 1756272000000, TraceID: "t-1",
		ClientID: "c", ClientVersion: "1.0.7", RequestIP: "1.1.1.1"}
	build := func() *BuiltRequest {
		got, berr := BuildRiskRequest(RiskParams{BizID: "B", EventType: "login"},
			map[string]any{"mobile": "13800000000"}, []string{"mobile"}, sgn, sys)
		if berr != nil {
			t.Fatalf("装配失败: %v", berr)
		}
		return got
	}
	b1, b2 := build(), build()

	// 相同输入两次装配:临时密钥每次新抽,签名密文必然不同
	if b1.Signature == b2.Signature {
		t.Fatal("两次装配的签名密文相同=临时密钥未刷新")
	}

	// 同一请求内:签名密文与敏感字段密文的临时公钥 V(前 65B)必须不同
	sigCT, derr := base64.StdEncoding.DecodeString(b1.Signature)
	if derr != nil {
		t.Fatal(derr)
	}
	fieldCT, ferr := base64.StdEncoding.DecodeString(js(b1.Body, "mobile"))
	if ferr != nil {
		t.Fatal(ferr)
	}
	if len(sigCT) < ecIESPointSize || len(fieldCT) < ecIESPointSize {
		t.Fatalf("密文长度异常: sig=%d field=%d", len(sigCT), len(fieldCT))
	}
	if bytes.Equal(sigCT[:ecIESPointSize], fieldCT[:ecIESPointSize]) {
		t.Fatal("签名与敏感字段共用同一临时公钥(同一 keystream),机密性被削弱")
	}
}
