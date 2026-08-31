package protocol

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// golden 向量:testdata/headers_golden.json(scripts/GenVectors.java 产出的六头样本,
// 规则摘要见 scripts/README §三.3;Java 对照点 RiskSimpleClient.buildHeaders L298-L307)
//
// 本文件同时承载六头构造与双 Base64 变体边界的高错点断言:
//   Authorization / X-RISK-BASIC 用 URL-safe 带填充 Base64(- 与 _,保留 =);
//   X-SIGNATURE 用标准字母表带填充(+ 与 /)。两者绝不可互换。
//
// 注意:X-User-Id 的默认值补齐(问询缺省 UNKNOWN / 案件查询恒 UNKNOWN)属于任务 2.5/2.6
// 的默认值与载荷构造职责,本层只做"传入即透传",故测试直接把 golden 的头值回灌为入参。
// ---------------------------------------------------------------------------

// goldenHeadersEntryCount 是 golden 文件的条数守卫:文件被截断或意外扩充时立即红。
const goldenHeadersEntryCount = 3

// 六头键名(与 headers.go 的常量保持一致,这里用字面量以便 golden 加载后可做常量交叉锁定)
var goldenSixHeaderNames = []string{
	"Content-Type",
	"X-RISK-MODE",
	"X-SIGNATURE",
	"Authorization",
	"X-RISK-BASIC",
	"X-User-Id",
}

// goldenHeadersSignInputs 对应 entries[].signInputs:签名链的输入与期望输出。
type goldenHeadersSignInputs struct {
	SortedSignJson           string `json:"sortedSignJson"`
	Sha512HexLowerOfSignJson string `json:"sha512HexLowerOfSignJson"`
	SignatureBase64Std       string `json:"signatureBase64Std"`
}

// goldenHeadersEntry 对应 entries[] 单条,json tag 与生成脚本产出的键名严格一致。
type goldenHeadersEntry struct {
	Name                   string                  `json:"name"`
	Scenario               string                  `json:"scenario"`
	ClientID               string                  `json:"clientId"`
	ClientSecret           string                  `json:"clientSecret"`
	ClientVersion          string                  `json:"clientVersion"`
	SignInputs             goldenHeadersSignInputs `json:"signInputs"`
	AuthorizationScheme    string                  `json:"authorizationScheme"`
	AuthorizationBase64url string                  `json:"authorizationBase64url"`
	RiskBasicBase64url     string                  `json:"riskBasicBase64url"`
	SignatureBase64Std     string                  `json:"signatureBase64Std"`
	HeaderJSON             string                  `json:"headerJson"`
	BodyJSON               string                  `json:"bodyJson"`
	Headers                map[string]string       `json:"headers"`
}

type goldenHeadersFile struct {
	Meta struct {
		Title     string   `json:"title"`
		Generator string   `json:"generator"`
		Notes     []string `json:"notes"`
	} `json:"_meta"`
	Entries []goldenHeadersEntry `json:"entries"`
}

// loadGoldenHeaders 读取并守卫校验六头 golden 样本(signer_test.go 同包复用)。
func loadGoldenHeaders(t *testing.T) goldenHeadersFile {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "headers_golden.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取六头 golden 文件失败: %v", err)
	}
	var parsed goldenHeadersFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("解析六头 golden 文件失败: %v", err)
	}
	if len(parsed.Entries) != goldenHeadersEntryCount {
		t.Fatalf("六头 golden 应为 %d 条,实得 %d(文件可能被截断或重复)", goldenHeadersEntryCount, len(parsed.Entries))
	}
	seen := map[string]bool{}
	for i := range parsed.Entries {
		e := &parsed.Entries[i]
		if e.Name == "" || seen[e.Name] {
			t.Fatalf("六头 golden 样本名缺失或重复: %q", e.Name)
		}
		seen[e.Name] = true
		for _, key := range goldenSixHeaderNames {
			if _, ok := e.Headers[key]; !ok {
				t.Fatalf("六头 golden 样本 %q 缺少头字段 %q", e.Name, key)
			}
		}
		if len(e.Headers) != len(goldenSixHeaderNames) {
			t.Fatalf("六头 golden 样本 %q 应恰有 6 个头,实得 %d 个:%v", e.Name, len(e.Headers), e.Headers)
		}
	}
	return parsed
}

// ---------------------------------------------------------------------------
// 六头逐字段对照(任务 2.3 主判据)
// ---------------------------------------------------------------------------

func TestBuildHeadersMatchesGoldenEntries(t *testing.T) {
	golden := loadGoldenHeaders(t)
	for i := range golden.Entries {
		entry := golden.Entries[i]
		t.Run(entry.Name, func(t *testing.T) {
			got := Build(
				entry.Headers["X-RISK-MODE"], // mode 由调用方传值,取 golden 回灌以隔离透传语义
				entry.HeaderJSON,
				entry.Headers["X-SIGNATURE"],
				entry.Headers["X-User-Id"],
				Auth{ClientID: entry.ClientID, ClientSecret: entry.ClientSecret},
			)

			// 1) 键集合必须恰好是六头,不多不少
			if len(got) != len(goldenSixHeaderNames) {
				t.Errorf("应产出恰好 6 个头,实得 %d:%v", len(got), got)
			}
			for _, name := range goldenSixHeaderNames {
				if _, ok := got[name]; !ok {
					t.Errorf("缺少必需头 %q", name)
					continue
				}
				want := entry.Headers[name]
				if firstHeaderValue(got, name) != want {
					t.Errorf("%s 不一致\n got = %q\nwant = %q", name, firstHeaderValue(got, name), want)
				}
			}

			// 2) 显式契约值(entry 顶层与 headers 两处重复定义,均须一致)再核对一遍,
			//    防止 golden 文件内部两份副本被人改动其一仍未察觉
			if entry.AuthorizationScheme != "Basic" {
				t.Fatalf("golden 的授权 scheme 应为 Basic,实得 %q", entry.AuthorizationScheme)
			}
			if gotAuth := firstHeaderValue(got, "Authorization"); gotAuth != "Basic "+entry.AuthorizationBase64url {
				t.Errorf("Authorization 与顶层 authorizationBase64url 拼接不一致\n got = %q\nwant = %q",
					gotAuth, "Basic "+entry.AuthorizationBase64url)
			}
			if gotBasic := firstHeaderValue(got, "X-RISK-BASIC"); gotBasic != entry.RiskBasicBase64url {
				t.Errorf("X-RISK-BASIC 与顶层 riskBasicBase64url 不一致\n got = %q\nwant = %q",
					gotBasic, entry.RiskBasicBase64url)
			}
			if gotSig := firstHeaderValue(got, "X-SIGNATURE"); gotSig != entry.SignatureBase64Std {
				t.Errorf("X-SIGNATURE 与顶层 signatureBase64Std 不一致\n got = %q\nwant = %q",
					gotSig, entry.SignatureBase64Std)
			}

			// 3) X-RISK-BASIC 解码回读必须还原成 headerJson 原文(URL-safe 字母表)
			decodedBasic, err := base64.URLEncoding.DecodeString(firstHeaderValue(got, "X-RISK-BASIC"))
			if err != nil {
				t.Fatalf("X-RISK-BASIC 无法按 URL-safe 带填充字母表解码: %v", err)
			}
			if string(decodedBasic) != entry.HeaderJSON {
				t.Errorf("X-RISK-BASIC 解码回读不一致\n got = %s\nwant = %s", decodedBasic, entry.HeaderJSON)
			}

			// 4) 凭证段解码回读 clientId:clientSecret
			cred := entry.ClientID + ":" + entry.ClientSecret
			decodedCred, err := base64.URLEncoding.DecodeString(firstHeaderValue(got, "Authorization")[len("Basic "):])
			if err != nil {
				t.Fatalf("Authorization 凭证段无法按 URL-safe 字母表解码: %v", err)
			}
			if string(decodedCred) != cred {
				t.Errorf("Authorization 解码回读不一致\n got = %q\nwant = %q", decodedCred, cred)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 双 Base64 变体边界(tasks.md 点名的高错点):从 golden 本身证明两种变体不可混用
// ---------------------------------------------------------------------------

func TestGoldenProvesTwoBase64VariantsAreNotInterchangeable(t *testing.T) {
	golden := loadGoldenHeaders(t)
	variableBoundariesSeen := false
	for _, entry := range golden.Entries {
		basic := entry.RiskBasicBase64url
		sig := entry.SignatureBase64Std

		// X-RISK-BASIC 属于 URL-safe 变体:不允许出现标准字母表专属符号
		if containsAnyRune(basic, '+', '/') {
			t.Errorf("样本 %q 的 X-RISK-BASIC 不应含标准字母表符号 + /:%s", entry.Name, basic)
		}
		// 含 - 或 _ 时,同一串在标准字母表下必然无法解码 —— 两种变体不可互换的直接证据
		if containsAnyRune(basic, '-', '_') {
			variableBoundariesSeen = true
			if _, err := base64.StdEncoding.DecodeString(basic); err == nil {
				t.Errorf("样本 %q 的 X-RISK-BASIC 含 URL-safe 专属符号,却能在标准字母表下解码,变体差异不成立", entry.Name)
			}
			if _, err := base64.URLEncoding.DecodeString(basic); err != nil {
				t.Errorf("样本 %q 的 X-RISK-BASIC 应能按 URL-safe 字母表解码: %v", entry.Name, err)
			}
		}

		// X-SIGNATURE 属于标准变体(密文随机,几乎必含 + /):URL-safe 解码应当失败
		if containsAnyRune(sig, '+', '/') {
			variableBoundariesSeen = true
			if _, err := base64.URLEncoding.DecodeString(sig); err == nil {
				t.Errorf("样本 %q 的 X-SIGNATURE 含标准字母表符号,却能在 URL-safe 下解码,变体差异不成立", entry.Name)
			}
			if _, err := base64.StdEncoding.DecodeString(sig); err != nil {
				t.Errorf("样本 %q 的 X-SIGNATURE 应能按标准字母表解码: %v", entry.Name, err)
			}
		}
	}
	if !variableBoundariesSeen {
		t.Fatal("golden 未覆盖任何变体边界证据(−/_ 或 +/ 缺失),请检查向量文件")
	}
}

// containsAnyRune 是小而直白的判定助手,避免为单一场景引入 strings 的多参歧义。
func containsAnyRune(s string, rs ...rune) bool {
	set := make(map[rune]struct{}, len(rs))
	for _, r := range rs {
		set[r] = struct{}{}
	}
	for _, r := range s {
		if _, ok := set[r]; ok {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 凭证含 + / 的单测(URL-safe 与标准字母表的差异面)+ 填充等号规则
// 说明:+/ 出现在凭证"原文"并不会让它出现在编码结果里(Base64 的 62/63 号索引位
// 要求高连续置位字节,可打印 ASCII 几乎命不中),所以这里的判据是:
//   ① 产物只允许出现 URL-safe 符号集 A-Z a-z 0-9 - _,且 '=' 填充长度符合规则;
//   ② 用硬编码字面量逐字符锁住期望值(不经被测函数同源算法)。
// ---------------------------------------------------------------------------

func TestAuthorizationUsesURLSafeAlphabetWithPadding(t *testing.T) {
	cases := []struct {
		name         string
		clientID     string
		clientSecret string
		wantBearer   string // 含 scheme 的完整 Authorization 期望值(手抄字面量)
		wantPadding  int    // 期望尾部 '=' 个数
	}{
		{
			name:         "凭证含加号与斜杠且留一位填充等号",
			clientID:     "a+b/c",
			clientSecret: "x+y/z", // "a+b/c:x+y/z" 长 11,%3==2 → 一个 '='
			wantBearer:   "Basic YStiL2M6eCt5L3o=",
			wantPadding:  1,
		},
		{
			name:         "凭证长度对齐 3 字节组时不留填充",
			clientID:     "a+b/c",
			clientSecret: "x+y/zz", // "a+b/c:x+y/zz" 长 12,%3==0 → 无 '='
			wantBearer:   "Basic YStiL2M6eCt5L3p6",
			wantPadding:  0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := Build(ModeSync, "{}", "unused-signature", userIDUnknown,
				Auth{ClientID: tc.clientID, ClientSecret: tc.clientSecret})

			auth := firstHeaderValue(got, "Authorization")
			if auth != tc.wantBearer {
				t.Errorf("Authorization 不一致\n got = %q\nwant = %q", auth, tc.wantBearer)
			}
			if padded := countTrailingPad(auth); padded != tc.wantPadding {
				t.Errorf("填充等号个数 = %d,期望 %d(auth=%q)", padded, tc.wantPadding, auth)
			}
			if containsAnyRune(auth, '+', '/') {
				t.Errorf("Authorization 混入了标准字母表符号(+ /),URL-safe 规则被破坏: %q", auth)
			}
			if prefix := "Basic "; len(auth) > len(prefix) && auth[:len(prefix)] != prefix {
				t.Errorf("Authorization 必须以 %q 开头,实得 %q", prefix, auth)
			}

			// URL-safe 且仅 URL-safe 能把凭证解回原文
			decoded, err := base64.URLEncoding.DecodeString(auth[len("Basic "):])
			if err != nil {
				t.Fatalf("凭证段无法按 URL-safe 字母表解码: %v", err)
			}
			if want := tc.clientID + ":" + tc.clientSecret; string(decoded) != want {
				t.Errorf("凭证段解码回读 = %q,期望 %q", decoded, want)
			}
		})
	}
}

// countTrailingPad 统计字符串尾部的 '=' 数量(base64 填充只会出现在末尾)。
func countTrailingPad(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '='; i-- {
		n++
	}
	return n
}

// ---------------------------------------------------------------------------
// 协议常量锁定:mode/userId 默认值的字面量属于跨任务契约(2.5/2.6 会引用)
// ---------------------------------------------------------------------------

func TestProtocolHeaderConstantsMatchGoldenFixtures(t *testing.T) {
	golden := loadGoldenHeaders(t)
	first := golden.Entries[0]

	if contentTypeJSON != "application/json" {
		t.Errorf("contentTypeJSON = %q,期望 application/json", contentTypeJSON)
	}
	if ModeSync != "sync" {
		t.Errorf("ModeSync = %q,期望 sync", ModeSync)
	}
	if userIDUnknown != "UNKNOWN" {
		t.Errorf("userIDUnknown = %q,期望 UNKNOWN", userIDUnknown)
	}

	if got := first.Headers["Content-Type"]; got != contentTypeJSON {
		t.Errorf("golden Content-Type = %q,与常量 %q 不一致", got, contentTypeJSON)
	}
	if got := first.Headers["X-RISK-MODE"]; got != ModeSync {
		t.Errorf("golden X-RISK-MODE = %q,与常量 %q 不一致", got, ModeSync)
	}
	// 问询样例 userId 为空时 bean 落到默认值 UNKNOWN,案件查询恒 UNKNOWN —— 该字面量由本常量承载
	if got := first.Headers["X-User-Id"]; got != userIDUnknown {
		t.Errorf("golden X-User-Id = %q,与常量 %q 不一致", got, userIDUnknown)
	}
}

// firstHeaderValue 读取原样键名的第一个值。
// 不能用 http.Header.Get:它会把查询键规范化成 MIME 首字母大写形态("X-RISK-MODE"→
// "X-Risk-Mode"),而本协议按全大写拼写直写,map 里根本不存在规范化后的那个键。
func firstHeaderValue(h http.Header, name string) string {
	values := h[name]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
