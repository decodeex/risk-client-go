package protocol

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// golden 向量:testdata/canonjson_cases.json(Java TreeMap + Jackson 2.13.5 行为,
// 期望值为手工书写的字符串常量,见 scripts/GenVectors.java)
// ---------------------------------------------------------------------------

// goldenCanonCase 对应 canonjson_cases.json 的单条用例,字段名与生成脚本产出一致。
type goldenCanonCase struct {
	Name             string `json:"name"`
	Purpose          string `json:"purpose"`
	InputDescription string `json:"inputDescription"` // 无结构化 input 字段:Go 侧按该描述自建输入 map
	CanonicalJSON    string `json:"canonicalJson"`
	Note             string `json:"note"`
}

type goldenCanonFile struct {
	Cases []goldenCanonCase `json:"cases"`
}

// goldenCanonCaseCount 是 golden 文件应有的用例数,用于防止文件被截断或意外扩充后被静默漏测。
const goldenCanonCaseCount = 15

func loadGoldenCanonCases(t *testing.T) []goldenCanonCase {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "canonjson_cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 golden 文件失败: %v", err)
	}
	var parsed goldenCanonFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("解析 golden 文件失败: %v", err)
	}
	if len(parsed.Cases) != goldenCanonCaseCount {
		t.Fatalf("golden 用例应为 %d 条,实得 %d(文件可能被截断或重复)", goldenCanonCaseCount, len(parsed.Cases))
	}
	seen := map[string]bool{}
	for _, c := range parsed.Cases {
		if c.Name == "" || seen[c.Name] {
			t.Fatalf("golden 用例名缺失或重复: %q", c.Name)
		}
		seen[c.Name] = true
	}
	return parsed.Cases
}

// goldenInputs 按 InputDescription 在 Go 侧重建每条 golden 用例的输入 map。
// 键即 golden 文件的 name 字段;新增 golden 用例时必须同步补一条构造器。
func goldenInputs() map[string]func() map[string]any {
	return map[string]func() map[string]any{
		// {'event':'login','bizId':'1001','userId':'u_01'}
		"c01_flat_sorted_keys": func() map[string]any {
			return map[string]any{"event": "login", "bizId": "1001", "userId": "u_01"}
		},
		// {'Type':..,'alpha':..,'Alpha':..,'beta':..}:大小写敏感,'A'<'T'<'a'<'b'
		"c02_key_order_is_code_unit_order": func() map[string]any {
			return map[string]any{"Type": "T1", "alpha": "a1", "Alpha": "A1", "beta": "b1"}
		},
		// {'b':{'y':2,'x':{'inner':'v'}},'a':[1,2,3]}:嵌套递归升序,数组保序
		"c03_nested_object_recursive_sort": func() map[string]any {
			return map[string]any{
				"b": map[string]any{"y": 2, "x": map[string]any{"inner": "v"}},
				"a": []any{1, 2, 3},
			}
		},
		// '<script>&amp;</script>' 与 '< > &':Jackson 绝不转义 < > &
		"c04_html_chars_not_escaped": func() map[string]any {
			return map[string]any{"lt_gt_amp": "< > &", "script": "<script>&amp;</script>"}
		},
		// {'a':null,'b':'keep','c':null}:属性 null 整省略(NON_NULL)
		"c05_null_properties_omitted": func() map[string]any {
			return map[string]any{"a": nil, "b": "keep", "c": nil}
		},
		// {'list':[null,'keep',null],'gone':null}:数组内 null 元素保留
		"c06_null_element_inside_array_kept": func() map[string]any {
			return map[string]any{"list": []any{nil, "keep", nil}, "gone": nil}
		},
		// Integer(42)/Long(1756272000000)/-7:数字保整型
		"c07_integer_types_stay_integer": func() map[string]any {
			return map[string]any{"intVal": 42, "longMs": int64(1756272000000), "negInt": -7}
		},
		// 中文原样 UTF-8,并与 ASCII 键混排(U+4E8B 事 < U+59D3 姓)
		"c08_chinese_utf8_raw_with_ascii_mix": func() map[string]any {
			return map[string]any{"姓名": "张三", "事件类型": "登录", "mixed_zh": "中文abc"}
		},
		// {}(c09 空对象):直接给空 map 字面量
		"c09_empty_map": func() map[string]any {
			return map[string]any{}
		},
		// {'':''}:空串键恒最小且要保留
		"c10_empty_string_key_and_value": func() map[string]any {
			return map[string]any{"": ""}
		},
		// 双引号与反斜杠的强制转义
		"c11_quotes_and_backslashes": func() map[string]any {
			return map[string]any{"quoted": "he said \"hi\"", "bs": "C:\\path\\"}
		},
		// 控制字符:0x01/0x0B/0x1F 为 \u00XX 且十六进制大写,0x08/0x09/0x0A 用短形
		"c12_control_chars_uppercase_hex_escape": func() map[string]any {
			return map[string]any{
				"u0001": "\x01",
				"u000b": "\x0b",
				"u001f": "\x1f",
				"bell":  "\b",
				"nl":    "\n",
				"tab":   "\t",
			}
		},
		// '/' 与 '&' 原样
		"c13_slash_and_ampersand_raw": func() map[string]any {
			return map[string]any{"url": "https://gw/risk?x=1&y=2"}
		},
		// true/false;数字字符串仍是字符串
		"c14_boolean_and_numeric_string": func() map[string]any {
			return map[string]any{"ok": true, "no": false, "numStr": "123"}
		},
		// 补平面 emoji 原样 4 字节 UTF-8
		"c15_supplementary_plane_char_raw": func() map[string]any {
			return map[string]any{"emoji": "\U0001F600 ok \U0001F600", "plain": "hi"}
		},
	}
}

// TestMarshalMatchesJacksonGolden 是本任务的主门禁:15 条向量全部逐字节对齐。
func TestMarshalMatchesJacksonGolden(t *testing.T) {
	cases := loadGoldenCanonCases(t)
	builders := goldenInputs()
	consumed := map[string]bool{}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			build, ok := builders[tc.Name]
			if !ok {
				t.Fatalf("golden 用例 %s 缺少 Go 侧输入构造器", tc.Name)
			}
			consumed[tc.Name] = true

			got, err := Marshal(build())
			if err != nil {
				t.Fatalf("Marshal 不应报错,却得到: %v", err)
			}
			if string(got) != tc.CanonicalJSON {
				t.Fatalf("%s 未逐字节对齐(%s):\n got  = %q\n want = %q\n 备注: %s",
					tc.Name, tc.Purpose, got, tc.CanonicalJSON, tc.Note)
			}
		})
	}

	for name := range builders {
		if !consumed[name] {
			t.Errorf("存在未对应任何 golden 用例的多余构造器: %s", name)
		}
	}
}

// ---------------------------------------------------------------------------
// 规则级单元测试(R3 大写十六进制 / R4 不做 HTML 转义 / R6 整型 / R7-R8 / 浮点边界 /
// 兜底类型与错误契约 / UTF-16 码元序)
// ---------------------------------------------------------------------------

// TestControlCharsEscapedPerRuleR3 逐个覆盖 0x00..0x1F,锁定短形转义与其余 \u00XX 的大写十六进制形态。
func TestControlCharsEscapedPerRuleR3(t *testing.T) {
	shortForms := map[byte]string{
		0x08: `\b`,
		0x09: `\t`,
		0x0A: `\n`,
		0x0C: `\f`,
		0x0D: `\r`,
	}
	const upperHex = "0123456789ABCDEF"

	for c := 0; c < 0x20; c++ {
		ch := byte(c)
		wantEscape, ok := shortForms[ch]
		if !ok {
			// 其余 <0x20 写成反斜杠+u+00XX 且十六进制字母【大写】(Jackson 形态,\u000B 即关键移植坑)
			wantEscape = `\u00` + string(upperHex[ch>>4]) + string(upperHex[ch&0x0F])
		}
		got, err := Marshal(map[string]any{"v": string(ch)})
		if err != nil {
			t.Fatalf("char %#02x: Marshal 报错 %v", ch, err)
		}
		want := `{"v":"` + wantEscape + `"}`
		if string(got) != want {
			t.Fatalf("char %#02x 应转义为 %s,得 %s", ch, want, got)
		}
	}

	// 显式锁死大写十六进制:小写形态绝不出现(Go encoding/json 缺省即为小写)
	out, err := Marshal(map[string]any{"u000b": "\x0b", "u001f": "\x1f"})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	s := string(out)
	if strings.Contains(s, `\u000b`) || strings.Contains(s, `\u001f`) {
		t.Fatalf("控制字符十六进制必须大写,却出现小写形态: %s", s)
	}
	if !strings.Contains(s, `\u000B`) || !strings.Contains(s, `\u001F`) {
		t.Fatalf("缺少大写十六进制转义形态: %s", s)
	}
}

// TestHTMLAndDelimiterCharsStayRawPerRuleR4:< > & ' / 以及 DEL、U+2028、U+2029 全部原样。
func TestHTMLAndDelimiterCharsStayRawPerRuleR4(t *testing.T) {
	got, err := Marshal(map[string]any{
		// \u53cc\u5f15\u53f7\u81ea\u8eab\u5c5e\u4e8e R3 \u5f3a\u5236\u8f6c\u4e49\u9762(golden c11 \u5df2\u8986\u76d6),\u8fd9\u91cc\u53ea\u9a8c R4 \u7684\u4e94\u4e2a\u5b57\u7b26
		"html":  "< > & ' /",
		"url":   "https://gw/risk?a=1&b=2",
		"del":   "\x7f",
		"ls_ps": "\u2028\u2029",
	})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	s := string(got)

	for _, forbidden := range []string{
		`\u003C`, `\u003c`, `\u003E`, `\u003e`, `\u0026`, `\u002F`, `\u002f`, `\u0027`, `\u2028`, `\u2029`,
	} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("R4: %s 不应被转义,整段输出 %s", forbidden, s)
		}
	}
	if !strings.Contains(s, "< > & ' /") {
		t.Fatalf("R4: < > & ' / 应原样保留,得 %s", s)
	}
	if !strings.Contains(s, "https://gw/risk?a=1&b=2") {
		t.Fatalf("R4: URL 内的 / 与 & 应原样保留,得 %s", s)
	}
	if !strings.Contains(s, "\x7f") || !strings.Contains(s, "\u2028") || !strings.Contains(s, "\u2029") {
		t.Fatalf("R4: DEL 0x7F 与 U+2028/U+2029 应原样输出,得 %q", s)
	}
}

// TestFloat64KeepsIntegralFormAndShortestNonIntegral 锁定浮点两条分支:
// 整数值输出无小数点形式(解 JSON 得到的 float64(42) 必须回到 "42");
// 非整数沿用最短表示。1e21 条目是刻意的边界声明:协议实际只传数字字符串与整型,
// 该兜底路径刻意不去追 Jackson 的 Double.toString(会输出 1.0E21)。
func TestFloat64KeepsIntegralFormAndShortestNonIntegral(t *testing.T) {
	cases := []struct {
		desc string
		val  float64
		want string
	}{
		{"正整数浮点无小数点", 42, "42"},
		{"负整数浮点带负号", -42, "-42"},
		{"零", 0, "0"},
		{"负零归一为 0", math.Copysign(0, -1), "0"},
		{"2^53 上界整数仍走整数形式", 9007199254740992, "9007199254740992"},
		{"非整数最短表示", 1.5, "1.5"},
		{"负小数", -0.125, "-0.125"},
		{"超出整数分支走科学计数兜底(边界声明)", 1e21, "1e+21"},
	}
	for _, tc := range cases {
		got, err := Marshal(map[string]any{"v": tc.val})
		if err != nil {
			t.Fatalf("%s: Marshal 报错 %v", tc.desc, err)
		}
		if want := `{"v":` + tc.want + `}`; string(got) != want {
			t.Fatalf("%s: 得 %s,期望 %s", tc.desc, got, want)
		}
	}

	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		out, err := Marshal(map[string]any{"v": bad})
		if err == nil {
			t.Fatalf("非有限浮点 %v 应报错而非产出非法 JSON,得 %s", bad, out)
		}
	}
}

// TestIntegerFamiliesKeepDecimalFormRuleR6:int 家族直接 strconv,不走 encoding/json 浮点路径。
func TestIntegerFamiliesKeepDecimalFormRuleR6(t *testing.T) {
	got, err := Marshal(map[string]any{
		"i":   int(-7),
		"i8":  int8(-128),
		"i16": int16(32767),
		"i32": int32(-2147483648),
		"i64": int64(1756272000000),
		"num": json.Number("1756272000000"), // 解析上游 JSON 时以 UseNumber 保留的原始数字文本
		"u":   uint(18446744073709551615),
		"u8":  uint8(255),
		"u16": uint16(65535),
		"u32": uint32(4294967295),
		"u64": uint64(1756272000000),
	})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	// 键升序:i, i16, i32, i64, i8, num, u, u16, u32, u64, u8
	want := `{"i":-7,"i16":32767,"i32":-2147483648,"i64":1756272000000,"i8":-128,` +
		`"num":1756272000000,"u":18446744073709551615,"u16":65535,"u32":4294967295,` +
		`"u64":1756272000000,"u8":255}`
	if string(got) != want {
		t.Fatalf("整型族应保持十进制整数形态:\n got  = %s\n want = %s", got, want)
	}
}

// TestUnsupportedValuesReturnErrorWithoutPartialOutput:不支持的类型必须显式报错,且不返回半成品字节。
func TestUnsupportedValuesReturnErrorWithoutPartialOutput(t *testing.T) {
	cases := map[string]any{
		"bytes": []byte("binary"), // 明确不支持(避免与字符串的 Base64 歧义)
		"fn":    func() {},
		"chan":  make(chan int),
		"struct": struct {
			A int
		}{A: 1},
		"nilptr": (*string)(nil), // 类型化 nil 指针同样显式报错,而非静默省略或输出 null
	}
	for name, v := range cases {
		out, err := Marshal(map[string]any{"k": v})
		if err == nil {
			t.Fatalf("%s(%T) 应返回错误,却得到 %s", name, v, out)
		}
		if out != nil {
			t.Fatalf("%s 出错时不应返回半成品字节,得 %s", name, out)
		}
	}
}

// fixedMarshaler 模拟调用方自定义类型的 json.Marshaler 兜底路径。
type fixedMarshaler struct{}

func (fixedMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(`{"z":1,"a":[true,null]}`), nil
}

// TestRawMessageAndMarshalerEmbeddedVerbatim:两个兜底类型按字面内嵌、内容不再重排序
// (签名确定性由调用方保证;规范 JSON 只承诺自身产出的结构化部分)。
func TestRawMessageAndMarshalerEmbeddedVerbatim(t *testing.T) {
	got, err := Marshal(map[string]any{
		"mid": fixedMarshaler{},
		"raw": json.RawMessage(`{"zz":1}`),
	})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	want := `{"mid":{"z":1,"a":[true,null]},"raw":{"zz":1}}`
	if string(got) != want {
		t.Fatalf("兜底类型应按字面内嵌:\n got  = %s\n want = %s", got, want)
	}
}

// TestEmptyObjectArraysAndNoTrailingWhitespace:R7 空 map {} 与 R8 无尾随换行/空白。
func TestEmptyObjectArraysAndNoTrailingWhitespace(t *testing.T) {
	for desc, in := range map[string]map[string]any{"空 map": {}, "nil map": nil} {
		got, err := Marshal(in)
		if err != nil {
			t.Fatalf("%s: Marshal 报错 %v", desc, err)
		}
		if string(got) != "{}" {
			t.Fatalf("%s 应输出 {},得 %q", desc, got)
		}
	}

	got, err := Marshal(map[string]any{"a": map[string]any{}, "l": []any{}, "keep": 1})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	if want := `{"a":{},"keep":1,"l":[]}`; string(got) != want {
		t.Fatalf("空对象/空数组应紧凑渲染:\n got  = %s\n want = %s", got, want)
	}
}

// TestKeyOrderIsUTF16CodeUnitOrder:排序语义 = String.compareTo 的 UTF-16 码元序。
// 增补平面键 😀(U+1F600,UTF-16 高位代理 0xD83D)排在 BMP 私有区键 U+E000 之前,
// 而 UTF-8 字节序(码点序)恰好相反 —— 本测试锁定实现取的是前者。
// 协议约定业务键只用 ASCII(见规格 c15 note),此处是排序函数的数学性质锁定,不是放开限制的许可。
func TestKeyOrderIsUTF16CodeUnitOrder(t *testing.T) {
	got, err := Marshal(map[string]any{"\U0001F600": "emoji", "\uE000": "bmp"})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	want := `{"` + "\U0001F600" + `":"emoji","` + "\uE000" + `":"bmp"}`
	if string(got) != want {
		t.Fatalf("增补平面键应按 UTF-16 码元序排在 U+E000 之前:\n got  = %s\n want = %s", got, want)
	}
	if errors.Is(err, ErrUnsupportedValue) {
		t.Fatal("不应误报不支持错误")
	}
}

// TestNestedMapNilsOmittedButArrayNilsKept 是 R5 的直白复述版补充断言(独立于 golden 文件)。
func TestNestedMapNilsOmittedButArrayNilsKept(t *testing.T) {
	got, err := Marshal(map[string]any{
		"outer": map[string]any{"a": nil, "b": map[string]any{"deep": nil}},
		"list":  []any{nil, map[string]any{"inner": nil}, "x"},
	})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	want := `{"list":[null,{},"x"],"outer":{"b":{}}}`
	if string(got) != want {
		t.Fatalf("嵌套层也要省略 null 属性而保留数组 null:\n got  = %s\n want = %s", got, want)
	}
}
