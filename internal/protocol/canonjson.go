package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"unicode/utf8"
)

// 本文件实现风控协议的「规范 JSON」(规则 R1~R9,见 scripts/README.md §四 与
// design.md『internal/protocol』章节)。它决定了签名摘要的输入字节,任何一处与
// Java 侧 TreeMap + Jackson 2.13.5 的输出不一致,网关侧验签即失败。
//
// 因此这里不复用 encoding/json 的序列化路径,而是自实现:
//   - R3 控制字符 \u00XX 的十六进制字母必须【大写】(Jackson),Go 缺省是小写;
//   - R4 不做 HTML 转义(< > & ' / 原样),且 U+2028/U+2029、DEL 0x7F 也不转义
//     (encoding/json 恒定转义 U+2028/U+2029,Jackson 不会);
//   - R5 map 属性值为 null 时整个键省略(Jackson NON_NULL),数组内 null 元素保留;
//   - R6 整型直接走 strconv,绝不经过浮点格式化(避免 42 变成 42.0 或科学计数法)。

// ErrUnsupportedValue 表示该值无法按规范 JSON 规则表达:不支持的类型、非有限浮点数
// 或包含非法 UTF-8 字节的字符串。Marshal 对这类值返回 error 且不产出任何字节
// (宁可显式失败影响一次调用,也不允许静默生成错误签名的报文)。
var ErrUnsupportedValue = errors.New("protocol: value cannot be represented as canonical json")

// Marshal 按 R1~R9 将 m 序列化为规范 JSON 字节:键升序、嵌套递归、紧凑分隔、
// 无 HTML 转义、省略 null 属性、非 ASCII 原样 UTF-8(R9)、无尾随换行或空白(R8)。
//
// 输出即为签名摘要的直接输入,因此调用方不得再对返回值做任何拼接、修剪或转码。
// m 为 nil 时按空对象处理(输出 "{}",对应 R7 —— 剥离头字段后可能得到空 body)。
func Marshal(m map[string]any) ([]byte, error) {
	e := &canonEncoder{}
	e.writeMap(m)
	if e.err != nil {
		return nil, e.err
	}
	return e.buf, nil
}

// canonEncoder 是流式写出器:e.err 非零后所有写入都成为空操作,
// 使递归过程中各层无需逐级传递 error(Marshal 在收口时统一读取)。
type canonEncoder struct {
	buf []byte
	err error
}

// fail 记录首个错误;后续写入保持无效以便快速跳过整棵剩余子树。
func (e *canonEncoder) fail(err error) {
	if e.err == nil {
		e.err = err
	}
}

// writeMap 写出一个 JSON 对象。属性值为 null(untyped nil)的键整个省略(R5)。
func (e *canonEncoder) writeMap(m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// R1:TreeMap 自然序 = String.compareTo = UTF-16 码元序(见 compareKeys)。
	slices.SortFunc(keys, compareKeys)

	e.buf = append(e.buf, '{')
	first := true
	for _, k := range keys {
		v := m[k]
		if v == nil { // R5:NON_NULL —— 属性为 null 则键整省略
			continue
		}
		if !first {
			e.buf = append(e.buf, ',') // R2:紧凑分隔
		}
		first = false
		e.writeString(k)
		e.buf = append(e.buf, ':')
		e.writeValue(v)
	}
	e.buf = append(e.buf, '}')
}

// writeValue 写单个值。支持的类型集合是协议实际会用到的超集:
// string / bool / nil / int 族 / uint 族 / json.Number / float64 /
// json.RawMessage / json.Marshaler 兜底 / map[string]any / []any。
func (e *canonEncoder) writeValue(v any) {
	switch val := v.(type) {
	case nil: // 仅数组元素会走到这里(map 属性已在 writeMap 里整键省略)
		e.buf = append(e.buf, "null"...)
	case bool:
		if val {
			e.buf = append(e.buf, "true"...)
		} else {
			e.buf = append(e.buf, "false"...)
		}
	case string:
		e.writeString(val)
	case int:
		e.writeInt(int64(val))
	case int8:
		e.writeInt(int64(val))
	case int16:
		e.writeInt(int64(val))
	case int32:
		e.writeInt(int64(val))
	case int64:
		e.writeInt(val)
	case uint:
		e.writeUint(uint64(val))
	case uint8:
		e.writeUint(uint64(val))
	case uint16:
		e.writeUint(uint64(val))
	case uint32:
		e.writeUint(uint64(val))
	case uint64:
		e.writeUint(val)
	case uintptr:
		e.writeUint(uint64(val))
	case json.Number:
		// 上游以 UseNumber 解析保留的原始数字文本:原样输出即可保住整数形态。
		e.buf = append(e.buf, val.String()...)
	case float64:
		e.writeFloat64(val)
	case json.RawMessage:
		e.buf = append(e.buf, val...) // 已合法的字节片段,按字面内嵌
	case json.Marshaler:
		raw, err := val.MarshalJSON()
		if err != nil {
			e.fail(fmt.Errorf("%w: json.Marshaler(%T): %v", ErrUnsupportedValue, v, err))
			return
		}
		e.buf = append(e.buf, raw...)
	case map[string]any:
		e.writeMap(val)
	case []any:
		e.buf = append(e.buf, '[')
		for i, item := range val {
			if i > 0 {
				e.buf = append(e.buf, ',') // R2:紧凑分隔
			}
			e.writeValue(item) // 数组内的 null 元素保留(R5 对照面),由 case nil 落地
		}
		e.buf = append(e.buf, ']')
	default:
		e.fail(fmt.Errorf("%w: unsupported type %T", ErrUnsupportedValue, v))
	}
}

func (e *canonEncoder) writeInt(v int64) {
	e.buf = strconv.AppendInt(e.buf, v, 10)
}

func (e *canonEncoder) writeUint(v uint64) {
	e.buf = strconv.AppendUint(e.buf, v, 10)
}

// maxIntegralFloat 是「整数形式」分支的上界 2^53:int64 转换无损,且不会
// 因超大值展开成一长串十进制数字而偏离常规数值书写习惯。
const maxIntegralFloat = float64(1 << 53)

// writeFloat64 是兜底分支:协议侧业务数值一律走字符串或整型(R6 注释),
// 这里只保证整数形态复原与最短往返表示,刻意不去追 Jackson 的 Double.toString
// (后者对大数会写 1.0E21 形态,追平没有收益)。
func (e *canonEncoder) writeFloat64(f float64) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		e.fail(fmt.Errorf("%w: non-finite float64 %v", ErrUnsupportedValue, f))
		return
	}
	if f == math.Trunc(f) && math.Abs(f) <= maxIntegralFloat {
		e.writeInt(int64(f)) // 含负零归一为 "0"、float64(42) 复原为 "42"
		return
	}
	e.buf = strconv.AppendFloat(e.buf, f, 'g', -1, 64)
}

// compareKeys 实现 R1 的 String.compareTo 语义:把两边字符串逐 rune 展开
// 为 UTF-16 码元序列后按字典序比较。ASCII 键与 BMP 中文键下它和 Go 的
// UTF-8 字节序一致;唯一分叉点是增补平面字符 vs U+E000..U+FFFF 区间字符
// (代理高位 0xD800..0xDBFF 小于 0xE000,但码点大于之)——协议约定键只用
// ASCII,本函数仍取真码元序以消除一类静默差异。
func compareKeys(a, b string) int {
	for a != "" && b != "" {
		ra, sa := utf8.DecodeRuneInString(a)
		rb, sb := utf8.DecodeRuneInString(b)
		a, b = a[sa:], b[sb:]
		if ra == rb {
			continue
		}
		var unitsA, unitsB [2]uint16 // 单个 rune 至多展开成一对代理项
		nA := utf16CodeUnits(ra, unitsA[:])
		nB := utf16CodeUnits(rb, unitsB[:])
		n := nA
		if nB < n {
			n = nB
		}
		for i := 0; i < n; i++ {
			if unitsA[i] != unitsB[i] {
				if unitsA[i] < unitsB[i] {
					return -1
				}
				return 1
			}
		}
		if nA != nB { // 单码元 vs 双码元在公共前缀之后较短者居先
			if nA < nB {
				return -1
			}
			return 1
		}
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	default:
		return 1
	}
}

// utf16CodeUnits 把 r 展开为其 UTF-16 编码单元:BMP 内是单码元,
// 增补平面是高低代理对(0xD800..0xDBFF + 0xDC00..0xDFFF)。
func utf16CodeUnits(r rune, dst []uint16) int {
	if r < 0x10000 {
		dst[0] = uint16(r)
		return 1
	}
	rest := r - 0x10000
	dst[0] = uint16(0xD800 + (rest >> 10))
	dst[1] = uint16(0xDC00 + (rest & 0x3FF))
	return 2
}

const upperHexDigits = "0123456789ABCDEF" // R3:十六进制字母必须大写

// needEscapeASCII 报告一个 ASCII 字节是否必须转义:
// 引号与反斜杠是强制转义;小于 0x20 的控制字符必须转义。
// 其余(含 < > & ' / 以及 DEL 0x7F)全部原样 —— 即 R4 的不做 HTML 转义。
func needEscapeASCII(b byte) bool {
	return b < 0x20 || b == '"' || b == '\\'
}

// writeString 写出带引号的 JSON 字符串。转义严格按 R3/R4:
// 短形仅 5 类:\b\t\n\f\r,加 \" 与 \\ 共七种;其余 <0x20 一律 \u00XX 大写;
// 所有 >= 0x20 的字节原样拷贝 —— 这同时覆盖了 DEL 0x7F、U+2028/U+2029 与
// 全部多字节 UTF-8 序列(它们的首字节必然 >= 0x80)。
func (e *canonEncoder) writeString(s string) {
	e.buf = append(e.buf, '"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if b >= utf8.RuneSelf { // 非 ASCII(R9:原样 UTF-8,不做 \uXXXX 转义)
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				// Java 侧字符串不存在非法 UTF-8,这里出现即说明入参已被污染:
				// 若原样透传,产物无法被 Jackson 反序列化,签名字节也无从谈起。
				e.fail(fmt.Errorf("%w: invalid utf-8 byte at index %d of %q", ErrUnsupportedValue, i, s))
				return
			}
			i += size
			continue
		}
		i++
		if !needEscapeASCII(b) {
			continue
		}
		e.buf = append(e.buf, s[start:i-1]...)
		switch b {
		case '"':
			e.buf = append(e.buf, '\\', '"')
		case '\\':
			e.buf = append(e.buf, '\\', '\\')
		case '\b': // 0x08
			e.buf = append(e.buf, '\\', 'b')
		case '\t': // 0x09
			e.buf = append(e.buf, '\\', 't')
		case '\n': // 0x0A
			e.buf = append(e.buf, '\\', 'n')
		case '\f': // 0x0C
			e.buf = append(e.buf, '\\', 'f')
		case '\r': // 0x0D
			e.buf = append(e.buf, '\\', 'r')
		default: // 其余 <0x20:\u00XX,十六进制字母大写(Jackson 形态, 即关键差异面)
			e.buf = append(e.buf, '\\', 'u', '0', '0', upperHexDigits[b>>4], upperHexDigits[b&0x0F])
		}
		start = i
	}
	e.buf = append(e.buf, s[start:]...)
	e.buf = append(e.buf, '"')
}
