package notify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// canonicalJSON 输出规范 JSON：键按 UTF-8 字节序排序、紧凑输出、转义表冻结于本文件
// —— 刻意不依赖 encoding/json 的 Encoder（其转义表随 Go 版本漂移：较新版本把 \b \f
// 由长格式改为短格式），生产端 Java 侧按本表逐字节对齐。
//
// 冻结的转义表（与 Java CanonicalJsonUtil / NotifyVerifier 一致）：
//   引号、反斜杠与 \b \f \n \r \t 用短格式；< > & 与 U+2028/U+2029 输出 \uXXXX；
//   其余 <0x20 控制字符 \u00xx 小写；0x7F、单引号、斜杠与全部非 ASCII 原样 UTF-8。
func canonicalJSON(v interface{}) ([]byte, error) {
	var sb strings.Builder
	if err := writeCanonicalValue(&sb, v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

func writeCanonicalValue(sb *strings.Builder, v interface{}) error {
	switch val := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if val {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case json.Number:
		sb.WriteString(val.String()) // UseNumber 解码保留原始数字文本
	case string:
		writeCanonicalString(sb, val)
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys) // 字节序，与 Java Utf8ByteComparator 一致
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeCanonicalString(sb, k)
			sb.WriteByte(':')
			if err := writeCanonicalValue(sb, val[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case []interface{}:
		sb.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonicalValue(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case float64: // 防御分支：UseNumber 解码下不应出现
		sb.WriteString(strconv.FormatFloat(val, 'g', -1, 64))
	default:
		return fmt.Errorf("canonical json 不支持的类型 %T", v)
	}
	return nil
}

const canonicalHexDigits = "0123456789abcdef"

func writeCanonicalString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				sb.WriteString("\\\"")
			case '\\':
				sb.WriteString("\\\\")
			case '\b':
				sb.WriteString("\\b")
			case '\f':
				sb.WriteString("\\f")
			case '\n':
				sb.WriteString("\\n")
			case '\r':
				sb.WriteString("\\r")
			case '\t':
				sb.WriteString("\\t")
			case '<':
				sb.WriteString("\\u003c")
			case '>':
				sb.WriteString("\\u003e")
			case '&':
				sb.WriteString("\\u0026")
			default:
				if c < 0x20 {
					sb.WriteString("\\u00")
					sb.WriteByte(canonicalHexDigits[c>>4])
					sb.WriteByte(canonicalHexDigits[c&0x0F])
				} else {
					sb.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case 0x2028:
			sb.WriteString("\\u2028")
		case 0x2029:
			sb.WriteString("\\u2029")
		default:
			sb.WriteString(s[i : i+size])
		}
		i += size
	}
	sb.WriteByte('"')
}
