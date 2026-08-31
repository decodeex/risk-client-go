package riskclient

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorSentinelsAreDistinct(t *testing.T) {
	all := []struct {
		name string
		err  error
	}{
		{"ErrConfig", ErrConfig},
		{"ErrParam", ErrParam},
		{"ErrReservedField", ErrReservedField},
	}
	for _, tc := range all {
		if tc.err == nil {
			t.Fatalf("%s 未定义或为 nil", tc.name)
		}
		if !errors.Is(tc.err, tc.err) {
			t.Fatalf("errors.Is(%s, %s) 应为 true", tc.name, tc.name)
		}
		if tc.err.Error() == "" {
			t.Fatalf("%s 应有非空错误文案", tc.name)
		}
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if errors.Is(all[i].err, all[j].err) || errors.Is(all[j].err, all[i].err) {
				t.Fatalf("哨兵应彼此互斥可判:%s 与 %s 不应互相匹配", all[i].name, all[j].name)
			}
		}
	}
}

func TestErrorSentinelsMatchThroughWrapping(t *testing.T) {
	cases := []struct {
		name string
		root error
		wrap func(error) error
	}{
		{
			name: "配置缺失初始化拦截(Req 6.2)",
			root: ErrConfig,
			wrap: func(e error) error { return fmt.Errorf("%w: base url is empty", e) },
		},
		{
			name: "事件类型缺少超时配置预检失败(Req 6.3)",
			root: ErrConfig,
			wrap: func(e error) error { return fmt.Errorf("event %q: %w", "LOGIN", e) },
		},
		{
			name: "基础参数必填项缺失(Req 1.3)",
			root: ErrParam,
			wrap: func(e error) error { return fmt.Errorf("eventType: %w", e) },
		},
		{
			name: "业务数据命中保留字段(Req 1.3)",
			root: ErrReservedField,
			wrap: func(e error) error { return fmt.Errorf("field %q: %w", "traceId", e) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := tc.wrap(tc.root)
			if !errors.Is(wrapped, tc.root) {
				t.Fatalf("包装后的错误应能被 errors.Is 判定\ngot: %v\nwant sentinel: %v", wrapped, tc.root)
			}
			if wrapped.Error() == tc.root.Error() {
				t.Fatalf("包装后应保留上下文文案,got %q", wrapped.Error())
			}
			// 双重包装仍需可判（客户端层层预检叠加上下文是常态）。
			double := fmt.Errorf("outer: %w", tc.wrap(tc.root))
			if !errors.Is(double, tc.root) {
				t.Fatalf("双层包装后 errors.Is 仍应为真: %v", double)
			}
		})
	}
}

func TestErrorSentinelsDoNotCrossMatch(t *testing.T) {
	if errors.Is(fmt.Errorf("wrap: %w", ErrParam), ErrConfig) {
		t.Fatal("ErrParam 包装链不应被判定为 ErrConfig")
	}
	if errors.Is(fmt.Errorf("wrap: %w", ErrReservedField), ErrParam) {
		t.Fatal("ErrReservedField 包装链不应被判定为 ErrParam")
	}
}
