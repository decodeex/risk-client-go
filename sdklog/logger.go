// Package sdklog 提供 SDK 内部使用的最小日志抽象。
//
// 设计定位（design.md）：SDK 为独立二方包仓库，不能 import 宿主服务的日志设施
// （如 bifufx-api/log），因此只定义一个四方法的最小接口，由接入方在构造门面 /
// 消费器时注入自己的实现——宿主侧一行适配即可桥回自己的 log 包；未注入时使用
// 本包的 NewStdLogger（标准库 log 输出，默认写 stderr）。
//
// 依赖方向强约束：本包是根包门面与 notify 消费包共同依赖的唯一横切件，
// notify 只允许 import 本包，不得 import 门面包与 internal/ 协议内核。
package sdklog

import (
	"fmt"
	"log"
)

// Logger 是 SDK 对日志器的最小要求：四个常用级别、printf 风格（string 格式串 +
// 可变参数）。刻意不包含结构化字段 / 动态级别等能力，保证宿主任何日志库都能低成本适配。
//
// 实现方需自行保证并发安全；format 与 args 的语义与 fmt.Sprintf 一致。
type Logger interface {
	// Debugf 记录调试级明细（如请求/响应报文），仅在调用明细开关开启时才会被 SDK 使用，
	// 因此可能携带业务数据内容。
	Debugf(format string, args ...any)
	// Infof 记录不含敏感内容的调用级摘要。
	Infof(format string, args ...any)
	// Warnf 记录不影响调用结果但值得关注的异常路径。
	Warnf(format string, args ...any)
	// Errorf 记录失败路径（远端错误码、重试耗尽等）。
	Errorf(format string, args ...any)
}

// StdLogger 是基于标准库 log 的默认 Logger 实现：写入 log 包全局输出目标
// （默认 stderr，含标准日期时间前缀），宿主可用 log.SetOutput 重定向。
type StdLogger struct{}

// NewStdLogger 创建默认日志器（标准库输出）。
func NewStdLogger() *StdLogger {
	return &StdLogger{}
}

// Debugf 以 "DEBUG" 级别标签经标准库 log 输出。
func (StdLogger) Debugf(format string, args ...any) { write("DEBUG", format, args...) }

// Infof 以 "INFO" 级别标签经标准库 log 输出。
func (StdLogger) Infof(format string, args ...any) { write("INFO", format, args...) }

// Warnf 以 "WARN" 级别标签经标准库 log 输出。
func (StdLogger) Warnf(format string, args ...any) { write("WARN", format, args...) }

// Errorf 以 "ERROR" 级别标签经标准库 log 输出。
func (StdLogger) Errorf(format string, args ...any) { write("ERROR", format, args...) }

// write 拼 “级别标签 + 正文” 后交给标准库 log（其内部互斥锁保证并发安全，
// 换行由 log 统一补齐）。
//
// 仅在有参数时才做一次 fmt.Sprintf：无参数时直接透传原文，
// 报文里常见的 % 字符不会被误当格式化动词吞掉或触发 %!(EXTRA ...) 噪声。
func write(level, format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	log.Print(level + " " + msg)
}

// Default 返回进程级共享的默认标准库实现(零配置语义);注入自定义 Logger 时不会用到。
func Default() Logger { return StdLogger{} }

// 包级便捷转发:以显式传入的 Logger 为接收者调用对应级别方法,
// 让调用方无需 import 后同时写两种形态(接口方法 / 包函数)。
func Debugf(l Logger, format string, args ...any) { l.Debugf(format, args...) }
func Infof(l Logger, format string, args ...any)  { l.Infof(format, args...) }
func Warnf(l Logger, format string, args ...any)  { l.Warnf(format, args...) }
func Errorf(l Logger, format string, args ...any) { l.Errorf(format, args...) }
