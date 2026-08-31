package notify

import "github.com/decodeex/bifu-risk-sdk/sdklog"

// defaultLogger 返回 notify 的缺省日志器（SDK 内置标准库实现）。
//
// 任务 4.1 的 ConsumerConfig.Logger 字段（sdklog.Logger）未注入时以此兜底；
// 本文件同时是依赖方向的显式声明点：notify 对 SDK 横切能力的引用仅限
// sdklog.Logger，不得 import 门面包与 internal/ 协议内核。
func defaultLogger() sdklog.Logger {
	return sdklog.NewStdLogger()
}
