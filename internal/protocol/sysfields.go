package protocol

import (
	"time"
)

// 本文件承载协议的系统注入字段(requestTime/traceId/requestIp/clientId/clientVersion):
// Java 版由 DefaultSystemFieldInjector 注入这五个键(golden 见 testdata/case_payload.json 的
// sysFields 块)。design 勘误:requestIp 只接收注入值(探测与缓存在门面 New 时完成),
// 本包保持零 IO 纯函数 —— 不读时钟以外的东西、不碰网卡。

// DefaultClientVersion 是 clientVersion 的缺省值(对齐 Java 版硬编码的 "1.0.7")。
// 允许宿主经 Config 覆盖(design.md sysfields 条目的有意增强),此处只给常量。
const DefaultClientVersion = "1.0.7"

// ReservedFieldNames 是网关协议保留字段全集:业务数据命中任何一个都会被
// request 构造层(任务 2.5)以 ErrReservedField 拒绝且不发网(Req 1.3)。
// 五个注入键天然由 SDK 自己填写;其余为 basicParam 协议字段。
var ReservedFieldNames = []string{
	"bizId", "userId", "platform", "eventType", "fingerToken", "ip", "bizTime",
	"tenantId", "siteType",
	"requestTime", "traceId", "requestIp", "clientId", "clientVersion",
}

// SystemFields 是一次调用的注入载体。各值全部显式传入,本文件不做任何探测:
// requestTime 由调用方取 NowMillis()(或测试定值);traceId 经 NewUUIDv4();
// clientId/clientVersion 来自 Config;requestIP 来自 Config 或 WithRequestIP。
//
// golden 复现形态(testdata/case_payload.json sample A):
//
//	{"requestTime":1756272000000,"traceId":"3fa85f64-…","requestIp":"192.168.1.100",
//	 "clientId":"test-client-id","clientVersion":"1.0.7"}
type SystemFields struct {
	RequestTime   int64  // 毫秒时间戳(Long,Jackson 输出无小数点)
	TraceID       string // UUIDv4 小写带连字符
	ClientID      string
	ClientVersion string
	RequestIP     string
}

// NowMillis 返回当前毫秒时间戳(独立小函数便于 2.5 测试替换语义时引用同一来源)。
func NowMillis() int64 { return time.Now().UnixMilli() }

// InjectSystemFields 把五个系统键写入 m(不存在覆盖问题:这些键保留,业务侧
// 在 2.5 的预留校验里已经被拦下)。m 为 nil 时静默返回——纯函数约定上 nil 输入
// 视为"无载体",调用方(request 层)永远传非 nil 合并 map。
func InjectSystemFields(m map[string]any, sf SystemFields) {
	if m == nil {
		return
	}
	m["requestTime"] = sf.RequestTime
	m["traceId"] = sf.TraceID
	m["clientId"] = sf.ClientID
	m["clientVersion"] = sf.ClientVersion
	m["requestIp"] = sf.RequestIP
}
