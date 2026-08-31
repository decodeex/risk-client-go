package protocol

import "errors"

// 协议层语义哨兵(真源)。根包 errors.go 将其再导出为 riskclient.ErrConfig 等,
// 保持公开 API 与 design.md 契约不变,同时 internal 包内可直接 errors.Is 判类。
var (
	// ErrParam 表示调用入参缺失或非法(Req 1.3 / secretFields 校验失败等)。
	ErrParam = errors.New("riskclient: invalid param")
	// ErrReservedField 表示业务数据命中协议保留字段名(Req 1.3)。
	ErrReservedField = errors.New("riskclient: reserved field")
	// ErrConfig 表示配置缺失或非法(New 阶段/超时表缺配等)。
	ErrConfig = errors.New("riskclient: invalid config")
)

// 本包内的短别名(var,error 是接口类型不能作常量):装配管线代码用别名保持
// 错误链可读,同时让"真源唯一"在 diff 里一眼可见。
var (
	ErrParamAlias         = ErrParam
	ErrReservedFieldAlias = ErrReservedField
	ErrConfigAlias        = ErrConfig
)
