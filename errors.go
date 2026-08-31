package riskclient

import "github.com/decodeex/bifu-risk-sdk/internal/protocol"

// 本文件是 SDK 双轨错误契约中的 “本地 error” 轨公开面:
//
//   - 本地轨:预检类失败(配置/参数/保留字段),返回下方三类哨兵之一经
//     fmt.Errorf("...: %w", sentinel) 包装后的错误,调用方用 errors.Is 判类;
//     命中哨兵的错误一律发生在发起网络请求之前,绝不发网(Req 6.2 / 6.3 / 1.3)。
//   - 远端轨:网关返回的结构化结果码(见 types.go 的 Response[T].Code),不算 error,
//     由调用方按码分支处理(Req 4.x),两条轨道不可混用。
//
// 哨兵真源在 internal/protocol/sentinels.go(internal 包与门面包共享同一实例,
// 避免两处定义漂移);此处仅再导出,注释保留原语义说明。

// ErrConfig 表示客户端配置缺失或非法。触发场景:
//   - 初始化阶段必要配置缺失或非法:网关地址、clientId、clientSecret、公钥为空,
//     或公钥无法解析为 P-256 公钥 —— 此时 New 不产出实例(Req 6.2);
//   - 调用时超时表中没有该事件类型的条目 —— 预检直接报此错且不发网(Req 6.3)。
var ErrConfig = protocol.ErrConfig

// ErrParam 表示调用入参缺失或非法。触发场景(Req 1.3 等):
//   - BasicParam 必填项为空(业务 ID、事件类型等)或取值非法;
//   - bizData / secretFields 形参不合法(nil 映射之外的形态问题)。
var ErrParam = protocol.ErrParam

// ErrReservedField 表示业务数据使用了协议保留字段名。触发场景(Req 1.3):
// 业务数据键命中网关协议保留字段(requestTime、traceId、clientId 等)——
// 这些字段由 SDK 系统注入、调用方不得覆盖,该次调用被拒绝且不发网络请求。
var ErrReservedField = protocol.ErrReservedField
