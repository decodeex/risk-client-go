// Package notify 提供风控审核结果通知的 Kafka 批量消费能力（聚批拉取、业务回调、
// 手动位点提交、重试、优雅启停；具体实现见后续任务 4.x）。
//
// 依赖方向强约束（design.md）：本包独立于根包门面，只允许依赖
// github.com/decodeex/risk-client-go/sdklog（最小 Logger 接口）作为日志横切件，
// 禁止 import 门面包与 internal/ 协议内核。
package notify
