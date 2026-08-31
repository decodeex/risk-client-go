package protocol

import (
	"encoding/json"
	"fmt"
)

// 本文件实现网关响应的「双形态解析 + 状态映射」,语义逐条对齐 Java 版
// client/support/DefaultRiskResponseHandler(含中文文案逐字引用):
//
//   - 问询形态(risk):envelope {code:string, msg, data}——code 为字符串,null/缺失即格式错;
//   - 案件形态(case/CommonResult):{success:bool, code:int, msg, data}——成功标志是布尔;
//   - 非 200 的 HTTP 状态按固定映射降级为结构化结果;解析层任何异常都不外抛,
//     一律折叠成「500」形态结果(与 Java 侧 catch(Exception) 行为一致)。
//
// 解析永不返回 error:这是双轨错误契约的远端轨——失败也是结果。

// CodeSuccess 等 ResultCode 常量 = Java ResponseCode 接口的同名值。
const (
	CodeSuccess             = "200"
	CodeUnauthorized        = "401"
	CodeForbidden           = "403"
	CodeTooManyRequests     = "429"
	CodeRequestTimeout      = "408"
	CodeInternalServerError = "500"
)

// Java 文案原文(DefaultRiskResponseHandler.handleHttpStatus / 各 catch 分支),
// 与服务端共用一整套措辞,改动前必须核对网关实际下发文案。
const (
	msgTooManyRequests = "请求过于频繁，请稍后再试"
	msgForbidden       = "请求被拒绝，请检查权限"
	msgUnauthorized    = "请求未授权，请先登录"
	msgStatusTimeout   = "请求风控服务超时，请稍后再试"
	msgServiceError    = "服务异常，请稍后再试"
	msgBadFormat       = "风控服务响应格式错误"
)

// Outcome 是两条调用链统一的结果形态:远端轨的最终产物,对应根包 Response[T]
// 的三字段(code/msg/data)。Data 仅在成功且报文携带时非空(json.RawMessage 保字节,
// 具体类型解码交由门面泛型封装)。
type Outcome struct {
	Code string
	Msg  string
	Data json.RawMessage
}

// IsSuccess 报告本次网关交互是否成功(等价 Java RiskResponse.isSuccess)。
func (o Outcome) IsSuccess() bool { return o.Code == CodeSuccess }

// StatusOutcome 把非 200 的 HTTP 状态折叠成结构化结果(Java handleHttpStatus 同表)。
func StatusOutcome(statusCode int) Outcome {
	switch statusCode {
	case 429:
		return Outcome{Code: CodeTooManyRequests, Msg: msgTooManyRequests}
	case 403:
		return Outcome{Code: CodeForbidden, Msg: msgForbidden}
	case 401:
		return Outcome{Code: CodeUnauthorized, Msg: msgUnauthorized}
	case 408:
		return Outcome{Code: CodeRequestTimeout, Msg: msgStatusTimeout}
	default:
		return Outcome{Code: CodeInternalServerError, Msg: msgServiceError}
	}
}

// TransportTimeoutOutcome 是本地判定的请求超时(Req 4.1)。operationMsg 由调用方传入
// 操作级文案:risk 固定 "请求风控服务超时，请稍后再试";案件查询为
// "查询通用审核案件超时，请稍后再试"(与 Java 各 catch(HttpTimeoutException) 一致)。
func TransportTimeoutOutcome(operationMsg string) Outcome {
	return Outcome{Code: CodeRequestTimeout, Msg: operationMsg}
}

// TransportExceptionOutcome 是其余传输故障(Req 4.2/4.3)。operationLabel 对齐 Java 的
// 日志操作名(risk:"同步风控问询";查询:"查询通用审核案件"),产出
// "<label>异常: <cause>" 形态文案。
func TransportExceptionOutcome(operationLabel string, cause error) Outcome {
	return Outcome{
		Code: CodeInternalServerError,
		Msg:  fmt.Sprintf("%s异常: %v", operationLabel, cause),
	}
}

// EmptyBodyOutcome 覆盖 Java 「done==null||length<2」分支:服务异常，响应为空。
func EmptyBodyOutcome() Outcome {
	return Outcome{Code: CodeInternalServerError, Msg: "服务异常，响应为空"}
}

// riskEnvelope 与 caseEnvelope 是两种报文的 wire 结构。unknown 字段忽略由
// encoding/json 默认行为保证(Jackson FAIL_ON_UNKNOWN_PROPERTIES=false 同义)。
type riskEnvelope struct {
	Code *string         `json:"code"` // 指针以区分 缺失/null 与 ""(Java 判 code==null)
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

type caseEnvelope struct {
	Success bool            `json:"success"`
	Code    json.RawMessage `json:"code"` // 线上实测:可能为数字或字符串,宽进后统一转字符串
	Msg     string          `json:"msg"`
	Data    json.RawMessage `json:"data"`
}

// ParseRiskBody 解析问询形态报文(已假定 HTTP 状态 200,状态判定在门面先行)。
// 解析或校验失败一律折叠为「500/风控服务响应格式错误」;
// 失败码原样透传(code+msg);成功码把 data 原始字节带出。
func ParseRiskBody(body []byte) Outcome {
	var env riskEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Code == nil {
		return Outcome{Code: CodeInternalServerError, Msg: msgBadFormat}
	}
	if *env.Code != CodeSuccess {
		return Outcome{Code: *env.Code, Msg: env.Msg}
	}
	return Outcome{Code: CodeSuccess, Msg: env.Msg, Data: env.Data}
}

// ParseCaseBody 解析案件查询形态(CommonResult:{success,code:int,...})。
// 失败时 int code 转字符串透传(String.valueOf(parsed.getCode()) 同义);
// 其它规则与问询形态一致。
func ParseCaseBody(body []byte) Outcome {
	var env caseEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Outcome{Code: CodeInternalServerError, Msg: msgBadFormat}
	}
	if !env.Success {
		return Outcome{Code: rawCodeToString(env.Code), Msg: env.Msg}
	}
	return Outcome{Code: CodeSuccess, Msg: env.Msg, Data: env.Data}
}

// rawCodeToString 把 JSON 里的 code(数字或字符串)规整为字符串
// (risk-audit 实测失败时 code 为字符串 "504",与数字形态并存)。
func rawCodeToString(raw json.RawMessage) string {
	var asNum json.Number
	if json.Unmarshal(raw, &asNum) == nil {
		return asNum.String()
	}
	var asStr string
	if json.Unmarshal(raw, &asStr) == nil {
		return asStr
	}
	return ""
}
