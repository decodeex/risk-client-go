package riskclient

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// 本文件是 SDK 公开 DTO(design.md Data Models)。字段名与 Java 版实体一一对应;
// 泛型结果容器的双形态(code:string 与 success:bool)是服务端既有事实,不是设计选择。

// BasicParam 是一次问询的基础参数(JAVA RiskBasicParam 同名同义)。
// 空值语义交由协议管线(默认补齐/NON_NULL 出现规则)处理——调用方只管按业务事实填。
type BasicParam struct {
	BizID       string // 业务 ID(必填)
	UserID      string // 用户 ID;空则默认 UNKNOWN
	Platform    string // 平台;可空(不出现于报文)
	EventType   string // 事件类型(必填,同时决定超时与路径)
	FingerToken string // 设备指纹 token;可空
	IP          string // 业务侧感知的用户 IP;可空
	BizTime     int64  // 业务发生时间毫秒;0 视为未设置
	TenantID    string // 租户;空则默认 default
	SiteType    string // 站点类型;空则默认 default
}

// Strategy 是问询成功后的判定载荷(Java RiskStrategy 字段同名)。
// Strategy 取值约定:accept / reject / verify / review。
type Strategy struct {
	RiskID   string         `json:"riskId"`
	Strategy string         `json:"strategy"`
	Data     map[string]any `json:"data"`
}

// Response 是问询链的结果容器(code 形态;Java RiskResponse 同构)。
// 双轨契约的远端轨:失败也是本结构的合法取值(Code != "200"),error 恒 nil。
type Response[T any] struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

// IsSuccess 统一成功判定(等价 Java isSuccess:code=="200")。
func (r Response[T]) IsSuccess() bool { return r.Code == "200" }

// CaseResponse 是案件查询链的结果容器(CommonResult 形态:success 布尔 + int code)。
type CaseResponse[T any] struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Data    T      `json:"data"`
}

// IsSuccess 成功判定直接采信服务端布尔(等价 CommonResult.isSuccess)。
func (r CaseResponse[T]) IsSuccess() bool { return r.Success }

// AuditCaseResult 是审核案件查询成功的业务载荷(字段同名对齐 GeneralCaseQueryResponse;
// auditTime 服务端为 java.util.Date,Jackson 序列化为 epoch 毫秒数值,已核实源码)。
type AuditCaseResult struct {
	CaseNo      string `json:"caseNo"`
	EventType   string `json:"eventType"`
	RiskID      string `json:"riskId"`
	BizID       string `json:"bizId"`
	AuditResult string `json:"auditResult"`
	AuditTime   int64  `json:"auditTime"`
	AuditUser   string `json:"auditUser"`
	Remark      string `json:"remark"`
}

// UnmarshalJSON 兼容 auditTime 的数值与字符串两种形态(个别历史环境曾以字符串下发;
// 宽进严出:内部形态恒为 int64 毫秒)。
func (a *AuditCaseResult) UnmarshalJSON(data []byte) error {
	type alias AuditCaseResult // 规避递归
	var direct alias
	if err := json.Unmarshal(data, &direct); err == nil {
		*a = AuditCaseResult(direct)
		return nil
	}
	var soft map[string]json.RawMessage
	if err := json.Unmarshal(data, &soft); err != nil {
		return fmt.Errorf("riskclient: decode audit case: %w", err)
	}
	if err := json.Unmarshal(data, (*alias)(a)); err != nil {
		return err // 非 auditTime 字段的真问题照常上抛
	}
	if raw, ok := soft["auditTime"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			v, perr := strconv.ParseInt(s, 10, 64)
			if perr != nil {
				return fmt.Errorf("riskclient: auditTime 字符串不可解析为毫秒时间戳: %w", perr)
			}
			a.AuditTime = v
		}
	}
	return nil
}
