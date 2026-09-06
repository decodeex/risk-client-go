package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// Notification 是 RISK_AUDIT_RESULT_NOTIFY 的消息结构。
//
// 与生产端约定(RiskGeneralCaseServiceImpl.buildAuditNotifyContent /
// WithdrawCaseServiceImpl,2026-08-26 源码核实):
//   - auditTime 为毫秒时间戳(Long);
//   - auditResult 取值枚举名 accept/reject;
//   - 生产端【不含】clientId 字段(Java 客户端模型遗留字段恒为空),Go 不映射;
//   - data 仅部分事件类型携带(如出金签名数据),可为空。
type Notification struct {
	BizID       string          `json:"bizId"`
	RiskID      string          `json:"riskId"`
	EventType   string          `json:"eventType"`
	AuditResult string          `json:"auditResult"`
	AuditRemark string          `json:"auditRemark"`
	AuditUser   string          `json:"auditUser"`
	AuditTime   int64           `json:"auditTime"` // 毫秒
	Data        json.RawMessage `json:"data,omitempty"`
}

// UnmarshalJSON 宽进兼容 auditTime 的数值与字符串两种形态,内部恒为 int64 毫秒。
// 直接形态失败时回落到逐字段解析(仍容忍未知字段);顶层非对象/断裂照常上抛。
func (n *Notification) UnmarshalJSON(data []byte) error {
	type alias Notification
	var direct alias
	if err := json.Unmarshal(data, &direct); err == nil {
		*n = Notification(direct)
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	getStr := func(k string) string {
		raw := fields[k]
		if raw == nil {
			return ""
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	}
	n.BizID = getStr("bizId")
	n.RiskID = getStr("riskId")
	n.EventType = getStr("eventType")
	n.AuditResult = getStr("auditResult")
	n.AuditRemark = getStr("auditRemark")
	n.AuditUser = getStr("auditUser")
	if raw, ok := fields["data"]; ok && string(raw) != "null" {
		n.Data = append([]byte(nil), raw...)
	}
	raw, ok := fields["auditTime"]
	if !ok || string(raw) == "null" {
		return nil // 缺省=0
	}
	var iNum int64
	if json.Unmarshal(raw, &iNum) == nil {
		n.AuditTime = iNum
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("notify: auditTime 形态非法: %w", err)
	}
	v, perr := strconv.ParseInt(s, 10, 64)
	if perr != nil {
		return fmt.Errorf("notify: auditTime 字符串不可解析为毫秒: %w", perr)
	}
	n.AuditTime = v
	return nil
}

// Handler 是接入方业务回调:一批(至多 PollMaxRecords 条)通知一次交给业务。
// 返回 error 触发 SDK 层重试语义;回调内部的业务幂等由接入方保证(接入文档强制)。
type Handler func(ctx context.Context, batch []Notification) error

// Filter 决定单条通知是否交给 Handler。返回 false 的通知不进回调,
// 但仍归属本批位点集合——不会出现"被过滤消息卡死消费"的形态。
type Filter func(n Notification) bool

// OnBatchError 在批次终局失败时被调用(重试耗尽),
// 用于宿主接告警通道(如 Lark)。参数为业务批次与最终错误;可为 nil(仅日志)。
// 需要留存失败批次(落日志/库/自建转存)也在此自行处理——SDK 不内置死信投递。
// batchErr 可用 errors.Is(err, ErrBatchExhausted) 判「重试耗尽」这一形态。
type OnBatchError func(batch []Notification, batchErr error)
