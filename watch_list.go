package riskclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/decodeex/risk-client-go/internal/protocol"
)

// 名单外部上报(watch-list-external-input design C1)。
// 与 Risk()/QueryAuditCase() 的双轨契约不同,本方法是单轨:error 涵盖本地预检、
// 网络失败与非 200 状态(含限流 429);HTTP 200 内的逐条 REJECTED 是合法回执,
// 不作为 error(Req 1.4:拒绝不影响同批)。

// 路径与超时。上报为告警级低频调用,不走 EventTimeoutMs(无 eventType 语义,
// SDK 配置零新增——design C1);固定 10s 上限,调用方可用 ctx 收紧。
const (
	watchListReportPath    = "/risk-watch-list/external/report"
	watchListReportTimeout = 10 * time.Second

	timeoutMsgWatchList     = "上报名单超时，请稍后再试"
	exceptionLabelWatchList = "上报名单"
)

// 回执四态常量(design C1 / C3)。
const (
	// WatchListResultSAVED 新写入。
	WatchListResultSAVED = "SAVED"
	// WatchListResultEXTENDED 已存在且已续期(重复上报延长有效期)。
	WatchListResultEXTENDED = "EXTENDED"
	// WatchListResultEXISTED 已存在未延长(建议时长未更晚/人工禁用不动)。
	WatchListResultEXISTED = "EXISTED"
	// WatchListResultREJECTED 拒绝(解密/准入/校验失败等,原因见 Message)。
	WatchListResultREJECTED = "REJECTED"
)

// WatchListReport 是一条上报名单对象。
type WatchListReport struct {
	// ObjectType 对象类型,如 "ip";非空(对象类型不限:账号/设备/地址均可)。
	ObjectType string
	// ListType 名单类别,"black" | "white";非空。
	ListType string
	// ItemValue 对象值明文;非空。SDK 固定 ECIES 加密后上送,密文参与签名。
	ItemValue string
	// Reason 上报原因,必填非空(审计溯源);SDK 加密后上送,空白本地预检拒绝。
	Reason string
	// TtlMinutes 建议时长(分钟),可选;<=0 表示不提建议时长,由服务端默认 TTL 决定。
	TtlMinutes int64
}

// WatchListReportResult 是一次上报的回执集合。
type WatchListReportResult struct {
	// Items 与入参顺序一致,逐条对应。
	Items []WatchListReportReceipt
}

// WatchListReportReceipt 是单条上报的回执。身份三字段(ObjectType/ListType/
// ItemValue)回显自入参明文;服务端回执只含摘要(itemValueSha512),不回明文。
type WatchListReportReceipt struct {
	ObjectType string
	ListType   string
	ItemValue  string
	// Result 取值:WatchListResultSAVED | WatchListResultEXTENDED |
	// WatchListResultEXISTED | WatchListResultREJECTED。
	Result string
	// Message 附加说明(REJECTED 时为拒绝原因,如 unauthorized/invalid)。
	Message string
}

// ReportWatchList 上报名单对象(黑/白名单、对象类型不限),返回逐条回执。
// itemValue/reason 由 SDK 固定 ECIES 加密(密文参与签名),调用方传明文;
// reason 必填非空(上报原因,审计溯源),空白本地预检拒绝。
// 协议头(Authorization/X-SIGNATURE/X-RISK-BASIC)与 Risk() 同构,复用同一把
// Config.PublicKey(零新配置);线上 body 即 canonjson 字节(签名原文==发送字节)。
//
// 一条上报可扇出写入风控侧登记的 N 个名单(1→N),回执按上报项笼统聚合:
// 任一名单写入成功即成功态(取 SAVED>EXTENDED>EXISTED),全部失败才 REJECTED
// (首个原因码);写不进的名单只落风控侧日志,无整体事务、不回滚已成功的写入,
// 续期式写入幂等,原样重试无害。
//
// 网络失败/超时/限流 429 等一切非 200 按 error 返回;HTTP 200 内的逐条 REJECTED
// 不是 error,经 Result.Message 给出原因。任何路径不 panic。
func (c *Client) ReportWatchList(ctx context.Context, items []WatchListReport) (*WatchListReportResult, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: items must not be empty", protocol.ErrParam)
	}
	for i, it := range items {
		if strings.TrimSpace(it.Reason) == "" {
			return nil, fmt.Errorf("%w: items[%d] reason is required", protocol.ErrParam, i)
		}
	}
	sys, err := c.sysFields(ctx)
	if err != nil {
		return nil, err
	}

	built, berr := protocol.BuildWatchListReportRequest(watchListItemMaps(items), c.signer, sys)
	if berr != nil { // 参数/配置类哨兵原样上抛
		return nil, berr
	}

	urlPath := strings.TrimRight(c.cfg.BaseURL, "/") + watchListReportPath
	headers := protocol.Build(protocol.ModeSync, built.HeaderJSON, built.Signature,
		"UNKNOWN", c.auth()) // M2M 无用户语义,X-User-Id 与案件查询同口径
	c.logRequest(urlPath, headers, built.Body)

	callCtx, cancel := context.WithTimeout(ctx, watchListReportTimeout)
	defer cancel()

	started := time.Now()
	status, raw, terr := c.do(callCtx, urlPath, headers, built.Body)
	if terr != nil {
		o := transportOutcome(terr, timeoutMsgWatchList, exceptionLabelWatchList)
		c.logResponse(urlPath, o, started)
		return nil, fmt.Errorf("riskclient: 上报名单失败(code=%s): %s: %w", o.Code, o.Msg, terr)
	}
	if status != http.StatusOK {
		o := protocol.StatusOutcome(status)
		c.logResponse(urlPath, o, started)
		return nil, fmt.Errorf("riskclient: 上报名单失败: http=%d code=%s msg=%s",
			status, o.Code, o.Msg)
	}

	result, perr := parseWatchListReceipts(raw, items)
	if perr != nil {
		c.logResponse(urlPath, protocol.Outcome{Code: protocol.CodeInternalServerError, Msg: perr.Error()}, started)
		return nil, fmt.Errorf("riskclient: 上报名单响应处理异常: %w", perr)
	}
	c.logResponse(urlPath, protocol.Outcome{Code: protocol.CodeSuccess}, started)
	return result, nil
}

// watchListItemMaps 把公开类型转为协议装配载体:objectType/listType/itemValue/
// reason 明文进入,protocol 层对 itemValue/reason 固定 ECIES 置换;
// reason 必填(门面已预检非空),ttlMinutes<=0 整键不出现(NON_NULL)。
func watchListItemMaps(items []WatchListReport) []map[string]any {
	out := make([]map[string]any, len(items))
	for i, it := range items {
		m := map[string]any{
			"objectType": it.ObjectType,
			"listType":   it.ListType,
			"itemValue":  it.ItemValue,
			"reason":     it.Reason,
		}
		if it.TtlMinutes > 0 {
			m["ttlMinutes"] = it.TtlMinutes
		}
		out[i] = m
	}
	return out
}

// watchListReceiptWire 是服务端逐条回执的 wire 形态(design C3):
// itemValueSha512 是对象值摘要,不回明文/密文。
type watchListReceiptWire struct {
	ObjectType      string `json:"objectType"`
	ListType        string `json:"listType"`
	ItemValueSha512 string `json:"itemValueSha512"`
	Result          string `json:"result"`
	Message         string `json:"message"`
}

// parseWatchListReceipts 解析 200 回执并按入参顺序对齐装填(身份字段回显自入参)。
// 回执条数与入参不符视为契约违约,显式报错(宁拒不猜,防静默错位)。
func parseWatchListReceipts(raw []byte, sent []WatchListReport) (*WatchListReportResult, error) {
	if len(raw) == 0 {
		return nil, errors.New("响应为空")
	}
	var wire struct {
		Items []watchListReceiptWire `json:"items"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("解析回执: %w", err)
	}
	if len(wire.Items) != len(sent) {
		return nil, fmt.Errorf("回执条数 %d 与上报表条数 %d 不符", len(wire.Items), len(sent))
	}
	out := &WatchListReportResult{Items: make([]WatchListReportReceipt, len(sent))}
	for i, r := range wire.Items {
		out.Items[i] = WatchListReportReceipt{
			ObjectType: sent[i].ObjectType,
			ListType:   sent[i].ListType,
			ItemValue:  sent[i].ItemValue,
			Result:     r.Result,
			Message:    r.Message,
		}
	}
	return out, nil
}
