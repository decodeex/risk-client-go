package riskclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/decodeex/risk-client-go/internal/protocol"
	"github.com/decodeex/risk-client-go/sdklog"
)

// Client 是两项网关调用的唯一门面(同步问询 Risk / 审核案件查询 QueryAuditCase)。
// 并发安全:实例全部字段在 New 后只读;多 goroutine 可共享同一 Client。
// 双轨错误契约:
//   - 本地预检失败(参数 ErrParam / 配置 ErrConfig / 保留字段 ErrReservedField)→ error 非 nil,未发网络;
//   - 其余一切失败(超时 408 / 传输 500 / 网关状态 / 格式错)→ 结构化结果,error==nil。
// 任何路径不 panic(Req 4.4)。

// Client 见包注释与各方法文档。
type Client struct {
	cfg       Config
	signer    *protocol.Signer
	http      *http.Client
	logger    sdklog.Logger
	requestIP string
	trace     func() (string, error)
}

// New 按 Config+Options 构造客户端。失败即返回包装 ErrConfig 的错误且不产出可用实例(Req 6.2)。
func New(cfg Config, opts ...Option) (*Client, error) {
	cfg = cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	st := clientSettings{logger: sdklog.Default()}
	for _, o := range opts {
		if o != nil {
			o(&st)
		}
	}

	pub, perr := parsePublicKey(cfg.PublicKey)
	if perr != nil {
		return nil, fmt.Errorf("%w: public_key 解析失败: %v", protocol.ErrConfig, perr)
	}
	signer, serr := protocol.NewSigner(pub)
	if serr != nil {
		return nil, fmt.Errorf("%w: %v", protocol.ErrConfig, serr)
	}

	hc := st.httpClient
	if hc == nil {
		hc = buildHTTPClient(cfg.HTTP)
	}

	ip := st.requestIP
	if !st.haveIP { // 未显式指定才走兜底探测(K8s 多网卡请务必 WithRequestIP)
		ip = probeOutboundIP()
	}

	c := &Client{
		cfg: cfg, signer: signer, http: hc,
		logger: st.logger, requestIP: ip,
		trace: func() (string, error) {
			if st.useTraceFn {
				return st.traceFn()
			}
			return protocol.NewUUIDv4()
		},
	}
	sdklog.Infof(c.logger, "riskclient ready base=%s event_timeout_entries=%d",
		cfg.BaseURL, len(cfg.EventTimeoutMs))
	return c, nil
}

// Risk 发起一次同步风控问询,返回策略判定(accept/reject/verify/review 等在 Strategy 内)。
func (c *Client) Risk(ctx context.Context, p BasicParam, bizData map[string]any,
	secretFields []string) (*Response[Strategy], error) {

	if p.BizID == "" || p.EventType == "" {
		return nil, fmt.Errorf("%w: bizId and eventType are required", protocol.ErrParam)
	}
	timeout, ok := c.cfg.eventTimeout(p.EventType)
	if !ok { // Req 6.3:缺事件超时=本地失败,不发网
		return nil, fmt.Errorf("%w: event timeout not configured for %q", protocol.ErrConfig, p.EventType)
	}
	sys, err := c.sysFields(ctx)
	if err != nil {
		return nil, err
	}

	started := time.Now()
	built, berr := protocol.BuildRiskRequest(protocol.RiskParams{
		BizID: p.BizID, UserID: p.UserID, Platform: p.Platform, EventType: p.EventType,
		FingerToken: p.FingerToken, IP: p.IP, BizTime: p.BizTime,
		TenantID: p.TenantID, SiteType: p.SiteType,
	}, bizData, secretFields, c.signer, sys)
	if berr != nil { // 参数/保留字段类哨兵原样上抛(双轨契约本地轨)
		return nil, berr
	}

	bodyBytes, mErr := protocol.Marshal(built.Body)
	if mErr != nil {
		return nil, fmt.Errorf("%w: marshal body: %v", protocol.ErrParam, mErr)
	}
	urlPath := c.riskURL(p.EventType)
	headers := protocol.Build(protocol.ModeSync, built.HeaderJSON, built.Signature,
		effectiveUserID(p.UserID), c.auth())
	c.logRequest(urlPath, headers, bodyBytes)

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	status, raw, terr := c.do(callCtx, urlPath, headers, bodyBytes)
	var outcome protocol.Outcome
	switch {
	case terr != nil:
		outcome = transportOutcome(terr, timeoutMsgRisk, exceptionLabelRisk)
	case status != http.StatusOK:
		outcome = protocol.StatusOutcome(status)
	default:
		outcome = protocol.ParseRiskBody(raw)
	}
	c.logResponse(urlPath, outcome, started)

	resp, derr := toStrategyResponse(outcome)
	if derr != nil { // 成功但 data 落不了 Strategy:折叠 Java 同款处理异常文案
		return &Response[Strategy]{Code: "500", Msg: fmt.Sprintf("响应处理异常: %v", derr)}, nil
	}
	return resp, nil
}

// QueryAuditCase 按事件类型+业务 ID 查询人工审核案件结果(上游补偿任务用)。
func (c *Client) QueryAuditCase(ctx context.Context, eventType, bizID string) (*CaseResponse[AuditCaseResult], error) {
	if eventType == "" || bizID == "" {
		return nil, fmt.Errorf("%w: eventType and bizId are required", protocol.ErrParam)
	}
	timeout, ok := c.cfg.eventTimeout(eventType)
	if !ok {
		return nil, fmt.Errorf("%w: event timeout not configured for %q", protocol.ErrConfig, eventType)
	}
	sys, err := c.sysFields(ctx)
	if err != nil {
		return nil, err
	}

	started := time.Now()
	built, berr := protocol.BuildCaseQueryRequest(eventType, bizID, c.signer, sys)
	if berr != nil {
		return nil, berr
	}

	bodyBytes, mErr := protocol.Marshal(built.Body)
	if mErr != nil {
		return nil, fmt.Errorf("%w: marshal body: %v", protocol.ErrParam, mErr)
	}
	urlPath := strings.TrimRight(c.cfg.BaseURL, "/") + c.cfg.CaseQueryPath // 无路径参数(可按网关环境覆盖)
	headers := protocol.Build(protocol.ModeSync, built.HeaderJSON, built.Signature,
		"UNKNOWN", c.auth()) // Java 版案件查询 X-User-Id 恒 "UNKNOWN"
	c.logRequest(urlPath, headers, bodyBytes)

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	status, raw, terr := c.do(callCtx, urlPath, headers, bodyBytes)
	resp := &CaseResponse[AuditCaseResult]{}
	switch {
	case terr != nil:
		o := transportOutcome(terr, timeoutMsgCase, exceptionLabelCase)
		*resp = CaseResponse[AuditCaseResult]{Success: false, Code: codeToInt(o.Code), Msg: o.Msg}
	case status != http.StatusOK:
		o := protocol.StatusOutcome(status)
		*resp = CaseResponse[AuditCaseResult]{Success: false, Code: codeToInt(o.Code), Msg: o.Msg}
	default:
		got, derr := decodeCaseOutcome(urlPath, raw)
		if derr != nil {
			return &CaseResponse[AuditCaseResult]{
				Code: 500, Msg: fmt.Sprintf("响应处理异常: %v", derr),
			}, nil
		}
		resp = got
	}
	c.logResponse(urlPath, protocol.Outcome{Code: strconv.Itoa(resp.Code), Msg: resp.Msg}, started)
	return resp, nil
}

// ---- 门面内部件 ----

// auth 返回门面持有的 M2M 凭证视图。
func (c *Client) auth() protocol.Auth {
	return protocol.Auth{ClientID: c.cfg.ClientID, ClientSecret: c.cfg.ClientSecret}
}

// nowMillisFn 是 requestTime 的取时接缝(测试可固定;生产=protocol.NowMillis)。
var nowMillisFn = protocol.NowMillis

// sysFields 组装一次调用的注入载体(traceId 生成失败归入配置族错误——签名链不接受空 traceId)。
func (c *Client) sysFields(_ context.Context) (protocol.SystemFields, error) {
	traceID, err := c.trace()
	if err != nil || traceID == "" {
		return protocol.SystemFields{}, fmt.Errorf("%w: generate traceId failed: %v", protocol.ErrConfig, err)
	}
	return protocol.SystemFields{
		RequestTime:   nowMillisFn(),
		TraceID:       traceID,
		ClientID:      c.cfg.ClientID,
		ClientVersion: c.cfg.ClientVersion,
		RequestIP:     c.requestIP,
	}, nil
}

// riskURL 拼同步问询端点(eventType PathEscape 对齐 OkHttp 编码行为:字母数字 ID 两边一致)。
func (c *Client) riskURL(eventType string) string {
	return strings.TrimRight(c.cfg.BaseURL, "/") + "/risk-engine/risk/" + url.PathEscape(eventType)
}

// do 是共享传输段:发送请求并读响应体。任何传输层错误统一作为 error 返回,
// 由调用方按各自操作文案折叠成 Outcome(避免本层硬编码业务措辞)。
func (c *Client) do(ctx context.Context, urlPath string, headers http.Header,
	body []byte) (status int, respBody []byte, err error) {

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, urlPath, bytes.NewReader(body))
	if reqErr != nil {
		return 0, nil, reqErr // 配置期已验 URL 形态,防御性路径
	}
	for k, vs := range headers {
		req.Header[k] = vs // 直写保留全大写拼写(Transport 已 ForceAttemptHTTP1Only)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if rerr != nil {
		return resp.StatusCode, nil, rerr
	}
	if c.cfg.LogDetail {
		sdklog.Debugf(c.logger, "[detail] %s <- status=%d body=%s", urlPath, resp.StatusCode, truncForLog(raw))
	}
	return resp.StatusCode, raw, nil
}

const (
	timeoutMsgRisk     = "请求风控服务超时，请稍后再试"   // Java risk catch(HttpTimeoutException) 原文
	timeoutMsgCase     = "查询通用审核案件超时，请稍后再试" // Java queryAuditCase 同款原文
	exceptionLabelRisk = "同步风控问询"           // Java 日志操作名,拼 "<label>异常: ..." 文案
	exceptionLabelCase = "查询通用审核案件"
)

const maxResponseBytes = 4 << 20 // 4MB 防御异常报文

// transportOutcome 把 http 层错误分类为超时与其余(Req 4.1/4.2):
// ctx 截断 DeadlineExceeded 或 net.Error.Timeout() → 408;其余 → 500。
func transportOutcome(err error, timeoutMsg, exceptionLabel string) protocol.Outcome {
	isTimeout := errors.Is(err, context.DeadlineExceeded)
	if !isTimeout {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			isTimeout = true
		}
	}
	if isTimeout {
		return protocol.TransportTimeoutOutcome(timeoutMsg)
	}
	return protocol.TransportExceptionOutcome(exceptionLabel, err)
}

// toStrategyResponse 把 Outcome 装进问询容器:data 只在成功且报文携带时解码;
// 失败时 Data 为零值(Response[Strategy].Data 不可用与 Java success=false 时一致)。
func toStrategyResponse(o protocol.Outcome) (*Response[Strategy], error) {
	base := Response[Strategy]{Code: o.Code, Msg: o.Msg}
	if !o.IsSuccess() || len(o.Data) == 0 {
		return &base, nil
	}
	if err := json.Unmarshal(o.Data, &base.Data); err != nil {
		return nil, err
	}
	return &base, nil
}

// effectiveUserID 供六头透传层拿到管线已补默认的同一份值(仅可读性,逻辑兜底)。
func effectiveUserID(v string) string {
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

// codeToInt 把状态映射产出的字符串码转回 int(案件容器用 int 形态;
// 映射表取值恒为数值串,兜底 -1 仅在契约被破坏时出现且随 Msg 一并呈现)。
func codeToInt(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return v
}
