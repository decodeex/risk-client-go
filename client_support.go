package riskclient

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/decodeex/bifu-risk-sdk/internal/protocol"
	"github.com/decodeex/bifu-risk-sdk/sdklog"
)

// 本文件承载 Client 的装配助手:公钥解析 / HTTP 连接池 / 出口 IP 兜底探测 /
// 明细日志工具。全部为无状态纯函数或一次性装配逻辑,保持 client.go 只读业务流。

// parsePublicKey 把 Config.PublicKey 两种形态解析成 P-256 公钥:
//   - PEM("-----BEGIN PUBLIC KEY-----",SPKI/PKIX 内层);
//   - 裸 Base64(标准字母表)的 SPKI DER(Java SecureUtil.loadPublicKey 的对等形态)。
//
// 解析后强制断言曲线为 P-256——协议(ECIES/签名)只在该曲线上有兼容承诺。
func parsePublicKey(raw string) (*ecdh.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	var der []byte
	var err error
	if strings.HasPrefix(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("PEM 块不可解析")
		}
		der = block.Bytes
	} else {
		der, err = base64.StdEncoding.DecodeString(stripBase64Whitespace(raw))
		if err != nil {
			return nil, fmt.Errorf("base64 解码失败: %v", err)
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("SPKI/PKIX 解析失败: %v", err)
	}
	ecdsaKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥类型 %T 不是 ECDSA(P-256) 形态", parsed)
	}
	pub, cerr := ecdsaKey.ECDH()
	if cerr != nil {
		return nil, fmt.Errorf("转为 ecdh 公钥失败: %v", cerr)
	}
	if pub.Curve() != ecdh.P256() {
		return nil, fmt.Errorf("公钥曲线 %v 非 P-256,协议只承诺 P-256 兼容", pub.Curve())
	}
	return pub, nil
}

// buildHTTPClient 按 HTTPConfig 组装共享连接池。HTTP/2 被显式禁用:
// 协议六头的全大写拼写仅在 HTTP/1.1 线上保证(h2 HPACK 强制小写,见 tasks.md 3.2 必办),
// ForceAttemptHTTP1Only 是该决策的落地锚点。
func buildHTTPClient(cfg HTTPConfig) *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: time.Duration(cfg.DialTimeoutMS) * time.Millisecond,
		}).DialContext,
		TLSHandshakeTimeout:   time.Duration(cfg.TLSHandshakeTimeoutMS) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(cfg.ResponseHeaderTimeoutMS) * time.Millisecond,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		// 六头拼写契约:自定义 TLSClientConfig 已阻断自动 h2 升级;再置空 TLSNextProto
		// 双保险强制 HTTP/1.1(h2 HPACK 会把头名全小写,协议不接受)
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Transport: transport}
}

// probeOutboundIP 探测首个非环回出口 IPv4(UDP 不发包建连即可取本地地址;
// 与 Java DefaultSystemFieldInjector 行为同构)。失败返回 "UNKNOWN" 占位。
func probeOutboundIP() string {
	conn, err := net.DialTimeout("udp4", "114.114.114.114:53", time.Second)
	if err != nil {
		return "UNKNOWN"
	}
	defer func() { _ = conn.Close() }()
	host, _, serr := net.SplitHostPort(conn.LocalAddr().String())
	if serr != nil || host == "" || strings.HasPrefix(host, "127.") {
		return "UNKNOWN"
	}
	return host
}

// ---- 日志支撑(Req 8.1/8.2)----

// logRequest 在明细态输出 URL/头(Authorization 掩码)/body;摘要始终输出。
func (c *Client) logRequest(urlPath string, headers http.Header, body []byte) {
	sdklog.Infof(c.logger, "[risk] POST %s body=%dB", urlPath, len(body))
	if c.cfg.LogDetail {
		masked := maskAuthorization(headers)
		sdklog.Debugf(c.logger, "[detail] %s -> headers=%s body=%s",
			urlPath, masked, truncForLog(body))
	}
}

// logResponse 输出调用级摘要(不含业务数据);明细态附带原始报文。
func (c *Client) logResponse(urlPath string, outcome protocol.Outcome, started time.Time) {
	sdklog.Infof(c.logger, "[risk] %s code=%s elapsed=%dms msg=%q",
		urlPath, outcome.Code, time.Since(started).Milliseconds(), outcome.Msg)
}

// sdklogDetail 显式收口"明细开"的判定点,防止散落布尔直读。
func sdklogDetail(on bool) bool { return on }

// truncForLog 截断超长报文,防日志膨胀;截断标记随行。
func truncForLog(b []byte) string {
	const limit = 4096
	s := string(b)
	if len(s) > limit {
		return s[:limit] + fmt.Sprintf("…(%d bytes truncated)", len(s)-limit)
	}
	return s
}

// maskAuthorization 返回掩码后的头副本片段:凭证值仅保留 scheme 与长度提示。
func maskAuthorization(h http.Header) string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		v := ""
		if len(vs) > 0 {
			v = vs[0]
		}
		if k == "Authorization" && len(v) > len("Basic ") {
			parts := strings.SplitN(v, " ", 2)
			out[k] = parts[0] + " ***(" + strconv.Itoa(len(v)) + " bytes)"
			continue
		}
		out[k] = v
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// decodeCaseOutcome 把案件查询的原始 200 报文装进 CaseResponse:
// Java handleCommonResultResponse 的三段语义——格式错折叠 500 / 失败 int 码透传 /
// 成功 data 转 bean(失败转门面文案)。data 不可解码时错误由调用方折成处理异常。
func decodeCaseOutcome[T AuditCaseResult](urlPath string, raw []byte) (*CaseResponse[T], error) {
	var env struct {
		Success bool            `json:"success"`
		Code    json.RawMessage `json:"code"` // 线上实测:数字/字符串两种形态并存,宽进后统一转 int
		Msg     string          `json:"msg"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return &CaseResponse[T]{Success: false, Code: 500, Msg: "风控服务响应格式错误"}, nil
	}
	if !env.Success {
		return &CaseResponse[T]{Success: false, Code: flexibleToInt(env.Code), Msg: env.Msg}, nil
	}
	var d T
	if len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return nil, err // 调用方折叠「响应处理异常」
		}
	}
	return &CaseResponse[T]{Success: true, Code: flexibleToInt(env.Code), Msg: env.Msg, Data: d}, nil
}

// stripBase64Whitespace 容忍配置里粘贴的换行/空格。
func stripBase64Whitespace(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\n', '\r', ' ', '\t':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// flexibleToInt 把 JSON 里的 code(数字或字符串数字)转成 int;无法解析返回 -1。
func flexibleToInt(raw json.RawMessage) int {
	var asInt int
	if json.Unmarshal(raw, &asInt) == nil {
		return asInt
	}
	var asStr string
	if json.Unmarshal(raw, &asStr) == nil {
		var v int
		if _, err := fmt.Sscanf(strings.TrimSpace(asStr), "%d", &v); err == nil {
			return v
		}
	}
	return -1
}
