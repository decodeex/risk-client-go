package protocol

import (
	"encoding/base64"
	"net/http"
)

// ---------------------------------------------------------------------------
// 六请求头构造 —— Java 版对照点 RiskSimpleClient.buildHeaders(L298-L307)。
//
//   Content-Type   application/json(固定)
//   X-RISK-MODE    同步链路恒 sync
//   X-SIGNATURE    签名器产出:标准 Base64(ECIES(小写hex(sha512(升序JSON))))
//   Authorization  "Basic " + URL-safe 带填充 Base64(clientId + ':' + clientSecret)
//                  ★ 不是标准 Basic 的字母表:+ / 被替换成 - _,且【保留】填充等号;
//                    这是网关侧的私有约定,对齐 host 侧会在这里翻车(双 Base64 变体高错点)
//   X-RISK-BASIC   URL-safe 带填充 Base64(headerJson,X-RISK-BASIC 解码回读即明文)
//   X-User-Id      问询 = basicParam.UserId 缺省 UNKNOWN;案件查询恒 UNKNOWN
//
// golden:testdata/headers_golden.json 三条样本逐字段锁定(scripts/README §三.3)。
// ---------------------------------------------------------------------------

// 头部键名常量。值本身就是 HTTP 语义的一部分,后续任务按名引用而非裸写字面串。
const (
	headerContentType   = "Content-Type"
	headerXRiskMode     = "X-RISK-MODE"
	headerXSignature    = "X-SIGNATURE"
	headerAuthorization = "Authorization"
	headerXRiskBasic    = "X-RISK-BASIC"
	headerXUserID       = "X-User-Id"
)

// 协议固定取值(mode 与 userId 默认值的字面量会被任务 2.5/2.6 引用)。
const (
	contentTypeJSON = "application/json" // 六头中 Content-Type 固定值
	// ModeSync 是同步问询链路的 X-RISK-MODE 值(导出供门面引用;async 不在本期范围)。
	ModeSync      = "sync"
	userIDUnknown = "UNKNOWN" // 问询缺省与案件查询恒用的 X-User-Id 兜底值
	basicScheme   = "Basic"   // 授权 scheme(golden 的 authorizationScheme 锁定该字面量)
)

// Auth 是网关 M2M 凭证。当前形态恰为 clientId/clientSecret 二元组,
// 不与根包 Config(任务 3.1)耦合:协议层只认自己需要的最小结构。
type Auth struct {
	ClientID     string
	ClientSecret string
}

// Build 按网关约定组装六头并返回 http.Header。
//
// 入参均为已就绪值:signature 来自 Signer.Signature,headerJSON 是 X-RISK-BASIC 的明文原文,
// userID 由调用方完成缺省补齐后传入(协议层只透传,不做默认值推断),
// mode 取 modeSync 一类的常量或后续配置值。
//
// 键名一律用直接赋值而非 Header.Set:标准库 Set 会把键规范化成 MIME 首字母大写形态
// ("X-RISK-MODE" → "X-Risk-Mode"),而本协议要求报文里逐字节保留全大写拼写;
// 直接赋值的键会由 net/http 原样写出(Header.WriteSubset 不做二次规范化)。
//
// 值不做非空校验——空凭证等属于门面 Config.Validate(6.2)的职责;本函数保持纯函数、无副作用、
// 可并发调用。
func Build(mode string, headerJSON, signature, userID string, auth Auth) http.Header {
	h := make(http.Header, 6)
	setRawHeader(h, headerContentType, contentTypeJSON)
	setRawHeader(h, headerXRiskMode, mode)
	setRawHeader(h, headerXSignature, signature)
	setRawHeader(h, headerAuthorization, basicScheme+" "+base64URLWithPadding(auth.ClientID+":"+auth.ClientSecret))
	setRawHeader(h, headerXRiskBasic, base64URLWithPadding(headerJSON))
	setRawHeader(h, headerXUserID, userID)
	return h
}

// setRawHeader 以原样键名写入单值头(绕开标准库的 MIME 规范化,键拼写即协议契约)。
func setRawHeader(h http.Header, name, value string) {
	h[name] = []string{value}
}

// base64URLWithPadding 编码成 URL-safe 字母表且保留 '=' 填充。
//
// stdlib 里 encoding/base64.URLEncoding 就是"URL-safe + 带填充"的那一款(RawURLEncoding 才是去填充版):
// 62→'-'、63→'_'、尾部 '=' 按余数补齐。单点封装让"哪一款变体"这个关键决策有唯一落点。
func base64URLWithPadding(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}
