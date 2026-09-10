// Package notify —— 通知验签（ECDSA 公钥验签）。
//
// 与生产端（risk-basic-common NotifySignService / Java SDK NotifyVerifier）跨语言对齐：
//   - 基准串：ts:nonce:canonicalJson（canonicalJson 为剔除 sign 与 auditRemark 字段后的规范 JSON）
//   - 规范 JSON：键按字节序排序、紧凑输出、转义与 encoding/json 默认一致（escapeHTML）
//   - 签名值：v1:Base64(SHA256withECDSA(私钥, 基准串))，ASN.1 DER —— 公钥验签，验签方无伪造能力
//   - 公钥为 M2M 必配项（Config.PublicKey），升级 SDK 即生效，零新增配置
package notify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// VerifyResult 验签四态（与 Java SDK NotifyVerifier.Result 对齐）。
type VerifyResult int

const (
	VerifyPass VerifyResult = iota
	VerifySignFail
	VerifyWindowFail
	VerifyNoSign
)

func (r VerifyResult) String() string {
	switch r {
	case VerifyPass:
		return "PASS"
	case VerifySignFail:
		return "SIGN_FAIL"
	case VerifyWindowFail:
		return "WINDOW_FAIL"
	default:
		return "NO_SIGN"
	}
}

// NonceChecker 可选重放去重回调：返回 false 表示窗口内重复（视为验签失败）。
type NonceChecker func(nonce string) bool

// NotifyVerifier 通知验签器。零值不可用，经 NewNotifyVerifier 构造。
type NotifyVerifier struct {
	pub          *ecdsa.PublicKey
	tolerance    time.Duration
	nonceChecker NonceChecker
	// verifyTopics 需要验签的 topic 集合（空集视为默认 RISK_AUDIT_RESULT_NOTIFY）。
	verifyTopics map[string]bool
}

const (
	signPrefix         = "v1:"
	defaultVerifyTopic = "RISK_AUDIT_RESULT_NOTIFY"
)

// NewNotifyVerifier 按公钥构造验签器；公钥不可解析返回错误（公钥为 M2M 必配项，正常配置必可用）。
// verifyTopics 为需要验签的 topic 列表（空视为仅默认 RISK_AUDIT_RESULT_NOTIFY），其余 topic 消息不验签直接放行。
func NewNotifyVerifier(publicKeyPEMorB64 string, tolerance time.Duration, nonceChecker NonceChecker, verifyTopics []string) (*NotifyVerifier, error) {
	pub, err := parseVerifyPublicKey(publicKeyPEMorB64)
	if err != nil {
		return nil, err
	}
	v := &NotifyVerifier{pub: pub, tolerance: tolerance, nonceChecker: nonceChecker,
		verifyTopics: map[string]bool{}}
	if v.tolerance <= 0 {
		v.tolerance = 300 * time.Second
	}
	for _, t := range verifyTopics {
		if tt := strings.TrimSpace(t); tt != "" {
			v.verifyTopics[tt] = true
		}
	}
	if len(v.verifyTopics) == 0 {
		v.verifyTopics[defaultVerifyTopic] = true
	}
	return v, nil
}

// VerifyFor 按 topic 判定是否验签：配置的 topic（默认 RISK_AUDIT_RESULT_NOTIFY）走验签，其余直接放行。
func (v *NotifyVerifier) VerifyFor(topic, raw string) VerifyResult {
	if v == nil || !v.verifyTopics[topic] {
		return VerifyPass
	}
	return v.Verify(raw)
}

// Verify 验签一条消息原文，返回四态结果；解析异常按 SIGN_FAIL。
func (v *NotifyVerifier) Verify(raw string) VerifyResult {
	if v == nil {
		return VerifyPass
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return VerifyNoSign
	}
	var m map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber() // 大整数原样输出，避免 float64 科学计数法破坏基准
	if err := dec.Decode(&m); err != nil {
		return VerifySignFail
	}
	signVal, ok := m["sign"].(string)
	if !ok || signVal == "" {
		return VerifyNoSign
	}
	tsNum, ok := m["ts"].(json.Number)
	if !ok {
		return VerifySignFail
	}
	tsMillis, err := tsNum.Int64()
	if err != nil {
		return VerifySignFail
	}
	nonce, _ := m["nonce"].(string)

	now := time.Now().UnixMilli()
	diff := now - tsMillis
	if diff < 0 {
		diff = -diff
	}
	if diff > v.tolerance.Milliseconds() {
		return VerifyWindowFail
	}
	if v.nonceChecker != nil && !v.nonceChecker(nonce) {
		return VerifySignFail
	}

	// 基准剔除 sign 与 auditRemark：审核员自由文本不参与签名（与生产端同口径），
	// 防伪核心是 auditResult/bizId 等受控字段；remark 被篡改不驱动放行，对账可见。
	delete(m, "sign")
	delete(m, "auditRemark")
	canonical, err := canonicalJSON(m)
	if err != nil {
		return VerifySignFail
	}
	basis := fmt.Sprintf("%d:%s:%s", tsMillis, nonce, canonical)

	if !strings.HasPrefix(signVal, signPrefix) {
		return VerifySignFail
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(signVal, signPrefix))
	if err != nil {
		return VerifySignFail
	}
	digest := sha256.Sum256([]byte(basis))
	if ecdsa.VerifyASN1(v.pub, digest[:], der) {
		return VerifyPass
	}
	return VerifySignFail
}

// parseVerifyPublicKey 解析 PEM 或 Base64(SPKI DER) 的 ECC 公钥为 P-256。
func parseVerifyPublicKey(raw string) (*ecdsa.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	var der []byte
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		der = block.Bytes
	} else {
		cleaned := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, trimmed)
		d, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("公钥 base64 解析失败: %v", err)
		}
		der = d
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("公钥 SPKI/PKIX 解析失败: %v", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥类型 %T 不是 ECDSA", parsed)
	}
	if key.Curve == nil || key.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("公钥曲线 %v 非 P-256", key.Curve)
	}
	return key, nil
}

// canonicalJSON 见 canonical.go —— 转义表冻结，不随 Go 版本漂移。
