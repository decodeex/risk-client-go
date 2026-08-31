package protocol

import (
	"crypto/ecdh"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// ---------------------------------------------------------------------------
// X-SIGNATURE 签名器 —— Java 版对照点 client/support/DefaultRiskSigner.java
// (DigestUtil.sha512Hex → eccEncrypt)。
//
// 链路:升序规范 JSON → sha512 → 128 字符小写 hex 串(这串 ASCII 字符本身就是被加密明文,
// 不再做任何包装)→ ECIES(网关公钥, BC 1.70 默认参数)→ 标准 Base64(带填充,+ 与 /)。
//
// 双变体提醒:签名值走【标准】字母表;Authorization / X-RISK-BASIC 走 URL-safe 带填充,
// 二者不可混用(headers.go 承担后者,golden 测试以两条路径互相证伪)。
//
// 并发安全:Signer 持有的只有不可变的 *ecdh.PublicKey,单实例可被多 goroutine 共享。
// ---------------------------------------------------------------------------

// Signer 用网关公钥产出 X-SIGNATURE。
type Signer struct {
	pub *ecdh.PublicKey
}

// NewSigner 以 P-256 网关公钥构造签名器。公钥在构造期完成校验(nil / 非 P-256 直接拦截),
// 保证 Signature 阶段不再有协议层前置失败面。
func NewSigner(pub *ecdh.PublicKey) (*Signer, error) {
	switch {
	case pub == nil:
		return nil, fmt.Errorf("protocol.NewSigner: %w", errNilReceiverKey)
	case pub.Curve() != eciesCurve:
		return nil, fmt.Errorf("protocol.NewSigner: %w", errNotP256Curve)
	}
	return &Signer{pub: pub}, nil
}

// Signature 计算同步问询/案件查询共用的 X-SIGNATURE。
//
// 入参 sortedJSON 必须是已完成确定序(canonical)序列化的签名字符串 —— 键序、null 省略等
// 规则由 canonjson 负责,本函数不做二次规范化。返回值为标准 Base64 密文字符串。
//
// 设计勘误说明:design.md 契约表写的是 Signature(sortedJSON string) string,
// 这里改为 (string, error)。理由:ECIES 底层存在可失败的随机源(crypto/rand),
// 吞掉错误会静默产出一个无效签名头,把兼容性问题推迟到网关侧才暴露;
// 显式 error 让门面(3.2)与请求管线(2.5/2.6)可以纳入统一错误契约。
func (s *Signer) Signature(sortedJSON string) (string, error) {
	ciphertext, err := Encrypt(s.pub, signaturePlaintext(sortedJSON))
	if err != nil {
		return "", fmt.Errorf("protocol.Signer.Signature: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// signatureWithEphemeral 与 Signature 同一条摘要链与同一套编码,仅临时密钥可注入。
// 供 golden 向量复现 Java 侧"固定 SecureRandom ephemeral 回放"的密文(headers_golden.json
// 的 signatureBase64Std 即以此方式生成,scripts/README §二.2);生产入口是 Signature。
func (s *Signer) signatureWithEphemeral(sortedJSON string, ephemeral *ecdh.PrivateKey) (string, error) {
	ciphertext, err := EncryptWithEphemeral(s.pub, signaturePlaintext(sortedJSON), ephemeral)
	if err != nil {
		return "", fmt.Errorf("protocol.Signer.signatureWithEphemeral: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// PublicKey 返回签名器持有的网关公钥。请求管线(2.5)对敏感字段做 ECIES 加密时
// 必须使用同一把公钥——从 Signer 取而不是再解析一份,保证"签名密钥==加密密钥"
// 这条协议不变量只有一个来源。
func (s *Signer) PublicKey() *ecdh.PublicKey { return s.pub }

// signaturePlaintext 计算 ECIES 实际接收的字节序列:
// sha512(sortedJSON) 后按 encoding/hex 固定小写字母表展开成 128 字符 ASCII 串。
// 与 Java DigestUtil.sha512Hex 一致——hex 小写是协议事实,不是实现偏好。
func signaturePlaintext(sortedJSON string) []byte {
	sum := sha512.Sum512([]byte(sortedJSON))
	return []byte(hex.EncodeToString(sum[:]))
}
