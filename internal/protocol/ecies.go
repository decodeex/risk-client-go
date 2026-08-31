package protocol

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// ECIES(BouncyCastle 1.70 无参默认参数)加密 —— 与 Java 版 risk-client 逐字节兼容。
//
// BC 侧形态(Cipher.getInstance("ECIES","BC") + IESParameterSpec(null,null,128)):
//   V   = 0x04 ‖ X ‖ Y(65B 非压缩点)= r·G
//   Z   = x(r·Y) 左填充定长 32B(ECDHBasicAgreement 的 asUnsignedByteArray(32, z))
//   shared = V ‖ Z(V 在前!)
//   K   = KDF2-SHA1(shared, 16+len(pt)),block_i = SHA1(shared ‖ be32(i)),i 从 1 起
//   反直觉布局:K[0:16] = HMAC-SHA1 的 MAC key,K[16:] = XOR keystream
//   C   = pt ⊕ K[16:]      (无分组密码,流式)
//   T   = HMAC-SHA1(K[0:16], C ‖ 8×0x00)(P2=null 时 IESEngine 补的长度标签,20B 不截断)
//   输出 = V ‖ C ‖ T
//
// 真值来源:testdata/ecies_vectors.json(scripts/GenVectors.java 固定 ephemeral 回放生成),
// 兼容判据分两层——测试层注入固定临时私钥逐字节比对;生产层走 crypto/rand,由服务端解密+MAC 兜底。
// ---------------------------------------------------------------------------

// 协议常数。SHA-1/HMAC-SHA1/KDF2 是对齐网关的协议兼容约束,并非本 SDK 的安全选型。
const (
	ecIESMACKeySize    = 16                 // macKeySize=128bit(BC 默认)
	ecIESMACTagSize    = sha1.Size          // 20B,HMAC-SHA1 不截断
	ecIESLengthTagSize = 8                  // MAC 输入尾接的长度标签字节数(P2=null)
	ecIESPointSize     = 65                 // 非压缩 P-256 点:0x04 ‖ X(32B) ‖ Y(32B)
	ecIESMaxKDFBlocks  = uint64(^uint32(0)) // KDF2 计数器为 be32,理论上限即块数上限
)

// eciesCurve 是协议固定的曲线(secp256r1 / P-256 / prime256v1)。
// 注:crypto/ecdh.Curve 两次调用 P256() 返回可比较的等值结构,== 判等可靠(已实测)。
var eciesCurve = ecdh.P256()

// 局部哨兵(errors.Is 可判)。尚未纳入根包错误契约,待首个调用方接入时统一定版。
var (
	errNilReceiverKey   = errors.New("接收方公钥为空")
	errNilEphemeralKey  = errors.New("临时私钥为空")
	errNotP256Curve     = errors.New("仅支持 P-256 曲线")
	errInvalidKDFOutLen = errors.New("KDF2 输出长度非法")
)

// Encrypt 用一次性随机临时密钥对明文做 BC 1.70 默认参数 ECIES 加密(生产语义):
// 每次调用 crypto/rand 重抽 ephemeral,密文必然不同(ECIES 本就是随机化加密,
// Java 版同明文两次加密输出亦不同),服务端按解密 + MAC 校验判定兼容性。
func Encrypt(pub *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("protocol.Encrypt: %w", errNilReceiverKey)
	}
	ephemeral, err := eciesCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("protocol.Encrypt: 生成临时密钥失败: %w", err)
	}
	return EncryptWithEphemeral(pub, plaintext, ephemeral)
}

// EncryptWithEphemeral 以调用方注入的固定临时私钥完成同一套加密流程。
// 仅在 internal 包内使用(供 golden 向量复现 Java 侧回放密文);生产入口是 Encrypt。
func EncryptWithEphemeral(pub *ecdh.PublicKey, plaintext []byte, ephemeral *ecdh.PrivateKey) ([]byte, error) {
	switch {
	case pub == nil:
		return nil, fmt.Errorf("protocol.EncryptWithEphemeral: %w", errNilReceiverKey)
	case ephemeral == nil:
		return nil, fmt.Errorf("protocol.EncryptWithEphemeral: %w", errNilEphemeralKey)
	case pub.Curve() != eciesCurve || ephemeral.Curve() != eciesCurve:
		return nil, fmt.Errorf("protocol.EncryptWithEphemeral: %w", errNotP256Curve)
	}

	// V = 0x04‖X‖Y(crypto/ecdh 的 PublicKey.Bytes() 恰为 65B 非压缩点)
	v := ephemeral.PublicKey().Bytes()
	if len(v) != ecIESPointSize {
		// 理论不可达(上方曲线判等已保证);密文前 65B 是服务端解密的定位基准,这里加一道协议防线。
		return nil, fmt.Errorf("protocol.EncryptWithEphemeral: 非压缩点长度异常 %d,期望 %d", len(v), ecIESPointSize)
	}

	// Z = x(r·Y):crypto/ecdh 的 ECDH() 恒返回 32B 定长 x 坐标(左填充语义已内建)
	z, err := ephemeral.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("protocol.EncryptWithEphemeral: 计算 ECDH 共享秘密失败: %w", err)
	}

	shared := make([]byte, 0, len(v)+len(z))
	shared = append(shared, v...)
	shared = append(shared, z...)

	derived, err := KDF2SHA1(shared, ecIESMACKeySize+len(plaintext))
	if err != nil {
		return nil, fmt.Errorf("protocol.EncryptWithEphemeral: 派生密钥失败: %w", err)
	}

	// C = pt ⊕ K[16:](keystream 长度恰等于 len(pt))
	ciphertext := make([]byte, len(plaintext))
	for i, b := range plaintext {
		ciphertext[i] = b ^ derived[ecIESMACKeySize+i]
	}

	// T = HMAC-SHA1(K[:16], C ‖ 8×0x00)
	mac := hmac.New(sha1.New, derived[:ecIESMACKeySize])
	mac.Write(ciphertext)
	mac.Write(make([]byte, ecIESLengthTagSize))
	tag := mac.Sum(nil)

	out := make([]byte, 0, len(v)+len(ciphertext)+len(tag))
	out = append(out, v...)
	out = append(out, ciphertext...)
	return append(out, tag...), nil
}

// KDF2SHA1 按 bcprov KDF2BytesGenerator(SHA-1, counterStart=1) 派生密钥材料:
// block_i = SHA1(secret ‖ be32(i)),i 从 1 起,顺次拼接后截取 outLen 字节。
// secret 即上文的 shared = V‖Z。
func KDF2SHA1(secret []byte, outLen int) ([]byte, error) {
	if outLen < 0 || uint64(outLen) > ecIESMaxKDFBlocks*sha1.Size {
		return nil, fmt.Errorf("protocol.KDF2SHA1: %w: outLen=%d", errInvalidKDFOutLen, outLen)
	}
	if outLen == 0 {
		return []byte{}, nil
	}
	var counter [4]byte // be32 计数器,i 从 1 起(bcprov BaseKDFBytesGenerator.counterStart=1)
	binary.BigEndian.PutUint32(counter[:], 1)

	out := make([]byte, 0, outLen+sha1.Size)
	h := sha1.New()
	for len(out) < outLen {
		h.Reset()
		h.Write(secret)
		h.Write(counter[:])
		out = h.Sum(out)
		binary.BigEndian.PutUint32(counter[:], binary.BigEndian.Uint32(counter[:])+1)
	}
	return out[:outLen], nil
}
