package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// 签名链 golden 验证:testdata/headers_golden.json 的 X-SIGNATURE
//
// 断言策略(要点,勿回退):
//   headers_golden.json 里的 signatureBase64Std 是 Java 侧用固定 ephemeral 生成的,
//   而生产入口 Signature() 走 crypto/rand,每次密文必然不同 → 不可能逐字节复现。
//   因此判据分两层:
//     ① 逐字节层:用 ecies_vectors.json 的 ephemeralReplay.replayPatternHex 构造固定
//        临时私钥,经与生产完全相同的摘要链+编码路径(signatureWithEphemeral)复现密文;
//        golden 密文即以该固定临时私钥生成(scripts/README §二.2)。
//     ② 语义层:对生产随机路径的输出做"独立解密 + MAC 自校验",解出的明文必须等于
//        golden 已锁定的 128 位小写 hex 摘要 —— 不依赖复现 ephemeral 也能锁死内容。
// ---------------------------------------------------------------------------

const (
	goldenSignatureByteLen = 213 // V(65B) ‖ C(128B 小写 hex 明文) ‖ T(20B)
	goldenDigestHexLen     = 128 // sha512 的十六进制小写长度
)

// spkiKeyPair 只取需要的两个键;ecies_vectors.json 其余字段由本文件不关心的结构丢弃。
type spkiKeyPair struct {
	PublicKeySpkiBase64Std string `json:"publicKeySpkiBase64Std"`
	PrivateKeyScalarHex    string `json:"privateKeyScalarHex"`
}

// loadGatewayKeys 从 ecies_vectors.json 取静态网关密钥对:
// 返回按 SPKI(X509/PKIX)解析出的接收方公钥(Signer 持有),以及可解密的静态私钥。
func loadGatewayKeys(t *testing.T) (*ecdh.PublicKey, *ecdh.PrivateKey) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ecies_vectors.json"))
	if err != nil {
		t.Fatalf("读取 ECIES 向量文件失败: %v", err)
	}
	var file struct {
		StaticKeyPair spkiKeyPair `json:"staticKeyPair"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("解析 ECIES 向量文件失败: %v", err)
	}
	return mustParseSPKIP256(t, file.StaticKeyPair.PublicKeySpkiBase64Std),
		mustFixedEphemeral(t, file.StaticKeyPair.PrivateKeyScalarHex)
}

// mustParseSPKIP256 把 Base64(标准字母表)的 SPKI/DER 公钥解析成 P-256 的 crypto/ecdh 公钥。
// 解析顺序与门面 3.1 计划的公钥加载路径一致:x509.ParsePKIXPublicKey → 类型断言 → ecdh 公钥。
func mustParseSPKIP256(t *testing.T, b64 string) *ecdh.PublicKey {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("SPKI Base64 非法: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("解析 PKIX 公钥失败: %v", err)
	}
	switch key := parsed.(type) {
	case *ecdsa.PublicKey:
		// P-256 命名曲线在 stdlib 里以 ecdsa 公钥形态返回;ECDH() 是它转 crypto/ecdh 的官方通道
		pub, err := key.ECDH()
		if err != nil {
			t.Fatalf("ecdsa 公钥转 crypto/ecdh 失败: %v", err)
		}
		return pub
	case *ecdh.PublicKey:
		// 新工具链对部分键型直接返回 crypto/ecdh 公钥(X25519 等);此处兜底接受
		return key
	default:
		t.Fatalf("SPKI 解析结果类型 %T 不是受支持的 P-256 形态", parsed)
		return nil
	}
}

// ---------------------------------------------------------------------------
// 断言①:固定临时私钥下逐字节复现 Java 密文
// ---------------------------------------------------------------------------

func TestSignerSignatureMatchesGoldenCiphertext(t *testing.T) {
	golden := loadGoldenHeaders(t)
	pub, _ := loadGatewayKeys(t)
	replayECDSA := loadGoldenECIES(t).EphemeralReplay.ReplayPatternHex

	signer, err := NewSigner(pub)
	if err != nil {
		t.Fatalf("构造 Signer 失败: %v", err)
	}
	fixedEphemeral := mustFixedEphemeral(t, replayECDSA)

	for i := range golden.Entries {
		entry := golden.Entries[i]
		t.Run(entry.Name, func(t *testing.T) {
			// 与生产 Signature() 同一条摘要链,仅临时密钥注入为回放块(golden 即由此生成)
			gotSig, err := signer.signatureWithEphemeral(entry.SignInputs.SortedSignJson, fixedEphemeral)
			if err != nil {
				t.Fatalf("签名失败: %v", err)
			}

			wantSig := entry.SignatureBase64Std
			if gotSig != wantSig {
				t.Errorf("X-SIGNATURE 逐字节不一致\n got = %s\nwant = %s", gotSig, wantSig)
			}
			// entry 与 signInputs 两处副本也须一致(锁定 golden 文件自身自洽)
			if entry.SignInputs.SignatureBase64Std != wantSig {
				t.Errorf("golden 两份签名副本不一致:%q vs %q", entry.SignInputs.SignatureBase64Std, wantSig)
			}
			if headerSig := entry.Headers["X-SIGNATURE"]; headerSig != wantSig {
				t.Errorf("golden 六头里的 X-SIGNATURE 与顶层不一致:%q vs %q", headerSig, wantSig)
			}

			// 结构定位:总长恒 213,V 段 = 回放块的临时公钥点,T 段 20B 收尾
			decoded, err := base64.StdEncoding.DecodeString(gotSig)
			if err != nil {
				t.Fatalf("X-SIGNATURE 应能按标准字母表解码: %v", err)
			}
			if len(decoded) != goldenSignatureByteLen {
				t.Errorf("X-SIGNATURE 解码长度 = %d,期望 %d(V65+明文128+MAC20)", len(decoded), goldenSignatureByteLen)
			}
			if vPoint := fixedEphemeral.PublicKey().Bytes(); !bytes.Equal(decoded[:len(vPoint)], vPoint) {
				t.Errorf("V 段不是回放块对应的临时公钥点\n got = %s\nwant = %s",
					hex.EncodeToString(decoded[:65]), hex.EncodeToString(vPoint))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 摘要链前半段独立锁定:sha512(sortedJSON) → 全小写 hex、长度 128
// ---------------------------------------------------------------------------

func TestSha512HexLowerChainLockedByGolden(t *testing.T) {
	golden := loadGoldenHeaders(t)
	for _, entry := range golden.Entries {
		entry := entry
		t.Run(entry.Name, func(t *testing.T) {
			sum := sha512.Sum512([]byte(entry.SignInputs.SortedSignJson))
			got := hex.EncodeToString(sum[:]) // encoding/hex 固定产出小写字母表
			if got != entry.SignInputs.Sha512HexLowerOfSignJson {
				t.Errorf("sha512hexlower 不一致\n got = %s\nwant = %s",
					got, entry.SignInputs.Sha512HexLowerOfSignJson)
			}
			if len(got) != goldenDigestHexLen {
				t.Errorf("摘要 hex 长度 = %d,期望 %d", len(got), goldenDigestHexLen)
			}
			for _, r := range got {
				if r >= 'A' && r <= 'Z' {
					t.Fatalf("摘要 hex 出现大写字母(Java 侧要求全小写): %s", got)
				}
			}
			// 这 128 个 ASCII 字符本身就是要被 ECIES 加密的明文,不应再有再包一层 JSON 之类的动作
			if plain := string(signaturePlaintext(entry.SignInputs.SortedSignJson)); plain != got {
				t.Errorf("被加密明文应恰为 128 字符的小写 hex 串本身\n got = %s\nwant = %s", plain, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 断言②:生产随机路径 —— 解密回读 + MAC 自校验锁死明文内容
// ---------------------------------------------------------------------------

func TestProductionSignatureDecryptsBackToGoldenDigest(t *testing.T) {
	golden := loadGoldenHeaders(t)
	pub, priv := loadGatewayKeys(t)

	signer, err := NewSigner(pub)
	if err != nil {
		t.Fatalf("构造 Signer 失败: %v", err)
	}

	for i := range golden.Entries {
		entry := golden.Entries[i]
		t.Run(entry.Name, func(t *testing.T) {
			firstSig, err := signer.Signature(entry.SignInputs.SortedSignJson)
			if err != nil {
				t.Fatalf("生产签名失败: %v", err)
			}
			firstPlain := decryptECIESForTest(t, priv, mustDecodeStdBase64(t, firstSig))
			if string(firstPlain) != entry.SignInputs.Sha512HexLowerOfSignJson {
				t.Errorf("生产签名解密回读 ≠ golden 摘要\n got = %s\nwant = %s",
					firstPlain, entry.SignInputs.Sha512HexLowerOfSignJson)
			}

			secondSig, err := signer.Signature(entry.SignInputs.SortedSignJson)
			if err != nil {
				t.Fatalf("第二次生产签名失败: %v", err)
			}
			if firstSig == secondSig {
				t.Error("同明文两次生产签名输出完全一致,说明 ephemeral 未走 crypto/rand")
			}
			secondPlain := decryptECIESForTest(t, priv, mustDecodeStdBase64(t, secondSig))
			if !bytes.Equal(firstPlain, secondPlain) {
				t.Errorf("两次签名解出的明文不同:\n%s\n%s", firstPlain, secondPlain)
			}
			if len(secondPlain) != goldenDigestHexLen {
				t.Errorf("解出明文长度 = %d,期望 128(hex 字符串本身)", len(secondPlain))
			}
		})
	}
}

// decryptECIESForTest 是测试侧独立实现的 ECIES 解密(接收方视角):
//
//	Z = x(d·V)(发送方算的是 x(r·Ypub),两侧在同一点上相遇)
//	K = KDF2SHA1(V‖Z, 16+len(C)),K[0:16] 为 MAC key、K[16:] 为 keystream(反直觉布局同加密侧)
//	T = HMAC-SHA1(K[0:16], C‖8×0x00) 必须先校验再解出明文 —— MAC 自校验即为兼容性的独立证据。
//
// 若两套实现在任一字节布局上意见相左,这里会立刻红掉。
func decryptECIESForTest(t *testing.T, priv *ecdh.PrivateKey, ciphertext []byte) []byte {
	t.Helper()
	vLen, tagLen := ecIESPointSize, ecIESMACTagSize
	if len(ciphertext) < vLen+tagLen+1 {
		t.Fatalf("密文过短无法解密:len=%d", len(ciphertext))
	}
	v := ciphertext[:vLen]
	c := ciphertext[vLen : len(ciphertext)-tagLen]
	tag := ciphertext[len(ciphertext)-tagLen:]

	point, err := eciesCurve.NewPublicKey(v)
	if err != nil {
		t.Fatalf("V 段不是合法的非压缩 P-256 点: %v", err)
	}
	z, err := priv.ECDH(point)
	if err != nil {
		t.Fatalf("计算共享秘密失败: %v", err)
	}
	shared := append(append([]byte{}, v...), z...)
	keyMaterial, err := KDF2SHA1(shared, ecIESMACKeySize+len(c))
	if err != nil {
		t.Fatalf("KDF2 失败: %v", err)
	}

	mac := hmac.New(sha1.New, keyMaterial[:ecIESMACKeySize])
	mac.Write(c)
	mac.Write(make([]byte, ecIESLengthTagSize))
	if !hmac.Equal(mac.Sum(nil), tag) {
		t.Fatal("MAC 校验失败:密文被改或实现布局不一致")
	}

	plaintext := make([]byte, len(c))
	for i, b := range c {
		plaintext[i] = b ^ keyMaterial[ecIESMACKeySize+i]
	}
	return plaintext
}

// mustDecodeStdBase64 解标准 Base64,失败立即终止测试。
func mustDecodeStdBase64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("标准 Base64 解码失败: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// 错误契约:nil / 异曲线公钥必须在构造期被拦截,不得等到首签才炸
// ---------------------------------------------------------------------------

func TestNewSignerRejectsInvalidPublicKey(t *testing.T) {
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("构造异曲线私钥失败: %v", err)
	}

	cases := []struct {
		name    string
		pub     *ecdh.PublicKey
		wantErr error
	}{
		{name: "nil 接收方公钥", pub: nil, wantErr: errNilReceiverKey},
		{name: "曲线不是 P-256", pub: x25519Priv.PublicKey(), wantErr: errNotP256Curve},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSigner(tc.pub)
			if signer != nil {
				t.Errorf("非法公钥不应产出 Signer 实例")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("错误 = %v,期望包含哨兵 %v", err, tc.wantErr)
			}
		})
	}
}

// 零值 Signer 不应 panic:Signature 走到底层 Encrypt 时会以哨兵报错(纵深防御,
// 正常使用须走 NewSigner 在构造期拦截)。
func TestSignerNilReceiverErrorsInsteadOfPanic(t *testing.T) {
	signer := &Signer{}
	sig, err := signer.Signature("{}")
	if sig != "" {
		t.Errorf("出错时不应返回签名串,实得 %q", sig)
	}
	if !errors.Is(err, errNilReceiverKey) {
		t.Errorf("错误 = %v,期望包含哨兵 %v", err, errNilReceiverKey)
	}
}
