package protocol

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// golden 向量:testdata/ecies_vectors.json(BouncyCastle 1.70 无参 ECIES 默认参数,
// 由 scripts/GenVectors.java 固定 SecureRandom 临时密钥产出,机制见 scripts/README §二)
//
// 兼容判据分两层(见向量文件 _meta.notes):
//   测试层:注入固定临时私钥,密文与 Java 版逐字节一致;
//   生产层:每次 crypto/rand 真随机临时密钥,密文必然不同,由服务端解密+MAC 校验兜底。
// ---------------------------------------------------------------------------

// goldenECIESVector 对应 vectors[] 单条字段,json tag 与生成脚本产出的键名严格一致。
type goldenECIESVector struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	PublicKeyHex     string `json:"publicKeyHex"`          // 静态接收方公钥,65B 非压缩(04 前缀)
	EphemeralDHex    string `json:"ephemeralDHex"`         // 本次加密使用的临时私钥标量(回放块)
	EphemeralPubHex  string `json:"ephemeralPublicKeyHex"` // V = k·G,密文前 65 字节
	PlaintextByteLen int    `json:"plaintextByteLen"`
	PlaintextHex     string `json:"plaintextHex"`
	SharedSecretHex  string `json:"sharedSecretHex"`  // V‖Z(V 在前),Z 左填充定长 32B
	KDFDerivedKeyHex string `json:"kdfDerivedKeyHex"` // KDF2-SHA1 全量输出 16+len(pt) 字节
	MacTagHex        string `json:"macTagHex"`        // HMAC-SHA1(K[:16], C‖8×0x00),20B 不截断
	CipherBase64Std  string `json:"cipherBase64Std"`  // 标准字母表带填充 = Java Base64Util.encodeToString
	CipherHex        string `json:"cipherHex"`        // 与 base64 同一密文的十六进制形态
	ExpectedTotalLen int    `json:"expectedTotalLen"` // 恒为 65 + len(pt) + 20
}

// goldenKDF2Vector 对应 kdf2Vectors[] 单条:KDF2-SHA1 中间值独立断言。
type goldenKDF2Vector struct {
	Name            string `json:"name"`
	SharedSecretHex string `json:"sharedSecretHex"`
	OutLen          int    `json:"outLen"`
	ExpectedKHex    string `json:"expectedKHex"`
}

// goldenStaticKeyPair / goldenEphemeralReplay 用于夹具自洽性校验。
type goldenStaticKeyPair struct {
	Curve                    string `json:"curve"`
	PrivateKeyScalarHex      string `json:"privateKeyScalarHex"`
	PublicKeyUncompressedHex string `json:"publicKeyUncompressedHex"`
}

type goldenEphemeralReplay struct {
	ReplayPatternHex            string `json:"replayPatternHex"`
	ResultingEphemeralScalarHex string `json:"resultingEphemeralScalarHex"`
}

type goldenECIESFile struct {
	StaticKeyPair   goldenStaticKeyPair   `json:"staticKeyPair"`
	EphemeralReplay goldenEphemeralReplay `json:"ephemeralReplay"`
	Vectors         []goldenECIESVector   `json:"vectors"`
	KDF2Vectors     []goldenKDF2Vector    `json:"kdf2Vectors"`
}

// 向量条数守卫:防止 golden 文件被截断或意外扩充后被静默漏测。
const (
	goldenECIESVectorCount = 6
	goldenKDF2VectorCount  = 5
)

func loadGoldenECIES(t *testing.T) goldenECIESFile {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "ecies_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 golden 文件失败: %v", err)
	}
	var parsed goldenECIESFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("解析 golden 文件失败: %v", err)
	}
	if len(parsed.Vectors) != goldenECIESVectorCount {
		t.Fatalf("ECIES golden 向量应为 %d 条,实得 %d(文件可能被截断或重复)", goldenECIESVectorCount, len(parsed.Vectors))
	}
	if len(parsed.KDF2Vectors) != goldenKDF2VectorCount {
		t.Fatalf("KDF2 golden 向量应为 %d 条,实得 %d(文件可能被截断或重复)", goldenKDF2VectorCount, len(parsed.KDF2Vectors))
	}
	seen := map[string]bool{}
	for _, v := range parsed.Vectors {
		if v.Name == "" || seen[v.Name] {
			t.Fatalf("ECIES 向量名缺失或重复: %q", v.Name)
		}
		seen[v.Name] = true
	}
	for _, v := range parsed.KDF2Vectors {
		if v.Name == "" || seen["kdf:"+v.Name] {
			t.Fatalf("KDF2 向量名缺失或重复: %q", v.Name)
		}
		seen["kdf:"+v.Name] = true
	}
	return parsed
}

// mustParseP256Point 把非压缩 65B 公钥点解析成 crypto/ecdh 公钥(测试夹具用)。
func mustParseP256Point(t *testing.T, hexStr string) *ecdh.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("公钥 hex 非法: %v", err)
	}
	pub, err := eciesCurve.NewPublicKey(raw)
	if err != nil {
		t.Fatalf("解析 P-256 非压缩公钥失败: %v", err)
	}
	return pub
}

// mustFixedEphemeral 用固定 32B 标量构造临时私钥(复现 BC 回放机制)。
func mustFixedEphemeral(t *testing.T, hexStr string) *ecdh.PrivateKey {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("临时私钥 hex 非法: %v", err)
	}
	d, err := eciesCurve.NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("构造固定临时私钥失败: %v", err)
	}
	return d
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex 解码失败: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// 核心判定测试:golden 六条向量逐字节一致(任务 5.2 的验收面)
// ---------------------------------------------------------------------------

func TestEncryptWithEphemeralMatchesGoldenVectors(t *testing.T) {
	golden := loadGoldenECIES(t)
	for _, tc := range golden.Vectors {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustParseP256Point(t, tc.PublicKeyHex)
			eph := mustFixedEphemeral(t, tc.EphemeralDHex)

			got, err := EncryptWithEphemeral(pub, mustHexDecode(t, tc.PlaintextHex), eph)
			if err != nil {
				t.Fatalf("加密失败: %v", err)
			}

			// 1) 总长恒为 65 + len(pt) + 20(空串即 85 的边界也在此覆盖)
			if len(got) != tc.ExpectedTotalLen {
				t.Errorf("密文长度 = %d,期望 %d(65+V + %d+C + 20+T)", len(got), tc.ExpectedTotalLen, tc.PlaintextByteLen)
			}

			// 2) 密文逐字节(hex 形态)对照 —— 本任务的硬判据
			wantCipher := strings.ToLower(tc.CipherHex)
			if gotHex := hex.EncodeToString(got); gotHex != wantCipher {
				t.Errorf("密文逐字节不一致\n got = %s\nwant = %s", gotHex, wantCipher)
			}

			// 3) 标准 Base64 带填充形态(Java Base64Util.encodeToString 同款变体)
			wantB64 := tc.CipherBase64Std
			if gotB64 := base64.StdEncoding.EncodeToString(got); gotB64 != wantB64 {
				t.Errorf("标准 Base64 密文不一致\n got = %s\nwant = %s", gotB64, wantB64)
			}

			// 4) 分段定位:V 段(前 65B)= Java 侧临时公钥点
			if len(got) >= 65 {
				if gotV := hex.EncodeToString(got[:65]); gotV != strings.ToLower(tc.EphemeralPubHex) {
					t.Errorf("V 段不一致\n got = %s\nwant = %s", gotV, strings.ToLower(tc.EphemeralPubHex))
				}
			}

			// 5) 分段定位:C 段与 T 段(HMAC 尾部 20B 不截断)
			pt := mustHexDecode(t, tc.PlaintextHex)
			if want := strings.ToLower(tc.MacTagHex); len(got) >= 85 {
				if gotT := hex.EncodeToString(got[len(got)-20:]); gotT != want {
					t.Errorf("T 段(HMAC)不一致\n got = %s\nwant = %s", gotT, want)
				}
			}

			// 6) 中间值自证:V = Go ECDH 侧临时公钥点,Z = x(k·Y) 32B,shared = V‖Z 与 golden 一致
			shared := append(append([]byte{}, eph.PublicKey().Bytes()...), ephemeralSecretZ(t, eph, pub)...)
			if gotShared := hex.EncodeToString(shared); gotShared != strings.ToLower(tc.SharedSecretHex) {
				t.Errorf("共享密钥串 V‖Z 不一致\n got = %s\nwant = %s", gotShared, strings.ToLower(tc.SharedSecretHex))
			}

			// 7) 中间值自证:K = KDF2-SHA1(shared, 16+len(pt)),与 golden 全量一致
			k, err := KDF2SHA1(shared, 16+len(pt))
			if err != nil {
				t.Fatalf("KDF2 失败: %v", err)
			}
			if gotK := hex.EncodeToString(k); gotK != strings.ToLower(tc.KDFDerivedKeyHex) {
				t.Errorf("KDF2 输出不一致\n got = %s\nwant = %s", gotK, strings.ToLower(tc.KDFDerivedKeyHex))
			}
		})
	}
}

// ephemeralSecretZ 只是测试可读性包装:取 ECDH 共享秘密 Z,并在异常时立即失败。
func ephemeralSecretZ(t *testing.T, eph *ecdh.PrivateKey, pub *ecdh.PublicKey) []byte {
	t.Helper()
	z, err := eph.ECDH(pub)
	if err != nil {
		t.Fatalf("ECDH 失败: %v", err)
	}
	return z
}

// ---------------------------------------------------------------------------
// KDF2-SHA1 中间值独立断言(block_i = SHA1(shared‖be32(i)),i 从 1 起)
// ---------------------------------------------------------------------------

func TestKDF2SHA1MatchesGoldenVectors(t *testing.T) {
	golden := loadGoldenECIES(t)
	for _, tc := range golden.KDF2Vectors {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			got, err := KDF2SHA1(mustHexDecode(t, tc.SharedSecretHex), tc.OutLen)
			if err != nil {
				t.Fatalf("KDF2SHA1 失败: %v", err)
			}
			if len(got) != tc.OutLen {
				t.Fatalf("KDF2 输出长度 = %d,期望 %d", len(got), tc.OutLen)
			}
			if want := strings.ToLower(tc.ExpectedKHex); hex.EncodeToString(got) != want {
				t.Errorf("KDF2 输出不一致(outLen=%d)\n got = %s\nwant = %s", tc.OutLen, hex.EncodeToString(got), want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 生产语义路径(crypto/rand 真 ephemeral)
// ---------------------------------------------------------------------------

// 空明文边界:密文恒 65+0+20=85 字节,keystream 为空段,tag 只对 8×0x00 计算。
func TestEncryptEmptyPlaintextIsExactly85Bytes(t *testing.T) {
	golden := loadGoldenECIES(t)
	vec := golden.Vectors[0]
	if vec.PlaintextByteLen != 0 || vec.ExpectedTotalLen != 85 {
		t.Fatalf("首条 golden 应为空明文/85B 夹具,实得 %q(len=%d)", vec.Name, vec.ExpectedTotalLen)
	}
	pub := mustParseP256Point(t, vec.PublicKeyHex)
	got, err := Encrypt(pub, []byte{})
	if err != nil {
		t.Fatalf("空明文加密失败: %v", err)
	}
	if len(got) != 85 {
		t.Errorf("空明文密文长度 = %d,期望 85", len(got))
	}
	if got[0] != 0x04 {
		t.Errorf("密文首字节 = %#x,期望非压缩点前缀 0x04", got[0])
	}
}

// 随机性健全性:同明文两次加密必须产生不同密文(ECIES 的 ephemeral 随机性),
// 同时两次输出的 V 都必须是合法非压缩点长度形态。
func TestEncryptRandomEphemeralYieldsDistinctCiphertexts(t *testing.T) {
	golden := loadGoldenECIES(t)
	vec := golden.Vectors[1] // short_ascii_test_token
	pub := mustParseP256Point(t, vec.PublicKeyHex)
	pt := mustHexDecode(t, vec.PlaintextHex)

	first, err := Encrypt(pub, pt)
	if err != nil {
		t.Fatalf("第一次加密失败: %v", err)
	}
	second, err := Encrypt(pub, pt)
	if err != nil {
		t.Fatalf("第二次加密失败: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Error("同一明文两次加密得到完全相同的密文,说明 ephemeral 未走 crypto/rand")
	}
	if len(first) != vec.ExpectedTotalLen || len(second) != vec.ExpectedTotalLen {
		t.Errorf("随机路径密文长度 = %d/%d,期望 %d", len(first), len(second), vec.ExpectedTotalLen)
	}
	// V 段不同 ⇒ ephemeral 不同(这才是随机性的直接证据)
	if bytes.Equal(first[:65], second[:65]) {
		t.Error("两次加密的 V 段(临时公钥点)相同,ephemeral 未随机会话变化")
	}
}

// ---------------------------------------------------------------------------
// 错误契约:统一包装局部哨兵(errors.Is 可判)
// ---------------------------------------------------------------------------

func TestEncryptRejectsInvalidInputs(t *testing.T) {
	golden := loadGoldenECIES(t)
	vec := golden.Vectors[1]
	pub := mustParseP256Point(t, vec.PublicKeyHex)
	x25519, err := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if err != nil {
		t.Fatalf("构造异曲线私钥失败: %v", err)
	}

	cases := []struct {
		name    string
		call    func() ([]byte, error)
		wantErr error
	}{
		{
			name:    "nil 接收方公钥",
			call:    func() ([]byte, error) { return Encrypt(nil, []byte("x")) },
			wantErr: errNilReceiverKey,
		},
		{
			name:    "曲线不是 P-256",
			call:    func() ([]byte, error) { return Encrypt(x25519.PublicKey(), []byte("x")) },
			wantErr: errNotP256Curve,
		},
		{
			name:    "nil 临时私钥",
			call:    func() ([]byte, error) { return EncryptWithEphemeral(pub, []byte("x"), nil) },
			wantErr: errNilEphemeralKey,
		},
		{
			name:    "异曲线临时私钥",
			call:    func() ([]byte, error) { return EncryptWithEphemeral(pub, []byte("x"), x25519) },
			wantErr: errNotP256Curve,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			out, err := c.call()
			if out != nil {
				t.Errorf("出错时不应返回密文,实得 %dB", len(out))
			}
			if !errors.Is(err, c.wantErr) {
				t.Errorf("错误 = %v,期望包含哨兵 %v", err, c.wantErr)
			}
		})
	}
}

// KDF2 参数校验:负长度必须报错而非越界写。
func TestKDF2SHA1RejectsNegativeLength(t *testing.T) {
	out, err := KDF2SHA1([]byte{0x01}, -1)
	if out != nil || !errors.Is(err, errInvalidKDFOutLen) {
		t.Errorf("KDF2SHA1 负长度: out=%v err=%v,期望 nil 与哨兵 errInvalidKDFOutLen", out, errInvalidKDFOutLen)
	}
}

// ---------------------------------------------------------------------------
// 夹具自洽性:golden 静态密钥对与回放块应能被 Go 侧 ecdh 还原成同一公钥点
// (任何一侧理解偏差都会在这里暴露,而不必等到密文比对失败再排查)
// ---------------------------------------------------------------------------

func TestGoldenFixturesAreSelfConsistent(t *testing.T) {
	golden := loadGoldenECIES(t)
	static := mustFixedEphemeral(t, golden.StaticKeyPair.PrivateKeyScalarHex)
	if got := hex.EncodeToString(static.PublicKey().Bytes()); got != strings.ToLower(golden.StaticKeyPair.PublicKeyUncompressedHex) {
		t.Errorf("静态私钥反推公钥不一致\n got = %s\nwant = %s", got, strings.ToLower(golden.StaticKeyPair.PublicKeyUncompressedHex))
	}
	replay := golden.EphemeralReplay.ReplayPatternHex
	if replay != golden.EphemeralReplay.ResultingEphemeralScalarHex {
		t.Fatalf("回放块应等于产生的临时标量: %q vs %q", replay, golden.EphemeralReplay.ResultingEphemeralScalarHex)
	}
	for _, v := range golden.Vectors {
		if v.EphemeralDHex != replay {
			t.Errorf("向量 %q 的临时标量应等于回放块 %q,实得 %q", v.Name, replay, v.EphemeralDHex)
		}
	}
}
