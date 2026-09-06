package riskclient

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decodeex/risk-client-go/internal/protocol"
)

// ---------------------------------------------------------------------------
// 集成测试:httptest 假网关。服务端以「网关视角」只凭线上报文重建签名输入,
// 再用 golden 静态私钥解密 X-SIGNATURE 做闭环比对 —— 即 Req 5.3 的可验证性要求。
// ---------------------------------------------------------------------------

type capturedRequest struct {
	rawHeader http.Header // 经 net/http 读出的 MIME 规范化键(值不变形)
	body      []byte
	path      string
}

// loadStaticPrivKey 从 golden PKCS8 解出静态接收方私钥(解密 X-SIGNATURE 用)。
func loadStaticPrivKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile("testdata/ecies_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		StaticKeyPair struct {
			PrivateKeyPkcs8Base64Std string `json:"privateKeyPkcs8Base64Std"`
		} `json:"staticKeyPair"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(doc.StaticKeyPair.PrivateKeyPkcs8Base64Std)
	if err != nil {
		t.Fatal(err)
	}
	keyAny, perr := x509.ParsePKCS8PrivateKey(der)
	if perr != nil {
		t.Fatal(perr)
	}
	ecdsaPriv, ok8 := keyAny.(*ecdsa.PrivateKey)
	if !ok8 {
		t.Fatalf("PKCS8 非 ECDSA 私钥形态:%T", keyAny)
	}
	dBytes := ecdsaPriv.D.FillBytes(make([]byte, 32))
	priv, cerr := ecdh.P256().NewPrivateKey(dBytes)
	if cerr != nil {
		t.Fatal(cerr)
	}
	return priv
}

// decryptECIES 独立实现解密(Z=x(d·V) → KDF2 → MAC 校验 → XOR 还原),仅测试用。
func decryptECIES(t *testing.T, priv *ecdh.PrivateKey, ct []byte) []byte {
	t.Helper()
	if len(ct) < 65+20 {
		t.Fatalf("密文过短:%d", len(ct))
	}
	V, C, T := ct[:65], ct[65:len(ct)-20], ct[len(ct)-20:]
	pubPoint, err := ecdh.P256().NewPublicKey(V)
	if err != nil {
		t.Fatalf("V 不是合法 P-256 点:%v", err)
	}
	Z, eerr := priv.ECDH(pubPoint)
	if eerr != nil {
		t.Fatalf("ECDH 失败:%v", eerr)
	}
	shared := make([]byte, 0, 65+32)
	shared = append(shared, V...)
	shared = append(shared, Z...)
	K := kdf2SHA1ForTest(shared, len(C)+16)
	macKey := K[:16]
	tag := hmacSHA1ForTest(macKey, append(append([]byte{}, C...), make([]byte, 8)...))
	if string(tag) != string(T) {
		t.Fatalf("MAC 校验失败(密文与静态私钥不符)")
	}
	pt := make([]byte, len(C))
	for i := range C {
		pt[i] = C[i] ^ K[16+i]
	}
	return pt
}

// kdf2SHA1ForTest / hmacSHA1ForTest 是 protocol 内部算法的本地镜像(测试独立实现,
// 刻意不复用生产代码,保证解密路径的独立性)。
func kdf2SHA1ForTest(shared []byte, outLen int) []byte {
	out := make([]byte, 0, outLen)
	for counter := 1; len(out) < outLen; counter++ {
		blockIn := append(append([]byte{}, shared...),
			byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))
		sum := sha1.Sum(blockIn)
		out = append(out, sum[:]...)
	}
	return out[:outLen]
}

func hmacSHA1ForTest(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// TestRiskIntegrationGatewayViewClosedLoop 全链路:真实 HTTP 往返 + 网关视角验签闭环。
func TestRiskIntegrationGatewayViewClosedLoop(t *testing.T) {
	oldNow := nowMillisFn
	fixedTime := int64(1756272000000)
	nowMillisFn = func() int64 { return fixedTime }
	defer func() { nowMillisFn = oldNow }()

	staticPriv := loadStaticPrivKey(t)
	spkiB64, _ := fixturePublicKey(t)

	var captured atomic.Pointer[capturedRequest]
	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedReq := &capturedRequest{rawHeader: r.Header.Clone(), path: r.URL.Path}
		capturedReq.body, _ = io.ReadAll(r.Body)
		captured.Store(capturedReq)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":"200","msg":"","data":{"riskId":"R-9001","strategy":"accept","data":{"score":7}}}`)
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	traces := 0
	cli, err := New(Config{
		BaseURL: srv.URL, ClientID: "it-client", ClientSecret: "s3cret#2026",
		PublicKey: spkiB64, EventTimeoutMs: map[string]int64{"login": 3000},
		LogDetail: true,
	},
		WithRequestIP("10.10.5.74"),
		WithTraceIDFunc(func() (string, error) {
			traces++
			return "fixed-trace-0001", nil
		}))
	if err != nil {
		t.Fatal(err)
	}

	resp, rerr := cli.Risk(context.Background(), BasicParam{
		BizID: "IT-BIZ-1", Platform: "APP", EventType: "login",
		BizTime: fixedTime - 1000,
	}, map[string]any{"amount": "99", "mobile": "13800000000"}, []string{"mobile"})
	if rerr != nil {
		t.Fatalf("Risk 不应产生本地 error:%v", rerr)
	}
	if !resp.IsSuccess() || resp.Data.Strategy != "accept" || resp.Data.RiskID != "R-9001" {
		t.Fatalf("成功往返不符:%+v", resp)
	}

	capReq := captured.Load()
	if capReq == nil {
		t.Fatal("请求未被捕获")
	}
	// ① 路径与六头存在性
	if capReq.path != "/risk-engine/risk/login" {
		t.Fatalf("路径不符:%s", capReq.path)
	}
	wantVals := map[string]string{
		"Content-Type": "application/json",
		"X-Risk-Mode":  "sync", // 服务端读出为规范化键;原拼写已在 headers 单测锁定
		"X-User-Id":    "UNKNOWN",
	}
	for k, want := range wantVals {
		val := firstHeaderValue(t, capReq.rawHeader, k)
		if val != want {
			t.Fatalf("%s=%q,want %q", k, val, want)
		}
	}
	authVal := firstHeaderValue(t, capReq.rawHeader, "Authorization")
	wantAuth := "Basic " + base64.URLEncoding.EncodeToString([]byte("it-client:s3cret#2026"))
	if authVal != wantAuth {
		t.Fatalf("Authorization 不符:\n got  = %s\n want = %s", authVal, wantAuth)
	}

	// ② 网关视角闭环:X-RISK-BASIC 明文 + body + 已知入参重建合并集 → 摘要;
	//    解密 X-SIGNATURE 与之逐字节比对。
	riskBasicPlain, err := base64.URLEncoding.DecodeString(firstHeaderValue(t, capReq.rawHeader, "X-Risk-Basic"))
	if err != nil {
		t.Fatalf("X-RISK-BASIC 应为 URL-safe 可解码:%v", err)
	}
	var headerFields map[string]any
	if json.Unmarshal(riskBasicPlain, &headerFields) != nil {
		t.Fatalf("X-RISK-BASIC 明文应合法 JSON:%s", riskBasicPlain)
	}
	var bodyFields map[string]any
	if json.Unmarshal(capReq.body, &bodyFields) != nil {
		t.Fatalf("body 应合法 JSON:%s", capReq.body)
	}

	rebuild := map[string]any{}
	// 协议基础字段从 X-RISK-BASIC 反推(userId 为缺省补齐值,直接采信线上形态)
	for _, k := range []string{"bizId", "userId", "platform", "eventType", "fingerToken", "ip",
		"bizTime", "tenantId", "siteType"} {
		if v, ok := headerFields[k]; ok {
			rebuild[k] = v
		}
	}
	// 注入五键从 X-RISK-BASIC 反推(requestTime 保持数值)
	for _, k := range []string{"traceId", "requestIp", "clientVersion", "clientId"} {
		if v, ok := headerFields[k]; ok {
			rebuild[k] = v
		}
	}
	if v, ok := headerFields["requestTime"]; ok {
		rebuild["requestTime"] = int64(v.(float64))
	}
	// 业务键取自 body(敏感字段此时已是密文,与签名时的 merged 一致)
	for k, v := range bodyFields {
		rebuild[k] = v
	}

	expectedSorted, mErr := protocol.Marshal(rebuild)
	if mErr != nil {
		t.Fatal(mErr)
	}
	digest := sha512.Sum512(expectedSorted)
	expectPlain := []byte(hex.EncodeToString(digest[:]))

	sigVal := firstHeaderValue(t, capReq.rawHeader, "X-Signature")
	ct, decErr := base64.StdEncoding.DecodeString(sigVal)
	if decErr != nil {
		t.Fatalf("X-SIGNATURE 应为标准 Base64:%v", decErr)
	}
	gotPlain := decryptECIES(t, staticPriv, ct)
	if string(gotPlain) != string(expectPlain) {
		t.Fatalf("闭环失败:\n 解得明文   = %s\n 期望摘要(hex)= %s\n (sorted=%s)",
			gotPlain, expectPlain, expectedSorted)
	}

	// mobile 必须在 body 里以密文出现且不同于明文
	if gotMobile, _ := bodyFields["mobile"].(string); gotMobile == "" || gotMobile == "13800000000" {
		t.Fatalf("敏感字段应以密文出现在 body:%v", bodyFields["mobile"])
	}
}

// TestQueryAuditCaseIntegrationForms 覆盖案件查询的成功/业务失败/HTTP401 三条映射。
func TestQueryAuditCaseIntegrationForms(t *testing.T) {
	spkiB64, _ := fixturePublicKey(t)
	mkSrv := func(body string, status int) (*Client, func()) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}))
		cli, err := New(Config{BaseURL: srv.URL, ClientID: "c", ClientSecret: "s",
			PublicKey: spkiB64, EventTimeoutMs: map[string]int64{"kyb": 2000}})
		if err != nil {
			t.Fatal(err)
		}
		return cli, srv.Close
	}

	cli, close1 := mkSrv(`{"success":true,"code":200,"msg":"","data":{"caseNo":"C-1","eventType":"kyb","riskId":"r","bizId":"b","auditResult":"accept","auditTime":1756272000000,"auditUser":"a001","remark":"ok"}}`, http.StatusOK)
	defer close1()
	resp, err := cli.QueryAuditCase(context.Background(), "kyb", "b-1")
	if err != nil || !resp.IsSuccess() || resp.Data.CaseNo != "C-1" || resp.Data.AuditResult != "accept" {
		t.Fatalf("成功样例不符:(%+v,%v)", resp, err)
	}

	cli2, close2 := mkSrv(`{"success":false,"code":30001,"msg":"案件不存在"}`, http.StatusOK)
	defer close2()
	fail, err := cli2.QueryAuditCase(context.Background(), "kyb", "none")
	if err != nil {
		t.Fatal(err)
	}
	if fail.IsSuccess() || fail.Code != 30001 || fail.Msg != "案件不存在" {
		t.Fatalf("业务失败透传不符:%+v", fail)
	}

	cli3, close3 := mkSrv(`denied`, http.StatusUnauthorized)
	defer close3()
	unauth, err := cli3.QueryAuditCase(context.Background(), "kyb", "b")
	if err != nil {
		t.Fatal(err)
	}
	if unauth.Success || unauth.Code != 401 || unauth.Msg != "请求未授权，请先登录" {
		t.Fatalf("401 映射不符:%+v", unauth)
	}
}

// TestRiskTimeoutAndNoNetworkBranches 锁定三类不发网分支 + 超时结构化返回。
func TestRiskTimeoutAndNoNetworkBranches(t *testing.T) {
	spkiB64, _ := fixturePublicKey(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		time.Sleep(400 * time.Millisecond) // 大于 login 的 100ms 超时
		fmt.Fprint(w, `{"code":"200"}`)
	}))
	defer srv.Close()

	cfg := Config{BaseURL: srv.URL, ClientID: "c", ClientSecret: "s", PublicKey: spkiB64,
		EventTimeoutMs: map[string]int64{"login": 100}}
	cli, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// a) 缺事件超时:ErrConfig 且零网络
	_, nerr := cli.Risk(context.Background(), BasicParam{BizID: "b", EventType: "unknown"},
		nil, nil)
	if !errors.Is(nerr, protocol.ErrConfig) || hits != 0 {
		t.Fatalf("缺超时应 ErrConfig 且不发网:%v hits=%d", nerr, hits)
	}
	// b) 必填缺失:ErrParam 且零网络
	_, perr := cli.Risk(context.Background(), BasicParam{EventType: "login"}, nil, nil)
	if !errors.Is(perr, protocol.ErrParam) || hits != 0 {
		t.Fatalf("缺 bizId 应 ErrParam 且不发网:%v", perr)
	}
	// c) 保留字段:ErrReservedField 且零网络
	_, rerr := cli.Risk(context.Background(), BasicParam{BizID: "b", EventType: "login"},
		map[string]any{"traceId": "hack"}, nil)
	if !errors.Is(rerr, protocol.ErrReservedField) || hits != 0 {
		t.Fatalf("保留字段应 ErrReservedField 且不发网:%v", rerr)
	}
	// d) 超时:408 结构化,error==nil,进程存活
	resp, terr := cli.Risk(context.Background(), BasicParam{BizID: "b", EventType: "login"},
		map[string]any{"amount": "1"}, nil)
	if terr != nil {
		t.Fatalf("超时不应产生本地 error:%v", terr)
	}
	if resp.IsSuccess() || resp.Code != "408" || resp.Msg != timeoutMsgRisk {
		t.Fatalf("超时应为 408/原文案:%+v", resp)
	}
}

// firstHeaderValue 取首个值;缺失直接判失败(缺头即协议违约)。
func firstHeaderValue(t *testing.T, h http.Header, name string) string {
	t.Helper()
	vs, ok := h[http.CanonicalHeaderKey(name)]
	if !ok || len(vs) == 0 {
		t.Fatalf("缺少头 %q(收到的键=%v)", name, headerKeys(h))
	}
	return vs[0]
}

func headerKeys(h http.Header) []string {
	ks := make([]string, 0, len(h))
	for k := range h {
		ks = append(ks, k)
	}
	return ks
}
