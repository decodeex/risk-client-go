package riskclient

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/decodeex/bifu-risk-sdk/internal/protocol"
)

// ---------------------------------------------------------------------------
// 5.2 并发与性能验证:SDK 侧单次调用开销(不含网络往返)。
// 口径:Build 管线(默认值/注入/敏感加密/规范 JSON/ECIES 签名链)+ 双形态解析,
// 即除 HTTP 传输外 SDK 全部 CPU 工作。design.md Performance 预算 <1ms/次。
// ---------------------------------------------------------------------------

func benchFixture(b *testing.B) (*Client, BasicParam) {
	raw, err := os.ReadFile("testdata/ecies_vectors.json")
	if err != nil {
		b.Fatal(err)
	}
	var doc struct {
		StaticKeyPair struct {
			PublicKeySpkiBase64Std string `json:"publicKeySpkiBase64Std"`
		} `json:"staticKeyPair"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		b.Fatal(err)
	}
	cfg := Config{
		BaseURL: "http://127.0.0.1:1", ClientID: "bench", ClientSecret: "bench",
		PublicKey:      doc.StaticKeyPair.PublicKeySpkiBase64Std,
		EventTimeoutMs: map[string]int64{"login": 100},
	}.applyDefaults()
	pub, perr := parsePublicKey(cfg.PublicKey)
	if perr != nil {
		b.Fatal(perr)
	}
	signer, serr := protocol.NewSigner(pub)
	if serr != nil {
		b.Fatal(serr)
	}
	c := &Client{cfg: cfg, signer: signer, logger: discardLogger{}}
	p := BasicParam{BizID: "B-9001", UserID: "u-01", Platform: "APP",
		EventType: "login", BizTime: 1756272000000}
	return c, p
}

type discardLogger struct{}

func (discardLogger) Debugf(string, ...any) {}
func (discardLogger) Infof(string, ...any)  {}
func (discardLogger) Warnf(string, ...any)  {}
func (discardLogger) Errorf(string, ...any) {}

// BenchmarkRiskPipeline 除网络外的单次问询全链路成本。
func BenchmarkRiskPipeline(b *testing.B) {
	c, p := benchFixture(b)
	sys := protocol.SystemFields{
		RequestTime:   1756272000000,
		TraceID:       "3fa85f64-5717-4562-b3fc-2c963f66afa6",
		ClientID:      "bench",
		ClientVersion: protocol.DefaultClientVersion,
		RequestIP:     "10.10.5.74",
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outcome := runPipelineForBench(ctx, c, p, sys)
		_ = outcome
	}
}

// runPipelineForBench 把 Risk 的本地段抽出来供基准(不发网)。
func runPipelineForBench(_ context.Context, c *Client, p BasicParam, sys protocol.SystemFields) string {
	built, err := protocol.BuildRiskRequest(protocol.RiskParams{
		BizID: p.BizID, UserID: p.UserID, Platform: p.Platform, EventType: p.EventType,
		FingerToken: p.FingerToken, IP: p.IP, BizTime: p.BizTime,
		TenantID: p.TenantID, SiteType: p.SiteType,
	}, map[string]any{"amount": "1000", "mobile": "13800000000"}, []string{"mobile"}, c.signer, sys)
	if err != nil {
		b2, _ := json.Marshal(err.Error())
		return string(b2)
	}
	headers := protocol.Build(protocol.ModeSync, built.HeaderJSON, built.Signature,
		effectiveUserID(p.UserID), c.auth())
	_, _ = protocol.Marshal(built.Body)
	o := protocol.ParseRiskBody([]byte(`{"code":"200","msg":"","data":{"riskId":"r","strategy":"accept","data":{}}}`))
	return headers.Get("X-SIGNATURE") + "|" + o.Code
}
