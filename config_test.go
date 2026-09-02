package riskclient

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/decodeex/bifu-risk-sdk/internal/protocol"
)

// fixturePublicKey 从 golden 的 staticKeyPair 取 SPKI Base64 作为合法公钥夹具。
func fixturePublicKey(t *testing.T) (spkiB64 string, pemForm string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/ecies_vectors.json")
	if err != nil {
		t.Fatalf("读取 vectors 失败: %v", err)
	}
	var doc struct {
		StaticKeyPair struct {
			PublicKeySpkiBase64Std string `json:"publicKeySpkiBase64Std"`
		} `json:"staticKeyPair"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	spki := doc.StaticKeyPair.PublicKeySpkiBase64Std
	pemForm = "-----BEGIN PUBLIC KEY-----\n" + spki + "\n-----END PUBLIC KEY-----"
	return spki, pemForm
}

func TestConfigValidateRejectsMissingFields(t *testing.T) {
	spki, pemForm := fixturePublicKey(t)
	_ = spki
	base := Config{
		BaseURL: "http://127.0.0.1:1", ClientID: "cid", ClientSecret: "sec",
		PublicKey: pemForm,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("完整配置应通过:%v", err)
	}
	for _, field := range []string{"BaseURL", "ClientID", "ClientSecret", "PublicKey"} {
		c := base
		switch field {
		case "BaseURL":
			c.BaseURL = ""
		case "ClientID":
			c.ClientID = ""
		case "ClientSecret":
			c.ClientSecret = ""
		case "PublicKey":
			c.PublicKey = ""
		}
		err := c.Validate()
		if !errors.Is(err, protocol.ErrConfig) {
			t.Fatalf("%s 缺失应报 ErrConfig,得 %v", field, err)
		}
		wantField := map[string]string{"BaseURL": "base_url", "ClientID": "client_id",
			"ClientSecret": "client_secret", "PublicKey": "public_key"}[field]
		if !strings.Contains(err.Error(), wantField) {
			t.Fatalf("%s 错误信息应点名缺失字段:%v", field, err)
		}
	}
	badURL := base
	badURL.BaseURL = "ftp://x"
	if err := badURL.Validate(); !errors.Is(err, protocol.ErrConfig) {
		t.Fatal("非 http/https 协议头应被拒")
	}
}

// TestNewParsesBothPublicKeyForms:SPKI Base64 与 PEM 两种形态都必须可用。
func TestNewParsesBothPublicKeyForms(t *testing.T) {
	spki, pemForm := fixturePublicKey(t)
	for name, key := range map[string]string{"spki-base64": spki, "pem": pemForm} {
		cfg := Config{BaseURL: "http://127.0.0.1:1", ClientID: "c", ClientSecret: "s",
			PublicKey: key, EventTimeoutMs: map[string]int64{"login": 1000}}
		c, err := New(cfg)
		if err != nil {
			t.Fatalf("%s 形态应可建实例:%v", name, err)
		}
		if c == nil || c.signer == nil {
			t.Fatalf("%s 实例不完整", name)
		}
	}
}

// TestNewDefaultsFillIn:零值 HTTP/版本字段落默认且不改原入参。
func TestNewDefaultsFillIn(t *testing.T) {
	spki, _ := fixturePublicKey(t)
	cfg := Config{BaseURL: "http://127.0.0.1:1", ClientID: "c", ClientSecret: "s",
		PublicKey: spki, EventTimeoutMs: map[string]int64{"login": 1000}}
	got, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.cfg.ClientVersion != protocol.DefaultClientVersion {
		t.Fatalf("默认 clientVersion 应为 %s,得 %s", protocol.DefaultClientVersion, got.cfg.ClientVersion)
	}
	if got.cfg.HTTP.MaxIdleConnsPerHost != 5 {
		t.Fatalf("MaxIdleConnsPerHost 默认应为 5(对齐 Java),得 %d", got.cfg.HTTP.MaxIdleConnsPerHost)
	}
	if cfg.ClientVersion != "" || cfg.HTTP.MaxIdleConnsPerHost != 0 {
		t.Fatal("applyDefaults 必须返回副本,不得污染调用方原值")
	}
}
