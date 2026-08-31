// Package riskclient_test 提供可运行接入示例(godoc Example 形态)。
package riskclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	riskclient "github.com/decodeex/bifu-risk-sdk"
)

// demoPublicKey 从 golden 向量取网关公钥(SPKI Base64 形态;真实接入用风控平台下发的公钥)。
func demoPublicKey() string {
	raw, err := os.ReadFile("testdata/ecies_vectors.json")
	if err != nil {
		return ""
	}
	var doc struct {
		StaticKeyPair struct {
			PublicKeySpkiBase64Std string `json:"publicKeySpkiBase64Std"`
		} `json:"staticKeyPair"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	return doc.StaticKeyPair.PublicKeySpkiBase64Std
}

// Example 问询最小装配:自建一个"什么都放行"的假网关演示完整调用形态。
func Example() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":"200","msg":"","data":{"riskId":"R-1","strategy":"accept","data":{}}}`)
	}))
	defer srv.Close()

	cli, err := riskclient.New(riskclient.Config{
		BaseURL:        srv.URL,
		ClientID:       "demo-client",
		ClientSecret:   "demo-secret",
		PublicKey:      demoPublicKey(),
		EventTimeoutMs: map[string]int64{"login": 2000},
	})
	if err != nil {
		fmt.Println("init:", err)
		return
	}

	resp, err := cli.Risk(context.Background(), riskclient.BasicParam{
		BizID: "demo-biz-0001", UserID: "u-1", Platform: "APP",
		EventType: "login", BizTime: time.Now().UnixMilli(),
	}, nil, nil)
	if err != nil {
		fmt.Println("local error:", err)
		return
	}
	fmt.Println(resp.Code, resp.Data.Strategy)
	// Output:
	// 200 accept
}
