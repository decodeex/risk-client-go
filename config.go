package riskclient

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/decodeex/bifu-risk-sdk/internal/protocol"
)

// Config 是创建客户端的全部静态配置(Req 6.1)。零配置文件依赖:结构由宿主的
// Kratos config/Apollo 等装载后传入,json/yaml 标签对齐宿主 ${VAR} 展开的下划线小写惯例。
//
// 必填:BaseURL / ClientID / ClientSecret / PublicKey / EventTimeoutMs(调用时逐事件查表,
// 缺配在使用点报 ErrConfig——Req 6.3;表本身允许空,便于先建实例后按需补)。
type Config struct {
	BaseURL string `json:"base_url" yaml:"base_url"`
	// ClientID/ClientSecret 即 M2M 凭证(Authorization 头原文素材),仅内存持有。
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"client_secret" yaml:"client_secret"`
	// PublicKey 是网关公钥:接受 PEM("-----BEGIN PUBLIC KEY-----")或 Base64(SPKI DER)
	// 两种形态,New 时解析为 P-256;非 P-256 或不可解析在初始化期拒绝(Req 6.2)。
	PublicKey string `json:"public_key" yaml:"public_key"`
	// ClientVersion 覆盖协议上报版本;空取 DefaultClientVersion(1.0.7,对齐 Java)。
	ClientVersion string `json:"client_version" yaml:"client_version"`
	// EventTimeoutMs 按事件类型的调用超时(毫秒)。问询与案件查询都以 eventType 查此表;
	// 未命中即本地失败,不发网络。毫秒入参对宿主 yaml 更友好,内部转 Duration。
	EventTimeoutMs map[string]int64 `json:"event_timeout_ms" yaml:"event_timeout_ms"`
	// HTTP 连接池参数;零值字段全部落默认值(见 HTTPConfig 文档)。
	HTTP HTTPConfig `json:"http" yaml:"http"`
	// LogDetail 明细日志开关(Req 8):true 输出请求/响应报文(Authorization 掩码);
	// false 只输出无业务内容的调用摘要与错误日志。默认 false。
	LogDetail bool `json:"log_detail" yaml:"log_detail"`
	// CaseQueryPath 案件查询路径,默认 "/risk-audit/generalCase/query"(带服务名前缀,
	// 对齐网关服务名路由约定,与 /risk-engine/risk/** 同规则;Java 历史无前缀路径未经验证)。
	CaseQueryPath string `json:"case_query_path" yaml:"case_query_path"`
}

// HTTPConfig 是共享 http.Client 的连接池参数(Req 6.1 的连接与读写超时部分)。
// 零值即默认:Dial 5s / TLS握手 10s / 响应头 10s / MaxIdleConnsPerHost=5
// (MaxIdleConnsPerHost 对齐 Java 版 httpMaxIdleConnections=5,可调)。
type HTTPConfig struct {
	DialTimeoutMS           int64 `json:"dial_timeout_ms" yaml:"dial_timeout_ms"`
	TLSHandshakeTimeoutMS   int64 `json:"tls_handshake_timeout_ms" yaml:"tls_handshake_timeout_ms"`
	ResponseHeaderTimeoutMS int64 `json:"response_header_timeout_ms" yaml:"response_header_timeout_ms"`
	MaxIdleConnsPerHost     int   `json:"max_idle_conns_per_host" yaml:"max_idle_conns_per_host"`
}

// Validate 做与网络无关的字段校验(New 会再追加公钥解析校验)。错误一律包装
// ErrConfig 以便 errors.Is 判类(Req 6.2:初始化拦截,不产出可用实例)。
func (c Config) Validate() error {
	var missing []string
	if strings.TrimSpace(c.BaseURL) == "" {
		missing = append(missing, "base_url")
	}
	if c.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if c.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if strings.TrimSpace(c.PublicKey) == "" {
		missing = append(missing, "public_key")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing required fields %s", protocol.ErrConfig, strings.Join(missing, ","))
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: base_url 非法(需 http/https 绝对地址): %q", protocol.ErrConfig, c.BaseURL)
	}
	return nil
}

// eventTimeout 把毫秒表项转为 Duration;未配置的事件返回 ok=false(Req 6.3)。
func (c Config) eventTimeout(eventType string) (time.Duration, bool) {
	ms, ok := c.EventTimeoutMs[eventType]
	if !ok {
		return 0, false
	}
	d := time.Duration(ms) * time.Millisecond
	if d <= 0 {
		return 0, false // 显式配置成非正数同样视作缺配,避免语义歧义
	}
	return d, true
}

// applyDefaults 返回补齐默认值后的副本(不改动调用方原值)。
func (c Config) applyDefaults() Config {
	if strings.TrimSpace(c.ClientVersion) == "" {
		c.ClientVersion = protocol.DefaultClientVersion
	}
	if strings.TrimSpace(c.CaseQueryPath) == "" {
		c.CaseQueryPath = "/risk-audit/generalCase/query"
	}
	if c.HTTP.DialTimeoutMS <= 0 {
		c.HTTP.DialTimeoutMS = 5000
	}
	if c.HTTP.TLSHandshakeTimeoutMS <= 0 {
		c.HTTP.TLSHandshakeTimeoutMS = 10000
	}
	if c.HTTP.ResponseHeaderTimeoutMS <= 0 {
		c.HTTP.ResponseHeaderTimeoutMS = 10000
	}
	if c.HTTP.MaxIdleConnsPerHost <= 0 {
		c.HTTP.MaxIdleConnsPerHost = 5
	}
	return c
}
