package notify

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/decodeex/risk-client-go/sdklog"
)

// ErrInvalidConfig 是 notify 包的配置哨兵(errors.Is 可判)。
var ErrInvalidConfig = errors.New("notify: invalid consumer config")

// ConsumerConfig 是消费能力配置。所有零值字段在 Validate 阶段落默认值;
// **构造 Consumer 与调用 Validate 都不建立任何网络连接**(Req 7.10:
// 连接发生在 Start 的工厂函数里)。
type ConsumerConfig struct {
	Brokers     []string    `json:"brokers" yaml:"brokers"`
	GroupID     string      `json:"group_id" yaml:"group_id"` // 必填:按服务命名,独立于 Java 消费组
	Topics      []string    `json:"topics" yaml:"topics"`
	StartOffset StartOffset `json:"start_offset" yaml:"start_offset"` // 默认 latest

	PollMaxRecords int           `json:"poll_max_records" yaml:"poll_max_records"` // 默认 10
	PollTimeout    time.Duration `json:"poll_timeout" yaml:"poll_timeout"`         // 聚批窗口,默认 1s
	RetryCount     int           `json:"retry_count" yaml:"retry_count"`           // 默认 3
	RetryInterval  time.Duration `json:"retry_interval" yaml:"retry_interval"`     // 默认 1s

	Filter       Filter        `json:"-"`
	OnBatchError OnBatchError  `json:"-"`
	Logger       sdklog.Logger `json:"-"`

	GracefulTimeout time.Duration `json:"graceful_timeout" yaml:"graceful_timeout"` // Stop 上限,默认 10s

	SASL SASLConfig `json:"sasl" yaml:"sasl"`
	TLS  TLSConfig  `json:"tls" yaml:"tls"`
}

// StartOffset 消费起点形态。
type StartOffset int8

const (
	OffsetLatest   StartOffset = iota // 默认:从最新开始
	OffsetEarliest                    // 从最早开始(调试/补偿任务常用)
)

// SASLConfig 经典 SASL 认证(plain / scram-sha256 / scram-sha512)。凭证经宿主
// ${VAR} 环境变量注入,建议不进静态配置文件。Mechanism 空表示不启用。
type SASLConfig struct {
	Mechanism string `json:"mechanism" yaml:"mechanism"` // plain|scram-sha256|scram-sha512
	User      string `json:"user" yaml:"user"`
	Password  string `json:"password" yaml:"password"`
}

// TLSConfig 出站 TLS。
type TLSConfig struct {
	Enable             bool `json:"enable" yaml:"enable"`
	InsecureSkipVerify bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}

// Validate 校验并在副本上落默认值(不改调用方原值)。全部失败都包装 ErrInvalidConfig。
func (c ConsumerConfig) Validate() (ConsumerConfig, error) {
	c = c.clone()
	switch {
	case len(c.Brokers) == 0:
		return c, fmt.Errorf("%w: brokers is empty", ErrInvalidConfig)
	case strings.TrimSpace(c.GroupID) == "":
		return c, fmt.Errorf("%w: group_id is required", ErrInvalidConfig)
	case len(c.Topics) == 0:
		return c, fmt.Errorf("%w: topics is empty", ErrInvalidConfig)
	}
	for i := range c.Brokers {
		if strings.TrimSpace(c.Brokers[i]) == "" {
			return c, fmt.Errorf("%w: brokers[%d] is blank", ErrInvalidConfig, i)
		}
	}
	switch strings.ToLower(c.SASL.Mechanism) {
	case "", "plain", "scram-sha256", "scram-sha512":
	default:
		return c, fmt.Errorf("%w: unsupported sasl mechanism %q", ErrInvalidConfig, c.SASL.Mechanism)
	}
	if c.PollMaxRecords <= 0 {
		c.PollMaxRecords = 10
	}
	if c.PollTimeout <= 0 {
		c.PollTimeout = time.Second
	}
	if c.RetryCount <= 0 {
		c.RetryCount = 3
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = time.Second
	}
	if c.GracefulTimeout <= 0 {
		c.GracefulTimeout = 10 * time.Second
	}
	if c.Logger == nil {
		c.Logger = sdklog.Default()
	}
	return c, nil
}

func (c ConsumerConfig) clone() ConsumerConfig {
	cp := c
	cp.Brokers = append([]string(nil), c.Brokers...)
	cp.Topics = append([]string(nil), c.Topics...)
	return cp
}
