package notify

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	kafka "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/decodeex/risk-client-go/sdklog"
)

// defaultConnFactory 是生产环境的连接工厂:按 ConsumerConfig 组装 kafka-go 的
// Reader(消费组协议)。参数口径与宿主 bifufx-api 对齐:
// CommitInterval=0(仅显式提交)、WatchPartitionChanges、组再平衡自动分摊。
//
// TLS/sASL:Enable 时 Dialer 挂 InsecureSkipVerify 可选的 TLS 与对应机制;
// SASL 凭证建议经宿主 ${VAR} 环境变量注入后传入本结构。
func defaultConnFactory(cfg ConsumerConfig) (*connections, error) {
	dialer := &kafka.Dialer{
		Timeout:   5 * time.Second,
		DualStack: true,
	}
	if cfg.TLS.Enable {
		dialer.TLS = &tls.Config{InsecureSkipVerify: cfg.TLS.InsecureSkipVerify} // #nosec G402 由配置显式声明
	}
	switch strings.ToLower(cfg.SASL.Mechanism) {
	case "plain":
		dialer.SASLMechanism = &plain.Mechanism{Username: cfg.SASL.User, Password: cfg.SASL.Password}
	case "scram-sha256":
		// 构造失败必须显式返回:此前错误被丢弃,机制为 nil 会静默退化成"不带 SASL 连接",
		// 凭证配错时只在 broker 侧看到莫名其妙的鉴权失败(2026-09-01 review 修复)。
		mech, merr := scram.Mechanism(scram.SHA256, cfg.SASL.User, cfg.SASL.Password)
		if merr != nil {
			return nil, fmt.Errorf("notify: sasl scram-sha256: %w", merr)
		}
		dialer.SASLMechanism = mech
	case "scram-sha512":
		mech, merr := scram.Mechanism(scram.SHA512, cfg.SASL.User, cfg.SASL.Password)
		if merr != nil {
			return nil, fmt.Errorf("notify: sasl scram-sha512: %w", merr)
		}
		dialer.SASLMechanism = mech
	}

	startOffset := kafka.LastOffset
	if cfg.StartOffset == OffsetEarliest {
		startOffset = kafka.FirstOffset
	}

	readerCfg := kafka.ReaderConfig{
		Brokers:               cfg.Brokers,
		GroupID:               cfg.GroupID,
		GroupTopics:           cfg.Topics,
		MinBytes:              1,
		MaxBytes:              10 << 20,
		StartOffset:           startOffset,
		CommitInterval:        0, // 仅显式提交 —— 位点语义的唯一事实来源是本循环
		WatchPartitionChanges: true,
		Dialer:                dialer,
		ErrorLogger:           kafka.LoggerFunc(func(msg string, args ...any) { sdklog.Errorf(cfg.Logger, msg, args...) }),
	}
	reader := kafka.NewReader(readerCfg)

	conn := &connections{reader: reader}
	return conn, nil
}
