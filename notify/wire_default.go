package notify

import (
	"crypto/tls"
	"strings"
	"time"

	kafka "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/decodeex/bifu-risk-sdk/sdklog"
)

// defaultConnFactory 是生产环境的连接工厂:按 ConsumerConfig 组装 kafka-go 的
// Reader(消费组协议)与可选的 DLQ Writer。参数口径与宿主 bifufx-api 对齐:
// Reader CommitInterval=0(仅显式提交)、WatchPartitionChanges、组再平衡自动分摊;
// Writer Hash balancer + RequiredAcks=1。
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
		mech, _ := scram.Mechanism(scram.SHA256, cfg.SASL.User, cfg.SASL.Password)
		dialer.SASLMechanism = mech
	case "scram-sha512":
		mech, _ := scram.Mechanism(scram.SHA512, cfg.SASL.User, cfg.SASL.Password)
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
	if cfg.DLQTopic != "" {
		conn.dlq = &kafka.Writer{
			Addr:         kafka.TCP(cfg.Brokers...),
			Topic:        cfg.DLQTopic,
			Balancer:     &kafka.Hash{},
			RequiredAcks: kafka.RequireOne,
			BatchTimeout: 50 * time.Millisecond,
			// TLS/SASL 与消费端同源:kafka.Transport 承载
			Transport: &kafka.Transport{
				DialTimeout: dialer.Timeout,
				TLS:         dialer.TLS,
				SASL:        dialer.SASLMechanism,
			},
		}
	}
	return conn, nil
}
