// Package riskclient 是风控网关的 Go 客户端(bifu-risk-sdk),提供三类能力:
//
//  1. 同步风控问询 Client.Risk —— 与 Java 版 risk-client 1.0.7 协议逐字节兼容
//     (BC 1.70 默认参数 ECIES 签名链、六头构造、敏感字段加密),同一网关与凭证可混用;
//  2. 审核案件查询 Client.QueryAuditCase —— 上游补偿任务用;
//  3. Kafka 审核结果通知消费 bifu-risk-sdk/notify —— 批量/过滤/重试/死信/优雅停机,
//     Start/Stop 兼容 Kratos transport.Server。
//
// # 快速接入
//
//	cfg := riskclient.Config{
//	    BaseURL: "https://risk-gateway", ClientID: "...", ClientSecret: "...",
//	    PublicKey: "<网关公钥 PEM 或 Base64(SPKI)>",
//	    EventTimeoutMs: map[string]int64{"withdraw": 5000, "login": 3000},
//	}
//	cli, err := riskclient.New(cfg, riskclient.WithRequestIP(podIP))
//	if err != nil { return err }
//	resp, err := cli.Risk(ctx, riskclient.BasicParam{
//	    BizID: "20260827001", UserID: "u-1", Platform: "APP",
//	    EventType: "login", BizTime: time.Now().UnixMilli(),
//	}, map[string]any{"amount": "1000"}, []string{"mobile"})
//	// 双轨错误契约:err 仅代表本地预检失败(参数/配置);
//	// 网关超时/限流等一切远端失败都是 resp 的非 200 Code。
//	if err != nil { return err }
//	if !resp.IsSuccess() { ... }
//
// # 错误契约(双轨)
//
//   - 本地轨:errors.Is(err, ErrConfig | ErrParam | ErrReservedField)——未发网络;
//   - 远端轨:结构化结果(Code 408/429/403/401/500 或业务码),不产生 error。
//
// # 接入提醒
//
//   - 容器/K8s 多网卡环境务必 WithRequestIP 显式指定出口 IP;
//   - 消费回调内部必须幂等(at-least-once 投递语义,见 notify 包文档)。
package riskclient
