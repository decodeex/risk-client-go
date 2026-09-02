# bifu-risk-sdk

风控网关 Go 客户端。与 Java 版 risk-client 1.0.7 协议逐字节兼容:同一网关、同一套凭证,Go/Java 混用。依赖仅标准库 + kafka-go v0.4.50。

## 引入依赖

```bash
go get github.com/decodeex/bifu-risk-sdk@v0.1.0
```

本仓 public,零认证配置。升级 = 改 require 版本号 + 代码评审;回滚 = 版本号回退。

## 快速接入

```go
cli, err := riskclient.New(riskclient.Config{
    BaseURL:        "https://risk-gateway",
    ClientID:       cfg.RiskClientID,     // 风控平台组发放
    ClientSecret:   cfg.RiskClientSecret,
    PublicKey:      cfg.RiskPublicKey,    // 网关公钥(向风控研发索取)
    EventTimeoutMs: map[string]int64{"login": 3000, "withdraw": 5000},
}, riskclient.WithRequestIP(podIP))       // K8s 多网卡环境必须显式指定
if err != nil { return err }              // 配置错:启动即失败,不会带病运行

// 同步问询:资金/登录等动作当场调用,按 strategy 当场处置
resp, err := cli.Risk(ctx, riskclient.BasicParam{
    BizID: "20260827001", UserID: "u-1", Platform: "APP",
    EventType: "withdraw", BizTime: time.Now().UnixMilli(),
    IP: "1.2.3.4",                        // 用户 IP 走这里,不能放 bizData
}, map[string]any{                        // 业务数据,原样进风控引擎
    "amount": "1000", "mobile": "13800000000",
}, []string{"mobile"})                    // 需加密传输的敏感字段
if err != nil { return err }              // 仅本地预检失败(参数/配置),未发网络

switch {
case resp.IsSuccess() && resp.Data.Strategy == "accept": // 放行
case resp.IsSuccess() && resp.Data.Strategy == "reject": // 拦截
default:                                                  // verify/review/非200:按业务兜底
}
```

**错误契约(必读)**:

- `err != nil`:参数/配置问题,**未发网络**;`errors.Is` 判 `ErrConfig / ErrParam / ErrReservedField`
- `err == nil`:请求已发出。**一切远端失败都是结果不是 error**——超时 408、限流 429、网关拒绝 403/401、其余 500;`resp.IsSuccess()` 即 code=="200"

**案件查询**(通知丢失时的补偿,按事件类型+业务ID 反查人工审核结果):

```go
cr, _ := cli.QueryAuditCase(ctx, "withdraw", "20260827001")
// cr.IsSuccess() / cr.Data.{CaseNo, AuditResult, AuditTime...}
// 路径默认 /risk-audit/generalCase/query(服务名前缀);异常环境可用 CaseQueryPath 覆盖
```

## 配置说明

| 字段 | 必填 | 说明 |
|---|---|---|
| BaseURL | ✓ | 风控网关地址 |
| ClientID / ClientSecret | ✓ | M2M 凭证(风控平台组发放,勿入代码库) |
| PublicKey | ✓ | 网关公钥,与所连环境必须成对;New 时解析校验 |
| EventTimeoutMs | ✓ | 每事件调用超时(毫秒);未配置的事件直接报错不发网络 |
| LogDetail | false | true 打印请求/响应报文(Authorization 掩码),仅排查用 |
| ClientVersion | 1.0.7 | 协议上报版本,无需改动 |
| HTTP | 有默认 | 连接池(MaxIdleConnsPerHost 默认 5) |

Option:`WithRequestIP` / `WithLogger`(接宿主日志,默认标准库)/ `WithHTTPClient` / `WithTraceIDFunc`。

**Client 请全局复用(单例)**:并发安全;每 New 一次就是一套独立连接池,按请求新建属反模式。

## 消费(审核结果通知)

```go
consumer, _ := notify.NewConsumer(notify.ConsumerConfig{
    Brokers:  []string{"msk:9092"},
    GroupID:  "my-service",              // 每个服务独立,勿与其他服务共用
    Topics:   []string{"RISK_AUDIT_RESULT_NOTIFY"},
    OnBatchError: func(b []notify.Notification, err error) { /* 接 Lark 告警 */ },
}, func(ctx context.Context, batch []notify.Notification) error {
    for _, n := range batch { /* 按 n.AuditResult(accept/reject)处置 */ }
    return nil                           // 返回 error 触发整批重试
})
app := kratos.New(kratos.Server(gs, hs, consumer))
```

配置(默认值):`PollMaxRecords(10)`、`PollTimeout(1s)`、`RetryCount(50)`、`RetryInterval(1s)`、`GracefulTimeout(10s)`、`StartOffset(latest)`、`DLQTopic(空)`、`SASL/TLS`、`Filter`。

**行为要点**:

- at-least-once 投递:**回调必须幂等**(重投/重复通知都可能出现)
- 回调失败:整批重试 `RetryCount×RetryInterval`;耗尽后调 `OnBatchError` 并提交位点继续消费(消息放弃)。要转存死信配 `DLQTopic`,不配则告警即终
- 位点仅在批次终局(成功/死信/耗尽告警)后提交,中途绝不提交
- 不构造 Consumer 就没有任何 Kafka 连接
- 传给 `Start`/`Run` 的 ctx 是消费循环的生命周期父级,请传 Background 或应用级 ctx,勿传短超时的请求 ctx(Kratos 挂 `kratos.Server` 时框架已管好)
- Stop 之后本实例不支持原地重启(需新建 Consumer);宿主进程重启即恢复
- 通知可能缺失:以 `QueryAuditCase` 补偿为准,勿依赖通知必达;案件查询路径默认带服务名前缀 `/risk-audit/generalCase/query`

## 接入注意

- 消息与问询里的业务键用 ASCII;`ip` 是协议字段走 `BasicParam.IP`,不能塞 bizData
- 六头全大写拼写仅 HTTP/1.1 保证,SDK 已强制;勿替换 Transport 后关闭该约束
- 问询不去重(每次调用生成新风险事件),防重由业务按 bizId 自理
- 网关侧改协议(加密参数/报文)需通知本仓同步,仓库内 golden 向量会立刻暴露不兼容
