# risk-client-go

> 风控平台 Go 客户端。与 Java 版客户端协议完全兼容：同一网关、同一套凭证，Go/Java 可混用。
> 三个能力：**同步问询**（登录、提币这些动作发生时，当场问风控放行还是拦截）、**审核结果通知消费**（人工审核完，Kafka 推给业务）、**案件查询**（通知丢了用它兜底查）。
> 直接 `go get` 即可，无私库认证配置；依赖只有标准库 + kafka-go。
> 接入前找风控研发要：网关地址、clientId / clientSecret、公钥（三样按环境成对）；要消费通知再加 Kafka 地址。

---

**🔧 修订记录**

| 功能 | 版本号 | 修订时间 | 修订人 | 备注 |
|---|---|---|---|---|
| 初版 | v0.1.0 | 2026.09.02 | kiwi | 同步风控问询（含敏感字段加密）+ 审核案件查询 + Kafka 审核结果通知消费；已通过真实环境全链路联调 |

---

## 快速开始

### 1️⃣ 添加依赖

```bash
go get github.com/decodeex/risk-client-go@v0.1.0
```

### 2️⃣ 构造 Client（全局单例，并发安全）

```go
import riskclient "github.com/decodeex/risk-client-go"

cli, err := riskclient.New(riskclient.Config{
    BaseURL:      "http://risk-gateway.risk.cex-k8s-test.jcworkint.com", // 网关地址
    ClientID:     cfg.RiskClientID,     // 找风控研发提供开发/生产环境的
    ClientSecret: cfg.RiskClientSecret, // 同上，勿入代码库
    PublicKey:    cfg.RiskPublicKey,    // 生产环境公钥咨询风控研发；New 时解析校验
    EventTimeoutMs: map[string]int64{   // 按事件类型的调用超时（毫秒），必配
        "login":    3000,
        "register": 3000,
    },
    LogDetail: false, // true 打印请求/响应报文（凭证掩码），仅排查用
}, riskclient.WithRequestIP(podIP))     // K8s 多网卡环境必须显式指定出口 IP
if err != nil { /* 配置错误启动即失败，不会带病运行 */ }
```

**Client 请全局复用（单例）**：每 New 一次就是一套独立连接池，按请求新建属反模式。

### 3️⃣ 超时配置

超时按 eventType 逐个配在 `EventTimeoutMs`，同步问询和案件查询共用这张表：

- **没配的事件类型，调用直接报错、不发请求**——新接场景先配超时再上线；
- 怎么定：风控平均响应 ~30ms，P99 大概是它的 3~5 倍，先给保守值，上线看 P99 再调。

建议值（可按业务容忍度调整）：

| eventType | 建议超时 | 说明 |
|---|---|---|
| login / register | 3000ms | 高频低风险场景 |
| withdraw 等资金类 | 5000ms | 规则链长，容忍度略高 |
| kyc_verification 等查询类 | 5000ms | 案件查询同用此表 |

### 配置文件示例（yaml）

SDK 不绑定配置文件：`Config` / `ConsumerConfig` 字段带 `yaml` 标签，配置中心或本地 yaml 装载后传入即可。完整配置示例如下（凭证已省略；接入时换成对应环境的值）：

```yaml
# 本地调试配置(该目录不进 git,凭证可直接写在这里;环境变量可覆盖)。
# 同步问询 + 案件查询(riskclient.Config)
risk:
  base_url: http://127.0.0.1:8081
  client_id: "xxxx"                    # 三个值找风控研发要对应环境的;也可用环境变量覆盖
  client_secret: "xxxx"                # 同上,勿入代码库
  public_key: "MFkwEwYHKoZIzj0CAQ..."  # 网关公钥(PEM 或 Base64(SPKI) 皆可),New 时校验
  log_detail: true                     # 明细日志:打印请求/响应报文(调试默认开,生产 false)
  event_timeout_ms:                    # 按事件类型的调用超时表,未配置的事件调用直接失败
    withdraw: 5000
    login: 3000
    register: 3000
    kyc_verification: 1000

# Kafka 审核结果通知消费(brokers/topics 用逗号串,同 Java bootstrap.servers)
kafka:
  enabled: true                        # 宿主开关:false 时完全零 Kafka 连接
  brokers: 127.0.0.1:9092              # 逗号分隔,多个写 host1:9092,host2:9092
  group_id: risk-sdk-debug
  topics: RISK_AUDIT_RESULT_NOTIFY     # 逗号分隔,可多个
  retry_count: 3                       # 回调失败重试次数(SDK 默认 3);耗尽后告警+提交位点继续
  retry_interval_ms: 1000              # 重试间隔(SDK 默认 1s)
  start_offset: latest                 # 生产口径(也是 SDK 默认);earliest 仅调试回放用,漏了靠案件查询补偿
```

装载代码（以 `gopkg.in/yaml.v3` 为例，解出后装配给 SDK）：

```go
type AppConfig struct {
    Risk  RiskConf  `yaml:"risk"`
    Kafka KafkaConf `yaml:"kafka"`
}

type RiskConf struct {
    BaseURL        string           `yaml:"base_url"`
    ClientID       string           `yaml:"client_id"`     // 凭证三项:环境变量优先,配置文件兜底
    ClientSecret   string           `yaml:"client_secret"`
    PublicKey      string           `yaml:"public_key"`
    LogDetail      bool             `yaml:"log_detail"`
    EventTimeoutMS map[string]int64 `yaml:"event_timeout_ms"`
    RequestIP      string           `yaml:"request_ip"`    // 可选:不配走 SDK 自动探测
}

// brokers/topics 是逗号串（同 Java bootstrap.servers），SDK 字段是 []string——
// 宿主自己收字符串、切开后再装配。SASL/TLS 等其余消费配置按需加字段。
type KafkaConf struct {
    Enabled         bool   `yaml:"enabled"`      // 宿主开关:false 就不构造 Consumer
    Brokers         string `yaml:"brokers"`      // 逗号分隔
    Topics          string `yaml:"topics"`       // 逗号分隔
    GroupID         string `yaml:"group_id"`
    RetryCount      int    `yaml:"retry_count"`
    RetryIntervalMS int    `yaml:"retry_interval_ms"`
    StartOffset     string `yaml:"start_offset"` // latest | earliest
}

func splitList(s string) []string {
    var out []string
    for _, p := range strings.Split(s, ",") {
        if p = strings.TrimSpace(p); p != "" {
            out = append(out, p)
        }
    }
    return out
}

var ac AppConfig
raw, err := os.ReadFile("config.yaml")
if err != nil { /* ... */ }
if err := yaml.Unmarshal(raw, &ac); err != nil { /* ... */ }

opts := []riskclient.Option{} // WithLogger 等按需加
if ac.Risk.RequestIP != "" {  // 不能无条件传空串:WithRequestIP("") 是「显式置空」语义,会跳过自动探测
    opts = append(opts, riskclient.WithRequestIP(ac.Risk.RequestIP))
}
cli, err := riskclient.New(riskclient.Config{
    BaseURL:        ac.Risk.BaseURL,
    ClientID:       ac.Risk.ClientID,
    ClientSecret:   ac.Risk.ClientSecret, // 凭证/公钥错误启动即失败
    PublicKey:      ac.Risk.PublicKey,
    LogDetail:      ac.Risk.LogDetail,
    EventTimeoutMs: ac.Risk.EventTimeoutMS,
}, opts...)

consumerCfg := notify.ConsumerConfig{
    Brokers:       splitList(ac.Kafka.Brokers),
    Topics:        splitList(ac.Kafka.Topics),
    GroupID:       ac.Kafka.GroupID,
    RetryCount:    ac.Kafka.RetryCount,
    RetryInterval: time.Duration(ac.Kafka.RetryIntervalMS) * time.Millisecond, // SDK 字段是 Duration,毫秒在宿主侧转
}
if ac.Kafka.StartOffset == "earliest" {
    consumerCfg.StartOffset = notify.OffsetEarliest // 默认即 latest,不配就是生产口径
}
consumer, err := notify.NewConsumer(consumerCfg, handler) // brokers 切完为空会在 Validate 报 ErrInvalidConfig，启动期暴露
// ac.Kafka.Enabled == false 时上面整段不执行,零 Kafka 连接
```

三个对接点别配错：

- `enabled` 是宿主自己的开关（示例工程的写法）：false 就不构造 `Consumer`，照样零 Kafka 连接——是否消费是代码决定，SDK 配置里没有这项；
- `request_ip` 默认不配（走 SDK 自动探测）；K8s 多网卡环境建议加这个字段，且只在有值时调 `WithRequestIP`——不能无条件传空串，`WithRequestIP("")` 是「显式置空」语义；
- 回调（`OnBatchError` / `Filter`）是代码不是配置，告警接线写在代码里；`retry_interval` 等在 SDK 是 `time.Duration`（yaml 直填会按纳秒解），所以示例工程用 `retry_interval_ms` 毫秒字段自己转；`poll_timeout` / `graceful_timeout` 默认值够用，不用配。

### 🚀 同步问询

```go
resp, err := cli.Risk(ctx, riskclient.BasicParam{
    BizID:       "order-1001",             // 业务单号，全局唯一（必填）
    UserID:      "u-001",                  // 空则默认 UNKNOWN
    Platform:    "web",
    EventType:   "login",                  // 必填，决定超时与路径
    IP:          "1.2.3.4",                // 用户终端 IP 走这里，不能放 bizData
    FingerToken: fingerToken,              // 设备指纹 token（前端 risk-fingerprint 采集）
    BizTime:     time.Now().UnixMilli(),
}, map[string]any{                         // 业务数据，原样进风控引擎
    "email": "user@example.com",
    "phone": "8613800000000",
}, []string{"email", "phone"})             // 敏感字段：SDK 加密后传输，平台侧解密

// 错误契约（必读）：
// err != nil  → 本地预检失败，未发网络：errors.Is 判 ErrConfig / ErrParam / ErrReservedField
// err == nil  → 请求已发出，一切远端失败都是结果不是 error，按 code 分支：
if err == nil && resp.IsSuccess() {        // code == "200"
    switch resp.Data.Strategy {
    case "accept": // 风控放行
    case "reject": // 风控拒绝（原因在 resp.Data.Data）
    case "review": // 转人工审核，等 Kafka 通知
    }
} else if err == nil {
    // 响应码：408 网络超时 / 429 请求过于频繁 / 401 未授权签名错误 / 403 无权限 / 500 内部错误 / 其他 业务错误码
    // 针对不同的 code 进行额外处置
} else {
    // ErrConfig / ErrParam / ErrReservedField：修调用方代码，不会发生在生产流量上
}
```

问询别做错的两件事：bizData 的键用 ASCII（中文键签名可能对不上）；每次调用就是一条新风险事件，同一 bizId 别重复问，防重由业务自理。

### 🚀 审核结果通知消费（at-least-once，**回调必须幂等**）

```go
import "github.com/decodeex/risk-client-go/notify"

consumer, err := notify.NewConsumer(notify.ConsumerConfig{
    Brokers: []string{"b-1.xxx.kafka.amazonaws.com:9092"},
    GroupID: "my-service",                        // 每个服务独立，勿与其他服务共用
    Topics:  []string{"RISK_AUDIT_RESULT_NOTIFY"},
    OnBatchError: func(batch []notify.Notification, err error) {
        // 重试耗尽的终局告警，接 Lark/监控
    },
}, func(ctx context.Context, batch []notify.Notification) error {
    for _, n := range batch {                     // 同步处理，按 n.AuditResult(accept/reject) 处置
        _ = n
    }
    return nil                                    // 返回 error 触发整批重试
})
// Kratos 服务：app := kratos.New(kratos.Server(gs, hs, consumer))
// 非 Kratos：go consumer.Run(ctx) 启动；停机时 consumer.Stop(ctx) 优雅收尾
```

消费行为要点：

- 一批处理完（回调成功，或重试耗尽已告警）才提交位点（位点=消费进度，告诉 Kafka「这批完了」）；失败中途绝不提交，这批会在重启后重新投递——所以回调必须幂等；
- 回调失败按 `RetryCount(默认3) × RetryInterval(默认1s)` 重试，耗尽后调 `OnBatchError` 告警、提交位点、继续消费；SDK 不内置死信 topic，要留存失败批次就在 `OnBatchError` 里自己落日志/库；
- 坏 JSON / 被 Filter 过滤的消息记日志跳过，不卡位点；
- 传给 `Start` / `Run` 的 ctx 是消费循环的生命周期父级：用 Background 或应用级 ctx，别传带短超时的请求 ctx（挂 kratos.Server 时框架已管好）；
- 不构造 Consumer 就没有任何 Kafka 连接；Stop 后实例不能原地重启（新建一个即可）。

### 🚀 案件查询

前置条件：所查询的 eventType 配入超时表（如 `kyc_verification: 5000`）。

```go
cr, err := cli.QueryAuditCase(ctx, "kyc_verification", "2758207")
// cr.IsSuccess() / cr.Data.{CaseNo, EventType, RiskID, BizID, AuditResult, AuditTime, AuditUser, Remark}
// AuditResult：accept 通过 / reject 拒绝 / temp_save 暂缓 / 空=待审核；查无案件 success=true 且 Data 为空
```

通知可能缺失，补偿任务以案件查询为准，勿依赖通知必达。

### 接入检查清单（上线前逐条过）

1. **凭证与公钥按环境成对**：clientId / clientSecret / publicKey 在 dev、test、prod 是三套，混用会被网关拒绝或验签失败——向风控研发领取时说清环境；
2. **Kafka 地址按环境区分**：dev / test / prod 是不同集群，向风控研发要对应环境的；
3. **`LogDetail` 生产保持 false**：true 会打印请求/响应报文（含业务数据，凭证已掩码），仅排查时临时开；
4. **多副本消费**：同一服务多副本共用同一个 GroupID 即自动分摊分区；副本数不要超过 topic 分区数；
5. **监控三项**：问询 `code != 200` 占比、调用耗时 P99、消费 `OnBatchError` 次数，接告警，异常先看 code 和 msg。

### 最后

SDK 内部失败全部兜底（panic 恢复、超时封顶），不会把宿主进程搞挂。使用中有问题，或需要更多能力（异步问询 / 提币签名等），联系风控研发。
