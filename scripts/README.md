# Golden 向量生成(scripts/GenVectors.java)

本目录的 `GenVectors.java` 是风控 SDK 协议层全部测试的**"标准答案"生产器**:它把 Java 版
risk-client(BouncyCastle 1.70 无参 ECIES + sha512 签名链 + TreeMap/Jackson 规范 JSON + 六头构造)
的真实字节行为固化成四份可被 Go 测试直接加载的向量。

> 协议变更(网关头/报文/加密参数)或 BC 版本升级 ⇒ **必须重跑本脚本并把新向量提交进 `testdata/`**,
> 否则 Go 侧 golden 测试会立刻红(这正是它的设计意图)。

---

## 一、如何重新生成

环境要求:**JDK 11(Zulu)+ bcprov-jdk15on-1.70.jar**,无其他依赖。
不需要 hutool / Jackson / commons-lang3 —— 规范 JSON 的期望值是手工常量(见 §五)。

```bash
# 本机(gradle 缓存里的 bcprov 路径)
BC=~/.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk15on/1.70/4636a0d01f74acaf28082fb62b317f1080118371/bcprov-jdk15on-1.70.jar

cd scripts/
javac -encoding UTF-8 -cp "$BC" GenVectors.java      # -encoding UTF-8 必须带,源码含中文样本
java   -cp ".:$BC" GenVectors                        # 缺省输出 ../testdata
java   -cp ".:$BC" GenVectors /abs/path/to/outdir    # 或显式指定输出目录
```

脚本每次运行都会先做一组自检断言,**任何一条失败都会抛异常并以非零码退出**(不会产出半截数据):

1. 静态私钥标量反推公钥点 == 写死的公钥常量;
2. 最小 DER 编码器重建出的 SPKI == 常量;PKCS#8 经 BC 解析后重新编码 == 常量;
3. 六条 ECIES 向量逐条:`JCA 实际密文` == `手工复算(V‖Z→KDF2→XOR‖HMAC)` == 可用静态私钥解回明文(MAC 通过);
4. 全部规范 JSON 手写期望串 == 脚本内置的另一份独立规则实现(`canonical()` / `orderedJson()`);
5. 敏感字段(email)期望密文 == 固化在源码中的常量。

重跑一次以上比较 MD5 应当完全一致(确定性)。当前版本四个文件的 MD5:

| 文件 | 大小(B) | MD5 |
|---|---|---|
| ecies_vectors.json | 31 152 | `746a65327cb345102bdd7654b73bf61f` |
| canonjson_cases.json | 6 901 | `1d2659085d86d39b1e6bc9cbc2162261` |
| headers_golden.json | 13 755 | `847783f35608af7cb74b6660f5a0a5ab` |
| case_payload.json | 6 868 | `ed8c4a08e8bb095b0b176470ba13f5a4` |

(这张表只在"有意的协议改动 + 重跑"之后由提交人手工更新。)

---

## 二、确定性机制(重点阅读)

### 1. 固定静态密钥对(P-256 接收方)

| 项 | 值 |
|---|---|
| 私钥标量 d(hex) | `afcfa7cf5efda8bf6f9ecbf55fb8adfe7f68cdfa9efdb86f3e78cb51fc69bd86` |
| popcount | **168 / 256**(满足任务要求的"高 popcount") |
| NAF 权重 | **79**,高于 BC `ECKeyPairGenerator` 的 minWeight = n.bitLength()/4 = 64 |
| 公钥点(65B 非压缩 hex) | `0421726ceb323c768bd064a73439f7d90acf6a791c8aab449c43023211f96876c2bf7dc36e7f9bedd16f3057f3e02bad43fae8b37e5ac614f67708aec26a6fd303` |
| SPKI(X509,Base64 标准字母表) | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIXJs6zI8dovQZKc0OffZCs9qeRyKq0ScQwIyEflodsK/fcNuf5vt0W8wV/PgK61D+uizflrGFPZ3CK7Cam/TAw==` |
| PKCS#8(Base64 标准字母表,BC 重编码后的形态) | `ME0CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEMzAxAgEBBCCvz6fPXv2ov2+ey/VfuK3+f2jN+p79uG8+eMtR/Gm9hqAKBggqhkjOPQMBBw==` |

选型说明:"高 popcount"不能盲目堆置位——全 0xFE(×32 字节)这种 popcount=224 的解,
NAF 权重只有 33,**低于** BC 自己 64 的过筛线,属于会被加密器拒收的低权重特殊标量,
那才是真正的"边界退化"。上面这颗在两个维度上都远离退化边界。

### 2. ephemeral 回放(不改 BC 源码、不改 Cipher API 形态)

生产代码 `SecureUtil.encrypt` 用两参初始化:`cipher.init(Cipher.ENCRYPT_MODE, publicKey)`,
随机源由 JCA 提供、不可复现。本脚本改成三参初始化:
`cipher.init(Cipher.ENCRYPT_MODE, publicKey, customSecureRandom)` —— **只是替换随机源**,
ECIES 引擎类与默认参数(`IESParameterSpec(null,null,128)`,无分组密码)完全一致。

`customSecureRandom extends SecureRandom`,只覆写一件事:`nextBytes(byte[] buf)` 永远用同一个
32 字节块循环填满 buf。

原理:BC 的 `IESEngine.processBlock` 加密前由 `ECKeyPairGenerator` 抽临时标量,调用链
`BigIntegers.createRandomBigInteger(256, rnd)` → `new BigInteger(int, Random)` →
对 P-256 恰好是**一次 nextBytes(32 字节)**(256 bit 无溢出位,不需要清最高位),因此:

* 回放块 → 临时标量 k 完全确定;
* 密文前 65 字节即 V = k·G(非压缩点);
* 回放块取值 `970a950aa9950d348ac8c4ce7aa977e76a49a93b346ecb9969baae4a6d333045`,
  它同时就是每条向量的 ephemeralDHex(NAF 权重 103,首抽即过筛;nextBytes 恒定,
  万一不过筛会无限重抽死循环——这点会被向量自检立刻暴露)。

Go 侧复现:用该 32 字节构造临时私钥(crypto/ecdh 的 NewPrivateKey 收 32B 定长),
对同一 publicKeyHex、同一 ephemeralDHex 得到的密文必须与 cipherBase64Std / cipherHex 逐字节一致。

### 3. 夹具全固定

requestTime / traceId / requestIp / clientId / clientVersion / 凭证全部是源码常量,
脚本不读系统时钟、网卡或环境变量;敏感字段加密也走回放机制,所以第 3 组头部样例里的密文同样稳定。

---

## 三、testdata 文件 Schema 与名单上报接入（3.5）

### 3.1 ecies_vectors.json

顶层:_meta.*、staticKeyPair(§二那组数值)、ephemeralReplay、parameterModel、vectors[]、kdf2Vectors[]。

vectors 共 6 条,字段:

| 字段 | 说明 |
|---|---|
| name / description | 向量标识与覆盖点 |
| publicKeyHex | 静态接收方公钥,65B 非压缩(04 前缀,X/Y 各 32B) |
| ephemeralDHex | 本次加密使用的临时私钥标量(= 回放块) |
| ephemeralPublicKeyHex | V = k·G,即密文前 65 字节 |
| plaintextByteLen / plaintextHex | 明文长度与十六进制(空串向量为空字符串,总长 85B 边界) |
| sharedSecretHex | V 连接 Z;Z = x(k·Y) 左填充定长 32B(**V 在前**) |
| kdfDerivedKeyHex | KDF2-SHA1 全量输出 16+len(pt) 字节:前 16B 为 MAC key,其余为 XOR keystream |
| macTagHex | HMAC-SHA1(K 前 16B,C 连接 8 个 0x00 的长度标签),20B 不截断 |
| cipherBase64Std | 标准字母表 Base64(带填充)= Java Base64Util.encodeToString |
| cipherHex | 同一密文的十六进制形态,避免 base64 歧义 |
| expectedTotalLen | 恒为 65 + len(pt) + 20(空串向量即 85) |

覆盖面:空串 / 短 ASCII(test_token,与 SecureUtil.main 同款)/ 中文 UTF-8 /
全 0xFF 共 16 字节 / 单字节 0x00 / 2 236 B 中英混合长文本。

kdf2Vectors 共 5 条:name、description、sharedSecretHex(独立输入)、outLen(16/20/21/41/80)、expectedKHex。
规则:block_i = SHA1(shared 连接 be32(i)),计数 i 从 1 起(bcprov BaseKDFBytesGenerator.counterStart=1)。

### 3.2 canonjson_cases.json

顶层:ruleSummary(R1~R9 文字版)+ cases[],共 15 条。每条字段:name、purpose、inputDescription、
canonicalJson(**期望输出,精确到字符的手写常量**)、note(移植注意点)。

用例覆盖:键升序(扁平 / 大小写敏感码元序 / 嵌套递归)、HTML 字符不转义(< > & ' / 全原样)、
null 属性省略(NON_NULL)、数组内 null 保留、整型不漂移(Integer/Long/负数)、中文 UTF-8 原样混排、
空 map、空字符串键值、引号反斜杠转义、控制字符转义形态(0x0B 输出为文本形式的「反斜杠+u+000B」,
十六进制字母大写——这是 Go 移植最易踩的差异)、斜杠原样、布尔与数字字符串、补平面字符(emoji)原样输出。

### 3.3 headers_golden.json

顶层 _meta.notes(六头规则摘要)+ entries[],共 3 条:

| 字段 | 说明 |
|---|---|
| name / scenario | 组名与调用场景(risk 带 eventType 路径参;案件查询无路径参) |
| clientId / clientSecret / clientVersion | 凭证夹具 |
| signInputs.sortedSignJson | 参与签名的升序 JSON(手写常量) |
| signInputs.sha512HexLowerOfSignJson | 小写 hex 的 sha512,这 128 个 ASCII 字符本身就是 ECIES 明文 |
| signatureBase64Std(entry 与 signInputs 各一份,等价) | 标准 Base64 的 X-SIGNATURE |
| authorizationBase64url / riskBasicBase64url | URL-safe 字母表且**带填充等号**(不是标准 Basic 字母表) |
| headerJson | X-RISK-BASIC 解码回读的明文(bean 声明顺序) |
| bodyJson | 剥离 14 键头白名单后的剩余体(risk 样例最直观) |
| secretFieldsUsed 等 | risk 样例独有:敏感字段明文/密文对照 |
| headers | 最终六头:Content-Type/X-RISK-MODE/X-SIGNATURE/Authorization/X-RISK-BASIC/X-User-Id |

三条样例:案件查询 7 键签名输入、同步问询 19 键签名输入(含敏感字段密文)、非 ASCII bizId 案件查询。

### 3.4 case_payload.json

samples[] 共 2 条(普通 bizId + 中文 bizId),逐行对应
com.ex.risk.client.RiskSimpleClient#queryAuditCase(L149-L191)的真实构造链:

* eventType / bizId:方法入参;
* sysFields:DefaultSystemFieldInjector.inject 注入的五键(requestTime(ms,Long)、traceId(UUIDv4)、
  requestIp、clientId、clientVersion);
* sortedSignJson:TreeMap 升序后的签名输入,恒为 7 键:
  bizId < clientId < clientVersion < eventType < requestIp < requestTime < traceId;
* signatureInputs:sha512hex 与 ECIES 后的 X-SIGNATURE 全链路值;
* bodyJson:**HTTP body 只有 eventType 与 bizId 两键** —— 键集合与签名输入不同,绝不能混用;
* bodyKeyOrderNote:Java 版用 Map.of(L159)构造 body,迭代序属 JDK 实现细节,且随进程 SALT 逐次变化
  (Zulu 11 跨进程实测两种键序都出现);服务端按 JSON 解析任何键序等价,golden 固定取升序规范形态;
* headerJson:X-RISK-BASIC 明文;userId 是 bean 默认值 UNKNOWN(requestMap 里没有 userId,
  hutool BeanUtil.copyProperties 不会覆盖默认值)。

---

### 3.5 名单外部上报接入指南（接入方视角，ReportWatchList）

外部系统把识别到的恶意对象（IP、账号、设备、链上地址等）上报给风控，自动进入黑/白名单并秒级生效，
到期自动失效。接入方只调 SDK 一个方法，加密、签名、协议头全部由 SDK 内部完成。

#### 前置条件

向风控研发索取三样东西，填进**现有** `Config`（与同步问询 `Risk()` 同一份配置，**零新增配置项**）：

| 配置项 | 说明 |
|---|---|
| `BaseURL` | 风控网关地址（http/https 绝对地址） |
| `ClientID` / `ClientSecret` | 接入方 M2M 凭证（风控侧登记后发放；未登记的 clientId 一律拒绝） |
| `PublicKey` | 网关公钥（PEM 或 Base64 SPKI），用于加密与签名 |

可写哪些名单类别、对象类型、默认有效期，由风控侧按 clientId 登记配置，接入前与风控研发确认。

#### 方法签名

```go
func (c *Client) ReportWatchList(ctx context.Context, items []WatchListReport) (*WatchListReportResult, error)

type WatchListReport struct {
    ObjectType string // 对象类型，如 "ip"；非空。不限类型：账号/设备/地址等名单可承载的值均可
    ListType   string // "black" | "white"；非空
    ItemValue  string // 对象值明文；非空。SDK 固定 ECIES 加密后上送，密文参与签名
    Reason     string // 上报原因，必填非空（审计溯源）；SDK 加密后上送，空白本地预检拒绝
    TtlMinutes int64  // 建议有效期（分钟），可选；<=0 或不传 = 不提建议，按风控侧默认 TTL
}
```

- `items` 不能为空、每条 `Reason` 必填非空（本地预检直接报错，不发请求）。
- **1→N**：风控侧可为同一 (对象类型, 名单类别) 登记多个目标名单（不同场景引用不同名单），
  一条上报自动写入全部命中名单，接入方无感知、无需逐名单调用。
- 有效期语义：**生效 TTL = min(风控侧默认 TTL, 建议时长)**；外部写入一律带限期，不支持永久。
  默认 TTL 当前为 24 小时（风控侧可按来源/名单类别调整，免发版生效）。
- 同一对象重复上报 = 续期（只延长不缩短）；已被风控人工禁用的对象再上报不会复活。
- 单批 items 上限默认 100（风控侧可配），超出整批拒绝。上报为告警级低频调用，勿批量刷量。
- 固定 10s 超时上限，调用方可用 `ctx` 收紧；不走 `EventTimeoutMs` 事件超时表。

#### 回执与错误语义（单轨契约，与 Risk() 不同）

`error` 涵盖：本地预检失败、网络失败/超时、一切非 200（含网关 401 鉴权失败、429 限流）。
**HTTP 200 内的逐条 REJECTED 是合法回执，不是 error**——单条被拒不拖累同批其他条目。

```go
type WatchListReportReceipt struct {
    ObjectType, ListType, ItemValue string // 身份三字段回显自入参明文（服务端只回 sha512 摘要，不回明文）
    Result  string // 四态，见下表
    Message string // REJECTED 时为拒绝原因码
}
```

| Result | 含义 | 接入方动作 |
|---|---|---|
| `SAVED` | 新写入，已生效 | 正常 |
| `EXTENDED` | 已存在，有效期已延长 | 正常（重复上报的预期回执） |
| `EXISTED` | 已存在但未延长（建议时长未更晚/人工禁用不动） | 正常，无需重试 |
| `REJECTED` | 该条被拒 | 看 `Message` 原因码，修正后再报 |

回执按上报项笼统聚合（1→N 时一条上报写多个名单）：**任一名单写入成功即成功态**
（取 SAVED>EXTENDED>EXISTED），全部失败才 REJECTED（首个原因码）。能写的写，
写不进的只落风控侧日志与告警，无整体事务、**不回滚已成功的写入**；
续期式写入幂等，原样重试无害；逐名单明细在风控侧日志，接入方无需关心。

常见拒绝原因码：`unauthorized`（clientId 未登记/对象类型+名单类别映射缺失）、
`decrypt_failed`（密文损坏或公钥不配）、`invalid`（reason 空/字段超长等）、`invalid_ttl`（TTL 配置非法）、
`batch_limit`（整批超上限）、`signature_failed`（验签失败，整批拒）、
`watch_code_not_found`（风控侧映射指向的名单不存在，找风控研发核对配置）、
`write_failed`（风控侧写入意外异常如 DB 抖动，原样重试即可）。
回执条数与入参不符时 SDK 报错（契约违约，宁拒不猜）。

#### 完整示例

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    riskclient "github.com/decodeex/risk-client-go"
)

func main() {
    client, err := riskclient.New(riskclient.Config{
        BaseURL:      "https://<风控网关地址>", // 找风控研发要
        ClientID:     "<clientId>",
        ClientSecret: "<clientSecret>",
        PublicKey:    "<网关公钥>",
    })
    if err != nil {
        log.Fatalf("SDK 初始化失败: %v", err) // 凭证/公钥缺配在这里拦截
    }

    ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
    defer cancel()

    res, err := client.ReportWatchList(ctx, []riskclient.WatchListReport{
        {
            ObjectType: "ip",
            ListType:   "black",
            ItemValue:  "203.0.113.66",
            Reason:     "恶意扫描告警",
            // TtlMinutes 不传 = 按风控侧默认 TTL（当前 24 小时）
        },
    })
    if err != nil {
        // 本地预检/网络/超时/401/429 等非 200 都在这里
        log.Fatalf("上报名单失败: %v", err)
    }
    for _, r := range res.Items {
        fmt.Printf("%s %s -> %s %s\n", r.ListType, r.ItemValue, r.Result, r.Message)
        if r.Result == riskclient.WatchListResultREJECTED {
            // 按 Message 原因码处理，勿原样重试
        }
    }
}
```

#### 门禁向量说明（内部）

原 `testdata/watchlist_report_vectors.json`（嵌套 items 逐字节门禁向量，spec 任务 3.2）
已于 11-17 删除。`GenVectors.java` 仍会生成该文件——需要重建门禁 KAT 时重跑本脚本即可再生成，
重建步骤见 `.kiro/specs/watch-list-external-input/tasks.md` 3.2 与 Implementation Notes
（须按 request.go 的 buildRiskCore 注入模式给 BuildWatchListReportRequest 加重放缝）。

---

## 四、规范 JSON 规则速查(Go 侧必须按此实现)

| # | 规则 |
|---|---|
| R1 | 键升序 = String.compareTo = UTF-16 码元序;嵌套对象递归同规则 |
| R2 | 紧凑分隔:逗号与冒号后没有空格;数组同理 |
| R3 | 必要转义仅三类:双引号与反斜杠各加一个反斜杠前缀;控制字符里 0x08→`\b`、0x09→`\t`、0x0A→`\n`、0x0C→`\f`、0x0D→`\r`,其余小于 0x20 的写成「反斜杠 + u + 四位十六进制」且**字母大写**(Jackson 实测 char 0x0B 输出为文本形式的 backslash-u-000B)。Go encoding/json 缺省是小写 → 必须自实现转义器 |
| R4 | 不做 HTML 转义:< > & ' / 全部原样;0x7F、U+2028、U+2029 也原样(Go 会恒定转义 U+2028/U+2029,Jackson 不会) |
| R5 | map/bean 属性值为 null → 键整个省略(Jackson NON_NULL);数组内的 null 元素保留 |
| R6 | Integer/Long 十进制整数,无小数点,负数带负号 |
| R7 | 空 map 序列化为 {} |
| R8 | 输出首尾无换行、无空白(签名字符串绝不允许带尾随换行) |
| R9 | 非 ASCII 原样输出 UTF-8 字节,不做任何 u 转义 |

---

## 五、"手写常量"声明(重要)

GenVectors.java 里所有规范 JSON 期望串(CANON_Cxx_*、SIGN_JSON_*、HEADER_JSON_*、BODY_JSON_*)
都是**人工书写并锁定的字符串常量**,不是任何库算出来的产物。依据有两层:

1. research.md / design.md 已从 Java 源码核实的规则(R1~R9);
2. 开发期用 risk-client 同款依赖(Jackson 2.13.5 + hutool 5.8.25,均来自本机 gradle 缓存)实测核对:
   bean 属性顺序、NON_NULL 行为、HTML 字符不转义、控制字符大写十六进制、DEL 与 U+2028 原样、Map.of 顺序。

运行期的 canonical()/orderedJson() 是**第二套独立实现的反向校验**:任何人改坏手写常量或改变规则理解,
脚本都会红掉。这使向量既保住"手抄字节真值"的本源,又经得起算法复核。

## 六、已知边界(不在向量内,但 Go 要知道)

* 排序语义差异:Java TreeMap 按 UTF-16 码元序,Go 按字节序。ASCII 与常用 BMP 中日韩字符两边一致;
  含增补平面字符(emoji)的**键**理论上顺序不同——协议约定业务键只用 ASCII(文档声明,不做特殊处理)。
* U+2028 / U+2029:Jackson 原样输出、Go 强制转义,协议键值不应出现这两个字符。
* DEL(0x7F):两边都原样,勿画蛇添足。
* 同毫秒并发导致 requestTime 相同属业务层问题,与协议无关。

## 七、与 Java 源码的对照清单(改动需重跑向量)

| Java 位置 | 对应向量 |
|---|---|
| utils/SecureUtil.java L173-L184(Cipher.getInstance("ECIES","BC") 无参) | ecies_vectors.json 全部 |
| client/support/DefaultRiskSigner.java(DigestUtil.sha512Hex → eccEncrypt) | headers / case_payload 的 X-SIGNATURE |
| utils/JsonUtil.java(Jackson 2.13.5,NON_NULL) | canonjson_cases.json 全部与 header/body 字符串 |
| client/support/DefaultSystemFieldInjector.java(注入五键) | case_payload.json 的 sysFields |
| client/RiskSimpleClient.java L149-L191(queryAuditCase)与 L298-L307(buildHeaders) | headers_golden.json、case_payload.json |
| client/support/RiskRequestBuilder.java(合并/加密/Treemap 签名/剥头成 body) | headers_golden.json 第 2 条 |
