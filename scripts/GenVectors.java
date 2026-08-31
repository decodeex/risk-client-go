import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * ============================================================================
 *  GenVectors —— Java 侧 golden 向量生成器(风控 SDK 协议测试的"标准答案")
 * ============================================================================
 *
 * 【目的】把 BouncyCastle 1.70 无参 ECIES、sha512 签名链、TreeMap 规范 JSON、
 *         六个请求头的真实字节行为固定下来,供 Go 版 internal/protocol 逐字节回归。
 *         输出四个文件:testdata/{ecies_vectors, canonjson_cases, headers_golden, case_payload}.json
 *
 * 【运行】javac -encoding UTF-8 -cp <bcprov-jdk15on-1.70.jar> GenVectors.java
 *         java  -cp .:<bcprov-jdk15on-1.70.jar> GenVectors [输出目录,缺省 ../testdata]
 *         只依赖 JDK11 + bcprov-jdk15on-1.70(-encoding UTF-8 必须带,源码里有中文样本);
 *         不需要 hutool/Jackson/commons-lang3 —— 规范 JSON 的期望值是手工常量(见下)。
 *
 * 【确定性机制(两件套,详见 scripts/README.md)】
 *   1. 静态密钥对:P-256 私钥标量写成常量,popcount=168 且 NAF 权重=79(高于 BC 生成器
 *      minWeight=64 的筛选下限 → 结构上远离退化边界)。公私钥运行期用最小 DER 编码器重建,
 *      并断言 SPKI/PKCS8 与常量逐字节相同。
 *   2. ephemeral 回放:Cipher.init(ENCRYPT_MODE, publicKey, 自定义 SecureRandom),
 *      该 SecureRandom.nextBytes 永远回填同一块 32 字节。BC IESEngine 加密前用
 *      ECKeyPairGenerator 抽临时标量(BigInteger(256, rnd) 恰好一次 nextBytes 抽满 32 字节),
 *      因此能稳定拿回同一个 ephemeral k —— 常量 EPHE_PATTERN_HEX 本身就是它。
 *
 * 【真实对照源(改动必须重跑本脚本并提交新向量)】
 *   utils/SecureUtil.java                 Cipher.getInstance("ECIES","BC")(无参)
 *   client/support/DefaultRiskSigner.java sign(sortedJson)=eccEncrypt(pub, sha512HexLower(sortedJson))
 *   utils/JsonUtil.java                   Jackson 2.13.5,NON_NULL,无 HTML 转义
 *   client/support/DefaultSystemFieldInjector.java
 *   client/RiskSimpleClient.java          queryAuditCase / buildHeaders(L298-L307)
 *   client/support/RiskRequestBuilder.java  risk 主路径(TreMap→签名、剥头字段成 body)
 */
public class GenVectors {

    // =========================================================================
    // 一、固定密钥材料与夹具常量(全部写死,禁止读时钟/网卡/环境变量)
    // =========================================================================

    /** 静态接收方私钥(P-256 标量,d < n):
     *  popcount=168("高 popcount"),NAF 权重=79 > BC ECKeyPairGenerator 的 minWeight=n.bitLength()/4=64。
     *  注意不是盲目堆置位:全 0xFE×32 这类 popcount=224 的解 NAF 权重只有 33,反而是会被加密器拒收的低权重特殊标量。 */
    static final String D_STATIC_HEX =
            "afcfa7cf5efda8bf6f9ecbf55fb8adfe7f68cdfa9efdb86f3e78cb51fc69bd86";

    /** 对应公钥点(65B 非压缩),从 d 现场重算后必须与该常量一致(防 DER 组装被改坏)。 */
    static final String PUB_UNCOMPRESSED_HEX =
            "0421726ceb323c768bd064a73439f7d90acf6a791c8aab449c43023211f96876c2bf7dc36e7f9bedd16f3057f3e02bad43fae8b37e5ac614f67708aec26a6fd303";

    /** 公钥的 X.509 SubjectPublicKeyInfo(Base64 标准字母表)= 生产配置里 publicKey 字符串的形态。 */
    static final String PUB_SPKI_BASE64_EXPECTED =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIXJs6zI8dovQZKc0OffZCs9qeRyKq0ScQwIyEflodsK/fcNuf5vt0W8wV/PgK61D+uizflrGFPZ3CK7Cam/TAw==";

    /** 私钥 PKCS#8 编码(SecureUtil.loadPrivateKey 同款解析方式)。 */
    static final String PRI_PKCS8_BASE64_EXPECTED =
            "ME0CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEMzAxAgEBBCCvz6fPXv2ov2+ey/VfuK3+f2jN+p79uG8+eMtR/Gm9hqAKBggqhkjOPQMBBw==";

    /** ephemeral 回放块(32 字节):每次加密抽到的临时标量(NAF 权重 103,一次过筛,不会死循环)。 */
    static final String EPHE_PATTERN_HEX =
            "970a950aa9950d348ac8c4ce7aa977e76a49a93b346ecb9969baae4a6d333045";

    // ---- 夹具 A:案件查询(kyc_general_case) ----
    static final String CLIENT_ID_A = "test-client-id";
    static final String CLIENT_SECRET_A = "test-client-secret";
    static final String EVENT_TYPE_A = "kyc_general_case";
    static final String BIZ_ID_A = "GB20260827093000001";
    static final long REQUEST_TIME_A = 1756272000000L;
    static final String TRACE_ID_A = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
    static final String REQUEST_IP_A = "192.168.1.100";
    static final String CLIENT_VERSION = "1.0.7";                       // 对齐 Java 版硬编码

    // ---- 夹具 B:同步问询(payment_risk_check,含敏感字段置换) ----
    static final String CLIENT_ID_B = "risk-demo-client";
    static final String CLIENT_SECRET_B = "s3cr3t-Demo-Key#2026";
    static final String USER_ID_B = "u_80001";
    static final long REQUEST_TIME_B = 1756272001500L;
    static final String TRACE_ID_B = "d9428888-1222-4a2b-a97c-91dbcd123456";
    static final String REQUEST_IP_B = "10.20.30.40";
    static final String SECRET_FIELD_PLAINTEXT = "user@example.com";

    // ---- 夹具 C:案件查询第二样例(非 ASCII bizId) ----
    static final String EVENT_TYPE_C = "kyb_merchant_case";
    static final String BIZ_ID_C = "店铺订单-20260827-00042";
    static final long REQUEST_TIME_C = 1756272010000L;
    static final String TRACE_ID_C = "5d5f4b6f-1111-4bbb-8ccc-92abdc999888";

    /**
     * 同步问询样例里敏感字段(email)期望密文。首跑时脚本会打印建议值,固化到这里之后,
     * 后续任何人改坏 ECIES 实现都会在此断言爆红(仓库自带回归闸门)。
     */
    static final String SECRET_FIELD_CIPHER_BASE64_STD_EXPECTED =
            "BH/k3SrZpkdAbkovllYu1ydj9fIhgPZP3yAFidQJQvRWFb7yiyKxyuyFXOos+jtLkIFRq3x1ylOwL0O1ZAph76LXJUFuISB0gVL01VdqYwNASvfCdIptOUkdzjo1sqm8DVLC4vk=";

    /** 首跑占位符开关:为 true 时不做密文常量比对(第一次生成时跳过)。 */
    static boolean secretCipherConstantPending() {
        return SECRET_FIELD_CIPHER_BASE64_STD_EXPECTED.startsWith("PLACEHOLDER");
    }

    // =========================================================================
    // 二、手写锁定的规范 JSON 期望串(canonjson_cases / headers / case_payload)
    // =========================================================================
    //
    // 这些 *_EXPECTED 全部是【手工书写】的字符串字面量,而不是脚本算出来的产物。
    // 规则依据(research.md「Java risk-client 代码库探索」与 design.md internal/protocol 章节,
    // 并在本地用 risk-client 同款 Jackson 2.13.5 + hutool 5.8.25 实测逐条核对过):
    //
    //   R1 键升序 = String.compareTo(UTF-16 码元序);嵌套对象递归同规则
    //   R2 紧凑:"k":"v"、逗号与冒号后均无空格;数组同理
    //   R3 必要转义仅三类:0x22→\" ;0x5C→\\ ;控制字符取 0x08→\b、0x09→\t、0x0A→\n、
    //      0x0C→\f、0x0D→\r,其余写成 \\u00XX 且十六进制字母【大写】
    //      (实测:char 0x0B → "\\u000B"、0x1F → "\\u001F"。Go 缺省小写,需要自己写转义器!)
    //   R4 不做 HTML 转义:<、>、&、'、/ 原样;0x7F、U+2028、U+2029 也原样
    //      (Go encoding/json 会恒定转义 U+2028/2029,Jackson 不会 —— 协议键值别出现这两个字符)
    //   R5 值为 null 的键省略(Jackson JsonInclude.Include.NON_NULL);
    //      数组内部的 null 元素保留(实测 {"list":[null,"keep",null]})
    //   R6 整型(Integer/Long)不带小数点;负数带负号
    //   R7 空 map 序列化为 {}
    //   R8 输出首尾无换行、无缩进(writeValueAsString 不追加换行)
    //   R9 非 ASCII 原样输出 UTF-8,不做 \\uXXXX 转义
    //
    // 为防手抄笔误,main 里把每条期望串与本脚本内置的独立规则实现 canonical()/orderedJson()
    // 交叉断言 —— 两边不一致立即抛异常退出。

    static final String CANON_C01_FLAT_SORTED =
            "{\"bizId\":\"1001\",\"event\":\"login\",\"userId\":\"u_01\"}";

    /** 大小写敏感的码元排序:'A'(0x41) < 'T'(0x54) < 'a'(0x61) < 'b'(0x62)。 */
    static final String CANON_C02_CASE_ORDER =
            "{\"Alpha\":\"A1\",\"Type\":\"T1\",\"alpha\":\"a1\",\"beta\":\"b1\"}";

    static final String CANON_C03_NESTED_SORT =
            "{\"a\":[1,2,3],\"b\":{\"x\":{\"inner\":\"v\"},\"y\":2}}";

    /** 关键差异面:Jackson 绝不转义 <、>、&(Go 默认会)。 */
    static final String CANON_C04_HTML_RAW =
            "{\"lt_gt_amp\":\"< > &\",\"script\":\"<script>&amp;</script>\"}";

    static final String CANON_C05_NULL_OMITTED = "{\"b\":\"keep\"}";

    /** NON_NULL 只影响属性,数组里的 null 元素保留。 */
    static final String CANON_C06_NULL_IN_ARRAY = "{\"list\":[null,\"keep\",null]}";

    static final String CANON_C07_INT_TYPES =
            "{\"intVal\":42,\"longMs\":1756272000000,\"negInt\":-7}";

    /** 排序:mixed_zh(ASCII)< 事件类型(U+4E8B)< 姓名(U+59D3)。 */
    static final String CANON_C08_CHINESE_UTF8 =
            "{\"mixed_zh\":\"中文abc\",\"事件类型\":\"登录\",\"姓名\":\"张三\"}";

    static final String CANON_C09_EMPTY_MAP = "{}";

    static final String CANON_C10_EMPTY_KEY_VALUE = "{\"\":\"\"}";

    static final String CANON_C11_QUOTES_BACKSLASH =
            "{\"bs\":\"C:\\\\path\\\\\",\"quoted\":\"he said \\\"hi\\\"\"}";

    /** 控制字符 Jackson 形态:\b、\t、\n 用短形;其余 \\u00XX 且大写十六进制。
     *  键序同样升序:bell < nl < tab < u0001 < u000b < u001f。 */
    static final String CANON_C12_CONTROL_CHARS =
            "{\"bell\":\"\\b\",\"nl\":\"\\n\",\"tab\":\"\\t\",\"u0001\":\"\\u0001\","
                    + "\"u000b\":\"\\u000B\",\"u001f\":\"\\u001F\"}";

    static final String CANON_C13_SLASH_RAW =
            "{\"url\":\"https://gw/risk?x=1&y=2\"}";

    static final String CANON_C14_BOOL_MIX =
            "{\"no\":false,\"numStr\":\"123\",\"ok\":true}";

    /** 补平面字符(surrogate pair)原样输出:😀 = U+1F600。 */
    static final String EMOJI = new StringBuilder().appendCodePoint(0x1F600).toString();
    static final String CANON_C15_EMOJI_VALUE =
            "{\"emoji\":\"" + EMOJI + " ok " + EMOJI + "\",\"plain\":\"hi\"}";

    // ---- 案件查询 A(kyc_general_case)----
    /** 签名输入 = TreeMap(requestMap) 的规范 JSON(requestMap = eventType/bizId + 注入五键)。 */
    static final String SIGN_JSON_CASE_A =
            "{\"bizId\":\"GB20260827093000001\",\"clientId\":\"test-client-id\",\"clientVersion\":\"1.0.7\","
                    + "\"eventType\":\"kyc_general_case\",\"requestIp\":\"192.168.1.100\","
                    + "\"requestTime\":1756272000000,\"traceId\":\"3fa85f64-5717-4562-b3fc-2c963f66afa6\"}";

    /** X-RISK-BASIC 明文:hutool BeanUtil.copyProperties(map, RiskRequestHeader.class) + Jackson。
     *  属性顺序【父类字段在前、子类字段在后】,各自按声明顺序(bizId,userId,platform,eventType,
     *  fingerToken,ip,bizTime,tenantId,siteType | traceId,requestIp,requestTime,clientVersion,clientId);
     *  platform/fingerToken/ip/bizTime 未赋值为 null 被 NON_NULL 省略;
     *  userId 是 bean 的默认初始化值 "UNKNOWN"(requestMap 里没有 userId,copyProperties 不会覆盖它)。 */
    static final String HEADER_JSON_CASE_A =
            "{\"bizId\":\"GB20260827093000001\",\"userId\":\"UNKNOWN\",\"eventType\":\"kyc_general_case\","
                    + "\"tenantId\":\"default\",\"siteType\":\"default\","
                    + "\"traceId\":\"3fa85f64-5717-4562-b3fc-2c963f66afa6\",\"requestIp\":\"192.168.1.100\","
                    + "\"requestTime\":1756272000000,\"clientVersion\":\"1.0.7\",\"clientId\":\"test-client-id\"}";

    /** HTTP body = JsonUtil.toJson(Map.of("eventType",..,"bizId",..))(RiskSimpleClient.java:159)。
     *  Map.of 迭代序是 ImmutableCollections.MapN 的哈希结果(逐进程随机漂移,Zulu 11 实测 17/40 与 23/40 两种序都出现);
     *  这里恰好也是升序形态,两种记法一致,并非协议承诺。 */
    static final String BODY_JSON_CASE_A =
            "{\"bizId\":\"GB20260827093000001\",\"eventType\":\"kyc_general_case\"}";

    // ---- 案件查询 C(非 ASCII bizId)----
    static final String SIGN_JSON_CASE_C =
            "{\"bizId\":\"店铺订单-20260827-00042\",\"clientId\":\"test-client-id\",\"clientVersion\":\"1.0.7\","
                    + "\"eventType\":\"kyb_merchant_case\",\"requestIp\":\"192.168.1.100\","
                    + "\"requestTime\":1756272010000,\"traceId\":\"5d5f4b6f-1111-4bbb-8ccc-92abdc999888\"}";

    static final String HEADER_JSON_CASE_C =
            "{\"bizId\":\"店铺订单-20260827-00042\",\"userId\":\"UNKNOWN\",\"eventType\":\"kyb_merchant_case\","
                    + "\"tenantId\":\"default\",\"siteType\":\"default\","
                    + "\"traceId\":\"5d5f4b6f-1111-4bbb-8ccc-92abdc999888\",\"requestIp\":\"192.168.1.100\","
                    + "\"requestTime\":1756272010000,\"clientVersion\":\"1.0.7\",\"clientId\":\"test-client-id\"}";

    static final String BODY_JSON_CASE_C =
            "{\"bizId\":\"店铺订单-20260827-00042\",\"eventType\":\"kyb_merchant_case\"}";

    // =========================================================================
    // 三、工具:JSON 渲染 / 规范化器 / 有序对象拼装 / DER / ECIES 复算
    // =========================================================================

    /** 极简 JSON 渲染器:2 空格缩进、插入序稳定、非 ASCII 原样(文件整体 UTF-8)。 */
    static class Json {
        @SuppressWarnings("unchecked")
        static void render(StringBuilder sb, Object o, int indent) {
            String pad = repeat(' ', indent);
            if (o == null) { sb.append("null"); return; }
            if (o instanceof String) { str(sb, (String) o); return; }
            if (o instanceof Boolean || o instanceof Number) { sb.append(o.toString()); return; }
            if (o instanceof Map) {
                Map<String, Object> m = (Map<String, Object>) o;
                sb.append("{\n");
                int i = 0;
                for (Map.Entry<String, Object> e : m.entrySet()) {
                    sb.append(pad).append("  ");
                    str(sb, e.getKey());
                    sb.append(": ");
                    render(sb, e.getValue(), indent + 2);
                    if (++i < m.size()) sb.append(",");
                    sb.append("\n");
                }
                sb.append(pad).append("}");
                return;
            }
            if (o instanceof List) {
                List<Object> l = (List<Object>) o;
                if (l.isEmpty()) { sb.append("[]"); return; }
                sb.append("[\n");
                for (int i = 0; i < l.size(); i++) {
                    sb.append(pad).append("  ");
                    render(sb, l.get(i), indent + 2);
                    if (i < l.size() - 1) sb.append(",");
                    sb.append("\n");
                }
                sb.append(pad).append("]");
                return;
            }
            throw new IllegalArgumentException("unsupported type: " + o.getClass());
        }

        /** 仅做 JSON 强制转义(<0x20 与引号反斜杠),大小写风格无所谓 —— 外层文档包裹层,
         *  与协议无关;canonicalValue 里另有按 Jackson 规则的版本。 */
        static void str(StringBuilder sb, String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    case '\b': sb.append("\\b"); break;
                    case '\f': sb.append("\\f"); break;
                    default:
                        if (c < 0x20) sb.append(String.format("\\u%04X", (int) c)); // 与 Jackson 一致:控制字符转义的十六进制字母大写
                        else sb.append(c);
                }
            }
            sb.append('"');
        }

        static String repeat(char c, int n) {
            char[] arr = new char[n];
            Arrays.fill(arr, c);
            return new String(arr);
        }
    }

    static String renderDoc(Object o) {
        StringBuilder sb = new StringBuilder();
        Json.render(sb, o, 0);
        sb.append('\n');
        return sb.toString();
    }

    /**
     * 独立的"规则版"规范化序列化器(R1~R8):只用于交叉校对手写常量,不作为期望值的来源。
     * 注意 null 处理:根层级与其余 map 层级一样省略 null(实测 Jackson 行为一致)。
     */
    static String canonical(Map<String, Object> input) {
        StringBuilder sb = new StringBuilder("{");
        boolean f = true;
        for (Map.Entry<String, Object> e : new TreeMap<>(input).entrySet()) {
            if (e.getValue() == null) continue;                      // R5:NON_NULL
            if (!f) sb.append(",");
            f = false;
            Json.str(sb, e.getKey());
            sb.append(":");
            canonicalValue(sb, e.getValue());
        }
        return sb.append("}").toString();
    }

    @SuppressWarnings("unchecked")
    static void canonicalValue(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }                 // 仅数组元素会走到这里
        if (v instanceof Map) {
            sb.append("{");
            boolean f = true;
            for (Map.Entry<String, Object> e : new TreeMap<>((Map<String, Object>) v).entrySet()) {
                if (e.getValue() == null) continue;                  // R5:NON_NULL 同样作用于嵌套属性
                if (!f) sb.append(",");
                f = false;
                Json.str(sb, e.getKey());
                sb.append(":");
                canonicalValue(sb, e.getValue());
            }
            sb.append("}");
            return;
        }
        if (v instanceof List) {
            sb.append("[");
            boolean f = true;
            for (Object item : (List<Object>) v) {
                if (!f) sb.append(",");
                f = false;
                canonicalValue(sb, item);
            }
            sb.append("]");
            return;
        }
        if (v instanceof Boolean || v instanceof Integer || v instanceof Long) { sb.append(v.toString()); return; }
        Json.str(sb, (String) v);
    }

    /** 按【给定顺序】拼一个 JSON 对象(不排序):用于复刻 bean 序列化的 X-RISK-BASIC 明文。
     *  值为 null 的键直接跳过(NON_NULL);数字不加引号。 */
    static String orderedJson(Object[][] pairs) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Object[] pair : pairs) {
            Object v = pair[1];
            if (v == null) continue;
            if (!first) sb.append(",");
            first = false;
            Json.str(sb, (String) pair[0]);
            sb.append(":");
            if (v instanceof Long || v instanceof Integer) sb.append(v.toString());
            else Json.str(sb, (String) v);
        }
        return sb.append("}").toString();
    }

    // ----------------------- 极小 DER 编码器(装载选定的 d) -----------------------

    static byte[] tlv(int tag, byte[] val) {
        ByteArrayOutputStream len = new ByteArrayOutputStream();
        if (val.length < 128) len.write(val.length);
        else {
            byte[] tmp = BigInteger.valueOf(val.length).toByteArray();
            if (val.length >= 256 && tmp[0] == 0) tmp = Arrays.copyOfRange(tmp, 1, tmp.length);
            len.write(0x80 | tmp.length);
            len.write(tmp, 0, tmp.length);
        }
        byte[] lb = len.toByteArray();
        byte[] out = new byte[1 + lb.length + val.length];
        out[0] = (byte) tag;
        System.arraycopy(lb, 0, out, 1, lb.length);
        System.arraycopy(val, 0, out, 1 + lb.length, val.length);
        return out;
    }

    static byte[] concat(byte[]... xs) {
        int n = 0;
        for (byte[] x : xs) n += x.length;
        byte[] o = new byte[n];
        int k = 0;
        for (byte[] x : xs) { System.arraycopy(x, 0, o, k, x.length); k += x.length; }
        return o;
    }

    static byte[] strip(BigInteger v) {
        byte[] r = v.toByteArray();
        if (r.length > 1 && r[0] == 0) return Arrays.copyOfRange(r, 1, r.length);
        return r;
    }

    static final byte[] OID_EC_PUBLIC_KEY = {(byte) 0x06, 0x07, (byte) 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01};
    static final byte[] OID_PRIME256V1 = {(byte) 0x06, 0x08, (byte) 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};

    static PublicKey loadPubSpki(String b64) throws Exception {
        return KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }

    static PrivateKey loadPrivPkcs8(String b64) throws Exception {
        return KeyFactory.getInstance("EC", "BC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }

    // ------------------------------ 随机数回放 --------------------------------

    /** 每次 nextBytes 都填同一块:BC 抽临时标量因此完全确定。 */
    static class ReplayRandom extends SecureRandom {
        private final byte[] pattern;

        ReplayRandom(byte[] pattern) { this.pattern = pattern.clone(); }

        @Override public void nextBytes(byte[] buf) {
            int filled = 0;
            while (filled < buf.length) {
                int take = Math.min(pattern.length, buf.length - filled);
                System.arraycopy(pattern, 0, buf, filled, take);
                filled += take;
            }
        }
    }

    // ------------------------- 生产同款加密 & 手工复算 -------------------------

    static byte[] jcaEcies(PublicKey pub, byte[] plain, SecureRandom rnd) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");               // 生产代码 SecureUtil.encrypt 同款无参调用
        cipher.init(Cipher.ENCRYPT_MODE, pub, rnd);
        return cipher.doFinal(plain);
    }

    /** 参数模型复算:V(65) ‖ C ‖ T(20)。任何一项和 JCA 不一致都说明参数理解有误。 */
    static Map<String, byte[]> manualEcies(ECDomainParameters dom, byte[] pointRecipient,
                                           BigInteger dEphemeral, byte[] plain) throws Exception {
        ECDHBasicAgreement agree = new ECDHBasicAgreement();
        agree.init(new ECPrivateKeyParameters(dEphemeral, dom));
        BigInteger z = agree.calculateAgreement(
                new ECPublicKeyParameters(dom.getCurve().decodePoint(pointRecipient), dom));

        X9ECParameters xp = SECNamedCurves.getByName("secp256r1");
        byte[] V = xp.getG().multiply(dEphemeral).normalize().getEncoded(false);

        byte[] Z = leftPad(z, 32);                                     // 左填充定长 32(≡ BC asUnsignedByteArray(32,z))
        byte[] shared = concat(V, Z);                                  // V 在前!

        KDF2BytesGenerator kdf = new KDF2BytesGenerator(new SHA1Digest());
        kdf.init(new KDFParameters(shared, null));
        byte[] K = new byte[16 + plain.length];                        // macKeySize=128bit
        kdf.generateBytes(K, 0, K.length);

        byte[] macKey = Arrays.copyOfRange(K, 0, 16);                  // 反直觉布局:MAC key 在前
        byte[] keystream = Arrays.copyOfRange(K, 16, K.length);
        byte[] C = new byte[plain.length];
        for (int i = 0; i < plain.length; i++) C[i] = (byte) (plain[i] ^ keystream[i]);

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(macKey, "HmacSHA1"));
        mac.update(C);
        mac.update(new byte[8]);                                       // P2 = null 时的 8 字节长度标签
        byte[] T = mac.doFinal();

        Map<String, byte[]> r = new LinkedHashMap<>();
        r.put("V", V);
        r.put("Z", Z);
        r.put("sharedSecret", shared);
        r.put("kdfKey", K);
        r.put("tag", T);
        r.put("full", concat(V, C, T));
        return r;
    }

    static byte[] leftPad(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        byte[] o = new byte[len];
        int copy = Math.min(raw.length, len);
        System.arraycopy(raw, raw.length - copy, o, len - copy, copy);
        return o;
    }

    static byte[] unhex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return o;
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static String sha512HexLower(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-512").digest(data));
    }

    static void eq(boolean cond, String msg) {
        if (!cond) throw new AssertionError("golden 向量自检失败: " + msg);
    }

    static void eqBytes(byte[] a, byte[] b, String msg) {
        eq(Arrays.equals(a, b), msg + " (left=" + hex(a) + ", right=" + hex(b) + ")");
    }

    static X9ECParameters curve() { return SECNamedCurves.getByName("secp256r1"); }

    static ECDomainParameters domain() {
        return new ECDomainParameters(curve().getCurve(), curve().getG(), curve().getN());
    }

    // =========================================================================
    // 四、主流程
    // =========================================================================

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Path outDir = Paths.get(args.length > 0 ? args[0] : "../testdata").normalize();
        Files.createDirectories(outDir);

        BigInteger dStatic = new BigInteger(1, unhex(D_STATIC_HEX));
        BigInteger dEph = new BigInteger(1, unhex(EPHE_PATTERN_HEX));

        // ---- 4.1 密钥自洽性:DER 现场重建 == 写死的编码常量 == 公钥点常量 ----
        byte[] pointStatic = curve().getG().multiply(dStatic).normalize().getEncoded(false);
        eq(hex(pointStatic).equals(PUB_UNCOMPRESSED_HEX), "静态公钥点与常量不一致");

        byte[] spki = tlv(0x30, concat(tlv(0x30, concat(OID_EC_PUBLIC_KEY, OID_PRIME256V1)),
                tlv(0x03, concat(new byte[]{0}, pointStatic))));
        byte[] sec1 = tlv(0x30, concat(tlv(0x02, new byte[]{1}), tlv(0x04, strip(dStatic))));
        byte[] pkcs8Raw = tlv(0x30, concat(tlv(0x02, new byte[]{0}),
                tlv(0x30, concat(OID_EC_PUBLIC_KEY, OID_PRIME256V1)), tlv(0x04, sec1)));
        eq(Base64.getEncoder().encodeToString(spki).equals(PUB_SPKI_BASE64_EXPECTED), "SPKI 编码漂移");

        // 私钥:PRI_PKCS8_BASE64_EXPECTED 存的是「BC 重编码后的规范形态」——用原始 DER 装载,
        // 再比对 getEncoded(),既验证 DER 可解析又锁定 BC 输出形态。
        PrivateKey priFromRaw = KeyFactory.getInstance("EC", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8Raw));
        eq(Base64.getEncoder().encodeToString(priFromRaw.getEncoded()).equals(PRI_PKCS8_BASE64_EXPECTED),
                "PKCS8 规范编码漂移 computed=" + Base64.getEncoder().encodeToString(priFromRaw.getEncoded()));

        PublicKey pub = loadPubSpki(PUB_SPKI_BASE64_EXPECTED);
        byte[] pointLoaded = ((org.bouncycastle.jce.interfaces.ECPublicKey) pub).getQ().getEncoded(false);
        eqBytes(pointLoaded, pointStatic, "SPKI 解析出的点与期望不符");
        eq(dStatic.bitCount() == 168, "私钥 popcount 应为 168");

        // ---- 4.2 ECIES 向量(JCA 实际加密 == 手工复算 == 可解回读 三重锁定) ----
        List<Map<String, Object>> vectors = new ArrayList<>();
        vectors.add(eciesVector(pointStatic, dEph, pub, "empty_plaintext",
                "空明文边界:密文恒为 65+0+20=85 字节,keystream 为空段", new byte[0]));
        vectors.add(eciesVector(pointStatic, dEph, pub, "short_ascii_test_token",
                "SecureUtil.main 同款短 token 形态", "test_token".getBytes(StandardCharsets.UTF_8)));
        vectors.add(eciesVector(pointStatic, dEph, pub, "chinese_utf8",
                "多字节 UTF-8 明文(加密只做字节级异或,与编码无关)",
                "风控客户端迁移-张三账户#2026".getBytes(StandardCharsets.UTF_8)));
        vectors.add(eciesVector(pointStatic, dEph, pub, "all_ff_16_bytes",
                "全 0xFF 二进制内容(最坏情况字节翻转)", repeat((byte) 0xFF, 16)));
        vectors.add(eciesVector(pointStatic, dEph, pub, "single_byte_00",
                "单字节 0x00:K 长度 17 字节,跨越两个 SHA1 分组(counter=1,2)", new byte[]{0x00}));
        vectors.add(eciesVector(pointStatic, dEph, pub, "long_text_over_1kb",
                ">1KB 中英混合长文本(签名链最常见的载荷尺寸)", longText().getBytes(StandardCharsets.UTF_8)));

        List<Map<String, Object>> kdf2Vectors = new ArrayList<>();
        kdf2Vectors.add(kdf2Vector("kdf_len16_min_mac_only", sharedOf(vectors, "short_ascii_test_token"), 16));
        kdf2Vectors.add(kdf2Vector("kdf_len20_exact_block", sharedOf(vectors, "short_ascii_test_token"), 20));
        kdf2Vectors.add(kdf2Vector("kdf_len21_cross_block_boundary", sharedOf(vectors, "short_ascii_test_token"), 21));
        kdf2Vectors.add(kdf2Vector("kdf_len41_two_blocks_plus_one", sharedOf(vectors, "empty_plaintext"), 41));
        kdf2Vectors.add(kdf2Vector("kdf_len80_from_chinese_vector", sharedOf(vectors, "chinese_utf8"), 80));

        // ---- 4.3 规范 JSON:手写常量 × 内置规则实现 双向对照 ----
        verifyCanonExpectations();

        // ---- 4.4 六头向量(3 组)+ 案件查询载荷(2 组) ----
        List<Map<String, Object>> headerEntries = new ArrayList<>();
        headerEntries.add(headerEntryAudit("audit_case_query_a_kyc_general_case",
                CLIENT_ID_A, CLIENT_SECRET_A, SIGN_JSON_CASE_A, HEADER_JSON_CASE_A, BODY_JSON_CASE_A));
        headerEntries.add(headerEntryRiskB(pub));
        headerEntries.add(headerEntryAudit("audit_case_query_c_nonascii_bizid",
                CLIENT_ID_A, CLIENT_SECRET_A, SIGN_JSON_CASE_C, HEADER_JSON_CASE_C, BODY_JSON_CASE_C));

        // ---- 4.5 写出四个文件 ----
        write(outDir.resolve("ecies_vectors.json"), renderEciesDoc(vectors, kdf2Vectors));
        write(outDir.resolve("canonjson_cases.json"), renderCanonDoc());
        write(outDir.resolve("headers_golden.json"), renderHeadersDoc(headerEntries));
        write(outDir.resolve("case_payload.json"), renderCasePayloadDoc());

        System.out.println();
        System.out.println("[OK] 已生成 4 个 golden 文件到 " + outDir.toAbsolutePath());
        System.out.println("     ecies_vectors.json  : " + vectors.size() + " 条加密向量 + " + kdf2Vectors.size() + " 条 KDF2 中间值");
        System.out.println("     canonjson_cases.json: 15 条规范 JSON 用例");
        System.out.println("     headers_golden.json : " + headerEntries.size() + " 组六头样例");
        System.out.println("     case_payload.json   : 2 组案件查询载荷对照");
    }

    // -------------------------------------------------------------------------
    // 向量构建
    // -------------------------------------------------------------------------

    private static Map<String, Object> eciesVector(byte[] pointStatic, BigInteger dEph, PublicKey pub,
                                                   String name, String desc, byte[] plain) throws Exception {
        byte[] viaJca = jcaEcies(pub, plain, new ReplayRandom(unhex(EPHE_PATTERN_HEX)));
        Map<String, byte[]> manual = manualEcies(domain(), pointStatic, dEph, plain);

        eqBytes(viaJca, manual.get("full"), "JCA 与手工复算不一致(参数模型有误): " + name);
        eq(viaJca.length == 65 + plain.length + 20, "密文长度不符合 V‖C‖T: " + name);
        eq(viaJca[0] == 0x04, "V 必须以非压缩前缀 0x04 开头: " + name);

        // 服务端视角有效性:静态私钥能解开(MAC 校验通过才算真 ECB 兼容)
        Cipher dec = Cipher.getInstance("ECIES", "BC");
        dec.init(Cipher.DECRYPT_MODE, loadPrivPkcs8(PRI_PKCS8_BASE64_EXPECTED));
        eqBytes(dec.doFinal(viaJca), plain, "解密回读失败: " + name);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("name", name);
        v.put("description", desc);
        v.put("publicKeyHex", PUB_UNCOMPRESSED_HEX);
        v.put("ephemeralDHex", EPHE_PATTERN_HEX);
        v.put("ephemeralPublicKeyHex", hex(manual.get("V")));
        v.put("plaintextByteLen", plain.length);
        v.put("plaintextHex", hex(plain));
        v.put("sharedSecretHex", hex(manual.get("sharedSecret")));
        v.put("sharedSecretNote", "V||Z,V 是上面的 ephemeralPublicKeyHex,Z=ECDH x 分量左填充 32B");
        v.put("kdfDerivedKeyHex", hex(manual.get("kdfKey")));
        v.put("macTagHex", hex(manual.get("tag")));
        v.put("cipherBase64Std", Base64.getEncoder().encodeToString(viaJca));
        v.put("cipherHex", hex(viaJca));
        v.put("expectedTotalLen", 65 + plain.length + 20);
        return v;
    }

    private static Map<String, Object> kdf2Vector(String name, byte[] shared, int outLen) {
        KDF2BytesGenerator kdf = new KDF2BytesGenerator(new SHA1Digest());
        kdf.init(new KDFParameters(shared, null));
        byte[] out = new byte[outLen];
        kdf.generateBytes(out, 0, outLen);
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("name", name);
        v.put("description", "block_i = SHA1(shared || be32(i)),i 从 1 起(bcprov BaseKDFBytesGenerator.counterStart=1)");
        v.put("sharedSecretHex", hex(shared));
        v.put("outLen", outLen);
        v.put("expectedKHex", hex(out));
        return v;
    }

    private static byte[] sharedOf(List<Map<String, Object>> vectors, String name) {
        for (Map<String, Object> v : vectors) {
            if (name.equals(v.get("name"))) return unhex((String) v.get("sharedSecretHex"));
        }
        throw new AssertionError("找不到向量 " + name);
    }

    /** 手写常量 × 内置规则实现 的交叉断言(两套独立来源对不上就说明抄错或规则理解错)。 */
    private static void verifyCanonExpectations() {
        eq(CANON_C01_FLAT_SORTED.equals(canonical(obj(
                "event", "login", "bizId", "1001", "userId", "u_01"))), "c01 flat_sorted");
        eq(CANON_C02_CASE_ORDER.equals(canonical(obj(
                "Type", "T1", "alpha", "a1", "Alpha", "A1", "beta", "b1"))), "c02 case_order");
        eq(CANON_C03_NESTED_SORT.equals(canonical(obj(
                "b", obj("y", 2L, "x", obj("inner", "v")),
                "a", Arrays.asList(1L, 2L, 3L)))), "c03 nested recursive sort");
        eq(CANON_C04_HTML_RAW.equals(canonical(obj(
                "script", "<script>&amp;</script>", "lt_gt_amp", "< > &"))), "c04 html raw");
        eq(CANON_C05_NULL_OMITTED.equals(canonical(obj(
                "a", null, "b", "keep", "c", null))), "c05 null omitted");
        eq(CANON_C06_NULL_IN_ARRAY.equals(canonical(obj(
                "list", Arrays.asList(null, "keep", null), "gone", null))), "c06 null kept in array");
        eq(CANON_C07_INT_TYPES.equals(canonical(obj(
                "intVal", 42, "longMs", 1756272000000L, "negInt", -7))), "c07 integer types");
        eq(CANON_C08_CHINESE_UTF8.equals(canonical(obj(
                "姓名", "张三", "事件类型", "登录", "mixed_zh", "中文abc"))), "c08 chinese utf8");
        eq(CANON_C09_EMPTY_MAP.equals(canonical(obj())), "c09 empty map");
        eq(CANON_C10_EMPTY_KEY_VALUE.equals(canonical(obj("", ""))), "c10 empty key/value");
        eq(CANON_C11_QUOTES_BACKSLASH.equals(canonical(obj(
                "quoted", "he said \"hi\"", "bs", "C:\\path\\"))), "c11 quotes/backslash");
        eq(CANON_C12_CONTROL_CHARS.equals(canonical(controlCase())), "c12 control chars");
        eq(CANON_C13_SLASH_RAW.equals(canonical(obj(
                "url", "https://gw/risk?x=1&y=2"))), "c13 slash raw");
        eq(CANON_C14_BOOL_MIX.equals(canonical(obj(
                "ok", Boolean.TRUE, "no", Boolean.FALSE, "numStr", "123"))), "c14 bool mix");
        eq(CANON_C15_EMOJI_VALUE.equals(canonical(obj(
                "emoji", EMOJI + " ok " + EMOJI, "plain", "hi"))), "c15 supplementary plane char");

        // ---- 报文级常量的交叉校验 ----
        eq(SIGN_JSON_CASE_A.equals(canonical(caseRequestMap(EVENT_TYPE_A, BIZ_ID_A,
                REQUEST_TIME_A, TRACE_ID_A, REQUEST_IP_A, CLIENT_ID_A))), "SIGN_JSON_CASE_A");
        eq(SIGN_JSON_CASE_C.equals(canonical(caseRequestMap(EVENT_TYPE_C, BIZ_ID_C,
                REQUEST_TIME_C, TRACE_ID_C, REQUEST_IP_A, CLIENT_ID_A))), "SIGN_JSON_CASE_C");

        // X-RISK-BASIC 明文按 bean 声明顺序(父类先,子类后)
        eq(HEADER_JSON_CASE_A.equals(orderedJson(new Object[][]{
                {"bizId", BIZ_ID_A}, {"userId", "UNKNOWN"}, {"eventType", EVENT_TYPE_A},
                {"fingerToken", null}, {"ip", null}, {"bizTime", null},
                {"tenantId", "default"}, {"siteType", "default"},
                {"traceId", TRACE_ID_A}, {"requestIp", REQUEST_IP_A},
                {"requestTime", REQUEST_TIME_A}, {"clientVersion", CLIENT_VERSION},
                {"clientId", CLIENT_ID_A}})), "HEADER_JSON_CASE_A");
        eq(HEADER_JSON_CASE_C.equals(orderedJson(new Object[][]{
                {"bizId", BIZ_ID_C}, {"userId", "UNKNOWN"}, {"eventType", EVENT_TYPE_C},
                {"fingerToken", null}, {"ip", null}, {"bizTime", null},
                {"tenantId", "default"}, {"siteType", "default"},
                {"traceId", TRACE_ID_C}, {"requestIp", REQUEST_IP_A},
                {"requestTime", REQUEST_TIME_C}, {"clientVersion", CLIENT_VERSION},
                {"clientId", CLIENT_ID_A}})), "HEADER_JSON_CASE_C");
    }

    /** queryAuditCase 的 requestMap(eventType/bizId + DefaultSystemFieldInjector 注入的五键)。 */
    private static Map<String, Object> caseRequestMap(String eventType, String bizId, long ts,
                                                      String traceId, String ip, String clientId) {
        return obj("eventType", eventType, "bizId", bizId,
                "requestTime", ts, "traceId", traceId, "requestIp", ip,
                "clientId", clientId, "clientVersion", CLIENT_VERSION);
    }

    /** 控制字符用显式码点构造,避免源码里混入裸控制字节。 */
    private static Map<String, Object> controlCase() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("nl", "\n");
        m.put("tab", "\t");
        m.put("u0001", Character.toString((char) 0x01));
        m.put("u000b", Character.toString((char) 0x0b));      // VT → \\u000B(注意大写 B)
        m.put("u001f", Character.toString((char) 0x1f));      // US → \\u001F
        m.put("bell", Character.toString((char) 0x08));       // BS → \b
        return m;
    }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    // -------------------------------------------------------------------------
    // 六头构造(RiskSimpleClient.buildHeaders L298-L307)
    // -------------------------------------------------------------------------

    private static Map<String, Object> sixHeaders(String clientId, String clientSecret,
                                                  String headerJson, String signatureStd, String xUserId) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("Content-Type", "application/json");
        h.put("X-RISK-MODE", "sync");                          // riskAsync 才用 async,本期不移植
        h.put("X-SIGNATURE", signatureStd);
        h.put("Authorization", "Basic " + Base64.getUrlEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)));   // URL-safe 【带填充】
        h.put("X-RISK-BASIC", Base64.getUrlEncoder().encodeToString(
                headerJson.getBytes(StandardCharsets.UTF_8)));
        h.put("X-User-Id", xUserId);
        return h;
    }

    /** 签名链:X-SIGNATURE = stdBase64(ECIES(staticPub, sha512HexLower(signJson))). */
    private static Map<String, Object> signatureInputs(String signJson) throws Exception {
        byte[] hashBytes = sha512HexLower(signJson.getBytes(StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.US_ASCII);
        byte[] sigCipher = jcaEcies(loadPubSpki(PUB_SPKI_BASE64_EXPECTED), hashBytes,
                new ReplayRandom(unhex(EPHE_PATTERN_HEX)));

        Map<String, byte[]> manual = manualEcies(domain(),
                unhex(PUB_UNCOMPRESSED_HEX), new BigInteger(1, unhex(EPHE_PATTERN_HEX)), hashBytes);
        eqBytes(manual.get("full"), sigCipher, "签名链路的手工复算与 JCA 不一致");

        Map<String, Object> si = new LinkedHashMap<>();
        si.put("sortedSignJson", signJson);
        si.put("sha512HexLowerOfSignJson", new String(hashBytes, StandardCharsets.US_ASCII));
        si.put("eciesPlaintextNote", "被 ECIES 加密的明文是这 128 个小写 hex 字符本身(US-ASCII)");
        si.put("signatureBase64Std", Base64.getEncoder().encodeToString(sigCipher));
        return si;
    }

    private static Map<String, Object> headerEntryAudit(String name, String clientId, String clientSecret,
                                                        String signJson, String headerJson, String bodyJson)
            throws Exception {
        Map<String, Object> si = signatureInputs(signJson);
        String signatureStd = (String) si.get("signatureBase64Std");
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("name", name);
        e.put("scenario", "queryAuditCase: POST {baseUrl}/generalCase/query(无路径参数)");
        e.put("clientId", clientId);
        e.put("clientSecret", clientSecret);
        e.put("clientVersion", CLIENT_VERSION);
        e.put("signInputs", si);
        e.put("authorizationScheme", "Basic");
        e.put("authorizationBase64url", Base64.getUrlEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)));
        e.put("riskBasicBase64url", Base64.getUrlEncoder().encodeToString(
                headerJson.getBytes(StandardCharsets.UTF_8)));
        e.put("signatureBase64Std", signatureStd);
        e.put("headerJson", headerJson);
        e.put("bodyJson", bodyJson);
        e.put("headerJsonNote", "hutool BeanUtil.copyProperties(requestMap, RiskRequestHeader.class) 再经 Jackson 序列化的确切字符串:"
                + " 父类字段在前子类字段在后、各按声明顺序,null 被省略;userId 是 bean 默认值 UNKNOWN(requestMap 没有 userId)");
        e.put("noteAboutSignatureScope", "X-SIGNATURE 只覆盖 sortedSignJson(TreeMap 升序 7 键),不含 headerJson/body 的其余键集合");
        e.put("headers", sixHeaders(clientId, clientSecret, headerJson, signatureStd, "UNKNOWN"));
        return e;
    }

    /** 同步问询样例:risk 主路径(RiskRequestBuilder.build 五步走完后的状态)。 */
    private static Map<String, Object> headerEntryRiskB(PublicKey pub) throws Exception {
        byte[] cipher = jcaEcies(pub, SECRET_FIELD_PLAINTEXT.getBytes(StandardCharsets.UTF_8),
                new ReplayRandom(unhex(EPHE_PATTERN_HEX)));
        String cipherB64 = Base64.getEncoder().encodeToString(cipher);
        if (secretCipherConstantPending()) {
            System.out.println("[提示] 请把这行密文固化进 SECRET_FIELD_CIPHER_BASE64_STD_EXPECTED:"
                    + " \"" + cipherB64 + "\"");
        } else {
            eq(cipherB64.equals(SECRET_FIELD_CIPHER_BASE64_STD_EXPECTED), "敏感字段期望密文常量漂移(加密实现变了?)");
        }

        // 合并参数 = JsonUtil.toMap(basicParam) ∪ bizData ∪ inject(RiskRequestBuilder.mergeParams/inject 之后)
        Map<String, Object> merged = new TreeMap<>();
        merged.put("bizId", "PAY202608270001");
        merged.put("userId", USER_ID_B);
        merged.put("platform", "IOS_APP");
        merged.put("eventType", "payment_risk_check");
        merged.put("fingerToken", "fp-9f8e7d6c");
        merged.put("ip", "203.0.113.77");
        merged.put("bizTime", REQUEST_TIME_B);
        merged.put("tenantId", "default");
        merged.put("siteType", "default");
        merged.put("amount", "1250.75");
        merged.put("countryCode", "SG");
        merged.put("bankCard", "6222600012345678");
        merged.put("deviceModel", "iPhone 15 Pro");
        merged.put("email", cipherB64);                       // 敏感字段原位置换成密文后才参与签名/发送
        merged.put("requestTime", REQUEST_TIME_B);
        merged.put("traceId", TRACE_ID_B);
        merged.put("requestIp", REQUEST_IP_B);
        merged.put("clientId", CLIENT_ID_B);
        merged.put("clientVersion", CLIENT_VERSION);

        String signJson = canonical(merged);
        Map<String, Object> si = signatureInputs(signJson);
        String signatureStd = (String) si.get("signatureBase64Std");

        // X-RISK-BASIC 明文(bizData 键不是 bean 属性,所以不进头)
        String headerJson = orderedJson(new Object[][]{
                {"bizId", "PAY202608270001"}, {"userId", USER_ID_B}, {"platform", "IOS_APP"},
                {"eventType", "payment_risk_check"}, {"fingerToken", "fp-9f8e7d6c"}, {"ip", "203.0.113.77"},
                {"bizTime", REQUEST_TIME_B}, {"tenantId", "default"}, {"siteType", "default"},
                {"traceId", TRACE_ID_B}, {"requestIp", REQUEST_IP_B},
                {"requestTime", REQUEST_TIME_B}, {"clientVersion", CLIENT_VERSION},
                {"clientId", CLIENT_ID_B}});

        // body = 剥离 HEADER_FIELDS 白名单 14 键后的剩余项(升序展示)
        Map<String, Object> bodyMap = stripHeaderFields(merged);
        String bodyJson = canonical(bodyMap);

        Map<String, Object> e = new LinkedHashMap<>();
        e.put("name", "sync_risk_with_secret_field_encrypted");
        e.put("scenario", "risk: POST {baseUrl}/risk-engine/risk/{eventType}");
        e.put("clientId", CLIENT_ID_B);
        e.put("clientSecret", CLIENT_SECRET_B);
        e.put("clientVersion", CLIENT_VERSION);
        e.put("signInputs", si);
        e.put("authorizationScheme", "Basic");
        e.put("authorizationBase64url", Base64.getUrlEncoder().encodeToString(
                (CLIENT_ID_B + ":" + CLIENT_SECRET_B).getBytes(StandardCharsets.UTF_8)));
        e.put("riskBasicBase64url", Base64.getUrlEncoder().encodeToString(
                headerJson.getBytes(StandardCharsets.UTF_8)));
        e.put("signatureBase64Std", signatureStd);
        e.put("headerJson", headerJson);
        e.put("bodyJson", bodyJson);
        e.put("headerJsonNote", "bizData/email 的密文不是 bean 属性 → 不出现在 X-RISK-BASIC,但参与签名并进 body");
        e.put("strippedHeaderFieldsNote", "Java HEADER_FIELDS 白名单共 14 键(requestTime,traceId,requestIp,clientId,"
                + "clientVersion,bizId,userId,platform,eventType,fingerToken,ip,bizTime,tenantId,siteType),全剔除后才是 body;"
                + " 本样例 body 剩 amount/bankCard/countryCode/deviceModel/email 5 键");
        e.put("secretFieldsUsed", Arrays.asList("email"));
        e.put("secretFieldPlaintext", SECRET_FIELD_PLAINTEXT);
        e.put("secretFieldCipherBase64Std", cipherB64);
        e.put("secretFieldEciesNote", "临时标量同样是回放的 EPHE_PATTERN_HEX,所以这条密文也是稳定的(Go 测试可直接断言)");
        e.put("headers", sixHeaders(CLIENT_ID_B, CLIENT_SECRET_B, headerJson, signatureStd, USER_ID_B));
        return e;
    }

    private static Map<String, Object> stripHeaderFields(Map<String, Object> merged) {
        List<String> headerFields = Arrays.asList("requestTime", "traceId", "requestIp", "clientId", "clientVersion",
                "bizId", "userId", "platform", "eventType", "fingerToken", "ip", "bizTime", "tenantId", "siteType");
        Map<String, Object> body = new TreeMap<>(merged);
        for (String f : headerFields) body.remove(f);
        return body;
    }

    // -------------------------------------------------------------------------
    // 文档组装
    // -------------------------------------------------------------------------

    private static Map<String, Object> metaDoc(String title, List<String> notes) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("_meta.title", title);
        m.put("_meta.generator", "scripts/GenVectors.java(JDK11 + bcprov-jdk15on 1.70,确定性可重跑)");
        m.put("_meta.notes", notes);
        return m;
    }

    private static String renderEciesDoc(List<Map<String, Object>> vectors, List<Map<String, Object>> kdf2) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.putAll(metaDoc("ECIES golden vectors(BouncyCastle 1.70 无参默认参数)", Arrays.asList(
                "IESEngine(ECDHBasicAgreement, KDF2BytesGenerator(SHA1), HMac(SHA1)),无分组密码 → 流式 XOR",
                "流程:V = 0x04||X||Y(65B);Z = x(r·Ypub) 左填充 32B;shared = V||Z(V 在前!);",
                "      K = KDF2-SHA1(shared, 16+len(pt))(block_i = SHA1(shared||be32(i)),i 从 1 起);",
                "      K[0:16] = HMAC-SHA1 的 MAC key,K[16:] = XOR keystream(反直觉布局)",
                "      C = pt ⊕ K[16:];T = HMAC-SHA1(K[0:16], C || 8×0x00)(P2=null 的长度标签,20B 不截断)",
                "输出 = V || C || T;",
                "兼容判据分两层:测试层(本文件固定 ephemeral,逐字节可比)/ 生产层(随机 ephemeral,服务端可解+MAC 通过即可)",
                "每条向量的生成过程都做了三重校验:JCA 实际输出 == 手工复算 == 静态私钥能解回来(MAC 通过)")));
        doc.put("staticKeyPair", obj(
                "curve", "secp256r1 / P-256 / prime256v1",
                "privateKeyScalarHex", D_STATIC_HEX,
                "privateKeyPopcount", 168L,
                "privateKeyNafWeight", 79L,
                "choiceRationale", "popcount 高(256 位中 168 位为 1)且 NAF 权重 79 > BC ECKeyPairGenerator 的 minWeight="
                        + "n.bitLength()/4=64;纯堆置位(如全 0xFE,popcount=224)的 NAF 权重只有 33,才是真正的低权重退化标量",
                "publicKeyUncompressedHex", PUB_UNCOMPRESSED_HEX,
                "publicKeySpkiBase64Std", PUB_SPKI_BASE64_EXPECTED,
                "privateKeyPkcs8Base64Std", PRI_PKCS8_BASE64_EXPECTED,
                "prodConfigUsage", "publicKeySpkiBase64Std 就是生产 Java 配置 publicKey 的格式(SecureUtil.loadPublicKey 直接可载)"));
        doc.put("ephemeralReplay", obj(
                "mechanism", "Cipher.init(ENCRYPT_MODE, publicKey, customSecureRandom);customSecureRandom.nextBytes "
                        + "永远回填同一 32 字节块。BC IESEngine 经 ECKeyPairGenerator 以 BigInteger(256, rnd) 抽临时标量,"
                        + "一次 nextBytes 就拿满 32 字节,所以每次都得到同一个 k",
                "replayPatternHex", EPHE_PATTERN_HEX,
                "resultingEphemeralScalarHex", EPHE_PATTERN_HEX,
                "rejectionLoopCheck", "标量 NAF 权重 103 >= 64,首抽即通过生成器筛选(nextBytes 恒定,若不过筛会无限重抽)",
                "productionBehaviour", "生产代码(Cipher.init 两参形式)使用默认随机源,密文不可预测;此处只是替换随机源,参数路径不变"));
        doc.put("parameterModel", obj(
                "derivation", "null", "encoding", "null", "nonceOrIv", "none",
                "kdf", "KDF2BytesGenerator(SHA1),counterStart=1",
                "mac", "HMac(SHA1), macKeySize=128bit, tag=20B 不截断",
                "blockCipher", "none(streaming)",
                "pointCompression", false,
                "outputLayout", "V(65B) || C(len(pt)) || T(20B)"));
        doc.put("vectors", vectors);
        doc.put("kdf2Vectors", kdf2);
        return renderDoc(doc);
    }

    private static String renderCanonDoc() {
        List<Map<String, Object>> cases = new ArrayList<>();
        cases.add(canonCase("c01_flat_sorted_keys", "三个键乱序放入,期望输出严格按键升序",
                "{'event':'login','bizId':'1001','userId':'u_01'}(Java 侧交给 TreeMap 后再序列化)", CANON_C01_FLAT_SORTED,
                "普通字符串值无任何额外转义"));
        cases.add(canonCase("c02_key_order_is_code_unit_order", "大小写敏感,按 UTF-16 码元序:大写在小写之前",
                "{'Type':..,'alpha':..,'Alpha':..,'beta':..}", CANON_C02_CASE_ORDER,
                "'A'<'T'<'a'<'b';与 Locale 无关(TreeMap 自然序)"));
        cases.add(canonCase("c03_nested_object_recursive_sort", "嵌套对象每一层都要升序;数组保持元素原有顺序",
                "{'b':{'y':2,'x':{'inner':'v'}},'a':[1,2,3]}", CANON_C03_NESTED_SORT,
                "递归应用 R1:b 内部也变成 x,y 顺序"));
        cases.add(canonCase("c04_html_chars_not_escaped", "Jackson 绝不转义 < > &(Go encoding/json 缺省会)",
                "value 含 '<script>&amp;</script>' 与 '< > &'", CANON_C04_HTML_RAW,
                "关闭 HTML 转义是最常见的移植翻车点:不同转义直接导致签名不一致"));
        cases.add(canonCase("c05_null_properties_omitted", "NON_NULL:值为 null 的键整个消失",
                "{'a':null,'b':'keep','c':null}", CANON_C05_NULL_OMITTED,
                "Go 侧等价做法:序列化前删掉 nil 值键"));
        cases.add(canonCase("c06_null_element_inside_array_kept", "对照面:NON_NULL 只作用于属性,数组内的 null 保留",
                "{'list':[null,'keep',null],'gone':null}", CANON_C06_NULL_IN_ARRAY,
                "不要把数组里的 null 也一并删掉"));
        cases.add(canonCase("c07_integer_types_stay_integer", "Integer/Long 输出整数,无 .0,负数带负号",
                "intVal=Integer(42)、longMs=Long(1756272000000)、negInt=-7", CANON_C07_INT_TYPES,
                "时间戳一定不能变成浮点数"));
        cases.add(canonCase("c08_chinese_utf8_raw_with_ascii_mix", "中文原样输出,并且与 ASCII 键混排时按码元序归位",
                "{'姓名':'张三','事件类型':'登录','mixed_zh':'中文abc'}", CANON_C08_CHINESE_UTF8,
                "U+4E8B(事) < U+59D3(姓),都在 ASCII 之后"));
        cases.add(canonCase("c09_empty_map", "空 map 输出 {},中间没有任何空白",
                "{}", CANON_C09_EMPTY_MAP,
                "剥完头字段后可能得到空 body"));
        cases.add(canonCase("c10_empty_string_key_and_value", "空字符串键与值都要保留",
                "{'':''}", CANON_C10_EMPTY_KEY_VALUE,
                "空串键在排序中恒最小"));
        cases.add(canonCase("c11_quotes_and_backslashes", "JSON 强制转义依然生效",
                "quoted='he said \"hi\"'; bs='C:\\path\\'", CANON_C11_QUOTES_BACKSLASH,
                "只有引号与反斜杠这两类是强制的"));
        cases.add(canonCase("c12_control_chars_uppercase_hex_escape", "控制字符转义形态:0x08→\\b、0x09→\\t、0x0A→\\n,"
                        + "其余为 \\u00XX 且十六进制字母【大写】",
                "值分别为 char 0x01 / 0x0B / 0x1F / 0x08", CANON_C12_CONTROL_CHARS,
                "关键差异:u000b 输出 '\\u000B' 大写 B!Go 缺省是小写 '\\u000b',这是真实移植坑,Go 侧必须自实现转义器"));
        cases.add(canonCase("c13_slash_and_ampersand_raw", "/ 和 & 都原样输出",
                "url='https://gw/risk?x=1&y=2'", CANON_C13_SLASH_RAW,
                "同样属于 HTML 转义争议面"));
        cases.add(canonCase("c14_boolean_and_numeric_string", "布尔输出 true/false;数字字符串仍是字符串",
                "ok=true、no=false、numStr='123'", CANON_C14_BOOL_MIX,
                "数字字符串绝不能掉引号(会改变签名)"));
        cases.add(canonCase("c15_supplementary_plane_char_raw", "补平面字符(emoji,U+1F600)surrogate pair 原样输出",
                "emoji='<U+1F600> ok <U+1F600>'", CANON_C15_EMOJI_VALUE,
                "按 UTF-8 编码为 4 字节,Go 行为一致。但增补平面的【键】会踩 UTF-16 码元序 vs 字节序差异,协议约定键只用 ASCII"));

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.putAll(metaDoc("canonical JSON 规则 golden 用例(与 Java TreeMap + Jackson 逐字节对齐)", Arrays.asList(
                "规则集 R1~R9 见 scripts/README.md(与 design.md『internal/protocol』章节一致)",
                "canonicalJson 期望值全部是【手工书写的字符串常量】:依据 risk-client 使用的 Jackson 2.13.5 + hutool 5.8.25 "
                        + "的真实行为核对,但生成脚本与 Go 测试都不引入这两个库来计算期望值",
                "生成脚本内置另一份独立的规则实现(canonical()/orderedJson()),专门反向校对手写常量是否抄错,不一致即失败",
                "所有样本都是签名输入形态:TreeMap 升序 + Jackson 序列化;不允许再用其它顺序")));
        doc.put("ruleSummary", obj(
                "R1_key_order", "java.util.TreeMap 自然序 = String.compareTo = UTF-16 码元序;嵌套对象递归",
                "R2_compact", "逗号与冒号后无空格,首尾无缩进无换行",
                "R3_escapes", "0x22→\\\", 0x5C→\\\\;0x08→\\b、0x09→\\t、0x0A→\\n、0x0C→\\f、0x0D→\\r;其余 <0x20 为 \\u00XX 且 hex 大写",
                "R4_no_html_escape", "< > & ' / 以及 0x7F、U+2028、U+2029 全部原样",
                "R5_null_handling", "map/bean 属性值为 null → 键整省略;数组中的 null 元素保留",
                "R6_integers", "Integer/Long 十进制整数,无小数点",
                "R7_empty_map", "{}",
                "R8_no_trailing_newline", "签名字符串不得带尾部换行或空白",
                "R9_utf8_raw", "非 ASCII 不做 \\uXXXX 转义,原样 UTF-8"));
        doc.put("cases", cases);
        return renderDoc(doc);
    }

    private static Map<String, Object> canonCase(String name, String purpose, String inputDesc,
                                                 String canonicalJson, String extraNote) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("name", name);
        c.put("purpose", purpose);
        c.put("inputDescription", inputDesc);
        c.put("canonicalJson", canonicalJson);
        c.put("note", extraNote);
        return c;
    }

    private static String renderHeadersDoc(List<Map<String, Object>> entries) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.putAll(metaDoc("六请求头 golden 样例(X-SIGNATURE / Authorization / X-RISK-BASIC 等)", Arrays.asList(
                "六个头见 RiskSimpleClient.buildHeaders(L298-L307):Content-Type/X-RISK-MODE/X-SIGNATURE/"
                        + "Authorization/X-RISK-BASIC/X-User-Id",
                "X-SIGNATURE = 标准 Base64( ECIES(staticPub, 小写hex(sha512(升序JSON))) ):被加密的是 128 个 ASCII hex 字符本身",
                "Authorization = \"Basic \" + Base64UrlWithPadding(clientId + ':' + clientSecret);"
                        + "这不是标准 Basic 的字母表(+/ 被换成 -_),【带填充 =】",
                "X-RISK-BASIC = Base64UrlWithPadding(headerJson),URL-safe 同样带填充",
                "X-User-Id:risk 场景来自 basicParam.getUserId()(缺省 UNKNOWN);案件查询硬编码 UNKNOWN",
                "三条样例分别覆盖:案件查询 7 键签名 / 同步问询含密文 19 键签名 / 非 ASCII bizId")));
        doc.put("entries", entries);
        return renderDoc(doc);
    }

    private static String renderCasePayloadDoc() throws Exception {
        Map<String, Object> pA = new LinkedHashMap<>();
        pA.put("name", "query_audit_case_kyc_general_case");
        pA.put("endpoint", "{baseUrl}/generalCase/query");
        pA.put("httpMethod", "POST");
        pA.put("pathParamNote", "案件查询没有路径参数(已砍掉的 withdrawSign 才把 orderId 放路径)");
        pA.put("timeoutSource", "eventTimeout.get(eventType),未配置会在本地预检抛 ClientException");
        pA.put("eventType", EVENT_TYPE_A);
        pA.put("bizId", BIZ_ID_A);
        pA.put("sysFields", sysFields(REQUEST_TIME_A, TRACE_ID_A, REQUEST_IP_A, CLIENT_ID_A));
        pA.put("sortedSignJson", SIGN_JSON_CASE_A);
        pA.put("signJsonExplanation", "TreeMap(HashMap{eventType,bizId} + inject 的五个系统字段) → Jackson 规范 JSON;"
                + "升序后 7 键:bizId/clientId/clientVersion/eventType/requestIp/requestTime/traceId");
        pA.put("signatureInputs", signatureInputs(SIGN_JSON_CASE_A));
        pA.put("bodyJson", BODY_JSON_CASE_A);
        pA.put("bodyKeyOrderNote", "Java 用 Map.of(\"eventType\",..,\"bizId\",..)(RiskSimpleClient.java:159)构造 body,"
                + "迭代序来自 ImmutableCollections.MapN 的哈希散列,属 JDK 实现细节而非协议契约,"
                + "且随进程 SALT 逐次变化(Zulu 11 跨进程实测两种键序均出现),语义完全等价;"
                + "golden 固定采用两键升序的规范形态(bizId<eventType 恰为升序),服务端按 JSON 解析任何键序可用");
        pA.put("headerJson", HEADER_JSON_CASE_A);

        Map<String, Object> pC = new LinkedHashMap<>();
        pC.put("name", "query_audit_case_c_nonascii_bizid");
        pC.put("endpoint", "{baseUrl}/generalCase/query");
        pC.put("httpMethod", "POST");
        pC.put("pathParamNote", "同上,无路径参数");
        pC.put("timeoutSource", "eventTimeout.get(eventType)");
        pC.put("eventType", EVENT_TYPE_C);
        pC.put("bizId", BIZ_ID_C);
        pC.put("sysFields", sysFields(REQUEST_TIME_C, TRACE_ID_C, REQUEST_IP_A, CLIENT_ID_A));
        pC.put("sortedSignJson", SIGN_JSON_CASE_C);
        pC.put("signJsonExplanation", "第二条样例验证非 ASCII bizId 在签名输入/header/body 三处的 UTF-8 原样行为");
        pC.put("signatureInputs", signatureInputs(SIGN_JSON_CASE_C));
        pC.put("bodyJson", BODY_JSON_CASE_C);
        pC.put("bodyKeyOrderNote", "同上;bizId 含中文时 body/signJson 均按 UTF-8 原样发送");
        pC.put("headerJson", HEADER_JSON_CASE_C);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.putAll(metaDoc("案件查询(generalCase/query)载荷构造对照", Arrays.asList(
                "来源:com.ex.risk.client.RiskSimpleClient#queryAuditCase(L149-L191) 逐行读取得到的真实构造链",
                "签名输入:riskSigner.sign(JsonUtil.toJson(new TreeMap<>(requestMap))),其中 requestMap 先放入 eventType/bizId,"
                        + "再由 DefaultSystemFieldInjector.inject 补入 requestTime(ms,Long)/traceId(UUIDv4)/requestIp/clientId/clientVersion",
                "HTTP body:JsonUtil.toJson(Map.of(\"eventType\",eventType,\"bizId\",bizId)) —— 键集合只有这两个,"
                        + "与签名输入的键集合不同,绝不能混",
                "sysFields 是夹具固定值(DefaultSystemFieldInjector 的五个注入键);生产里 requestTime 来自系统时钟、traceId 来自 UUID 随机")));
        doc.put("samples", Arrays.asList(pA, pC));
        return renderDoc(doc);
    }

    private static Map<String, Object> sysFields(long ts, String traceId, String ip, String clientId) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("requestTime", ts);
        s.put("requestTimeNote", "毫秒时间戳,类型 Long(序列化不带小数点)");
        s.put("traceId", traceId);
        s.put("traceIdFormat", "UUIDv4 小写带连字符(DefaultSystemFieldInjector 用 UUID.randomUUID())");
        s.put("requestIp", ip);
        s.put("requestIpNote", "Java 启动时抓的首个非环回 IPv4;抓不到则是字符串 UNKNOWN(RiskSimpleClient.getLocalIpAddress)");
        s.put("clientId", clientId);
        s.put("clientVersion", CLIENT_VERSION);
        return s;
    }

    private static byte[] repeat(byte b, int n) {
        byte[] o = new byte[n];
        Arrays.fill(o, b);
        return o;
    }

    private static String longText() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 24; i++) {
            sb.append("风控请求载荷长文本样本 piece-").append(i)
              .append(" {\"orderRef\":\"ord-2026-0827-").append(i).append("\",\"channel\":\"FX_WEB\"}\n");
        }
        return sb.toString();
    }

    private static void write(Path file, String content) throws Exception {
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        System.out.printf("[write] %s (%d bytes)%n",
                file.toAbsolutePath(), content.getBytes(StandardCharsets.UTF_8).length);
    }
}
