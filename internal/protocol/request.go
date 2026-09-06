package protocol

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

// 本文件是问询/案件查询共用的请求装配管线,逐段对应 Java 版
// client/support/RiskRequestBuilder + RiskSimpleClient 的构造链:
//
//	默认值补齐 → 保留字段校验(拒绝且不发网)→ 敏感字段逐个 ECIES 原位置换
//	→ 合并 map → 规范 JSON(升序)→ X-SIGNATURE → 头 JSON(bean 序)→ 剥离头字段成 body

// errPipeline 是本文件的装配级上下文标记;语义分类(参数错/保留字段)由下方
// 从根包别名来的哨兵承担——真源在 sentinels.go,根包仅再导出。
var errPipeline = errors.New("protocol: request assembly")

// RiskParams 是同步问询的基础参数(design.md Data Models 的 BasicParam 内部形态)。
// 空串语义按 Java 版 builder:userId/tenantId/siteType 缺省补默认;
// platform/fingerToken/ip 未设置(空串)时整体不出现在报文里(NON_NULL);
// bizTime 为 0 视为未设置。
type RiskParams struct {
	BizID       string
	UserID      string // 默认 UNKNOWN
	Platform    string
	EventType   string
	FingerToken string
	IP          string
	BizTime     int64 // 毫秒时间戳;0=未设置
	TenantID    string
	SiteType    string
}

// BuiltRequest 是管线产出:签名输入/签名值/头明文/body 四件套。
// 调用方(headers 层与门面 HTTP 装配)不得再改动这些字节——它们共同构成网关验签的输入。
type BuiltRequest struct {
	SortedSignJSON string         // 升序规范 JSON:X-SIGNATURE 的直接输入
	Signature      string         // 标准 Base64 密文(X-SIGNATURE 头的值)
	HeaderJSON     string         // bean 声明序:X-RISK-BASIC 解码后的明文
	Body           map[string]any // 剥离全部协议头字段后的剩余键(可为空)
}

// headerBeanOrder 是 X-RISK-BASIC 明文的键序 = Java 风险实体 bean 的声明顺序
// (RiskBasicParam → RiskRequestHeader,golden headers_golden.json 三条 entry 全部吻合)。
// 注意这不是升序:bean 序≠TreeMap 序,前者只用于这个头。
var headerBeanOrder = [14]string{
	"bizId", "userId", "platform", "eventType", "fingerToken", "ip", "bizTime",
	"tenantId", "siteType",
	"traceId", "requestIp", "requestTime", "clientVersion", "clientId",
}

// applyRiskDefaults 补齐三个带默认值的字段(Req 1.4),返回值即"生效参数集"。
func applyRiskDefaults(p RiskParams) RiskParams {
	if p.UserID == "" {
		p.UserID = "UNKNOWN"
	}
	if p.TenantID == "" {
		p.TenantID = "default"
	}
	if p.SiteType == "" {
		p.SiteType = "default"
	}
	return p
}

// validateSecretFields 校验敏感字段声明:name 必须存在于 bizData、不得命中保留字段、
// 值必须是可字符串化的受控类型(string/int/int64)。其余类型一律 ErrParam —— 敏感
// 字段的密文字节就是协议载荷,宁拒勿猜(float64 等浮点形态进入签名链会有无声发散风险)。
func validateSecretFields(bizData map[string]any, secretFields []string) error {
	reserved := make(map[string]struct{}, len(ReservedFieldNames))
	for _, r := range ReservedFieldNames {
		reserved[r] = struct{}{}
	}
	for _, name := range secretFields {
		if name == "" {
			return fmt.Errorf("%w: secret field name is empty", ErrParamAlias)
		}
		if _, ok := reserved[name]; ok {
			return fmt.Errorf("%w: secret field %q hits reserved names", ErrReservedFieldAlias, name)
		}
		v, ok := bizData[name]
		if !ok {
			return fmt.Errorf("%w: secret field %q not found in bizData", ErrParamAlias, name)
		}
		switch v.(type) {
		case string, int, int64:
			// 受控可字符串化类型
		default:
			return fmt.Errorf("%w: secret field %q has unsupported type %T (string|int|int64 only)",
				ErrParamAlias, name, v)
		}
	}
	return nil
}

// BuildRiskRequest 执行完整装配(生产入口)。
// sgn 持有的公钥同时用于敏感字段加密——"签名密钥==加密密钥"不变量由此保证。
//
// 安全要点(2026-09-01 review 修复):生产路径对每条密文独立抽新临时密钥,
// 对齐 Java 侧行为(每次 eccEncrypt 都是新 Cipher,BC 每个 doFinal 内部自取新临时对)。
// 此前实现让签名与全部敏感字段共用一个临时密钥,同一请求的所有密文落在同一条
// XOR keystream 上(等价流密码密钥复用):拿到两条密文异或即可消去 keystream,
// 敏感字段机密性被显著削弱。兼容性不受影响——服务端按密文各自独立解密。
func BuildRiskRequest(p RiskParams, bizData map[string]any, secretFields []string, sgn *Signer,
	sys SystemFields) (*BuiltRequest, error) {

	if sgn == nil || sgn.pub == nil {
		return nil, fmt.Errorf("%w: signer with gateway public key is required", ErrConfigAlias)
	}
	return buildRiskCore(p, bizData, secretFields, sgn, sys,
		func(pt []byte) ([]byte, error) { return Encrypt(sgn.PublicKey(), pt) },
		sgn.Signature)
}

// buildRiskWithEphemeral 仅供 golden 回放:注入的单个临时密钥贯穿全链,
// 逐字节复现 Java 侧"固定 SecureRandom ephemeral 回放"的密文。生产入口是 BuildRiskRequest。
func buildRiskWithEphemeral(p RiskParams, bizData map[string]any, secretFields []string,
	sgn *Signer, eph *ecdh.PrivateKey, sys SystemFields) (*BuiltRequest, error) {

	return buildRiskCore(p, bizData, secretFields, sgn, sys,
		func(pt []byte) ([]byte, error) { return EncryptWithEphemeral(sgn.PublicKey(), pt, eph) },
		func(sorted string) (string, error) { return sgn.signatureWithEphemeral(sorted, eph) })
}

// buildRiskCore 是装配核心,加密/签名原语注入(生产=每密文新临时密钥;golden=固定回放)。
// 步骤即本文件头注释的五段;任何一步失败都不产生部分产物。
func buildRiskCore(p RiskParams, bizData map[string]any, secretFields []string,
	sgn *Signer, sys SystemFields,
	encryptSecret func(pt []byte) ([]byte, error),
	signSorted func(sortedJSON string) (string, error)) (*BuiltRequest, error) {

	if bizData == nil {
		bizData = map[string]any{}
	}
	eff := applyRiskDefaults(p)

	// ① 保留字段校验(先于任何加密/序列化):业务键命中注入键或协议基础字段一律拒绝。
	for k := range bizData {
		for _, r := range ReservedFieldNames {
			if k == r {
				return nil, fmt.Errorf("%w: bizData key %q is reserved", ErrReservedFieldAlias, k)
			}
		}
	}
	if err := validateSecretFields(bizData, secretFields); err != nil {
		return nil, err
	}

	merged := make(map[string]any, len(bizData)+9+5)
	putBasicParamKeys(merged, eff)

	// ③ 敏感字段逐个加密:值转字符串 → ECIES → 标准 Base64,原位置换(Req 1.2)。
	// 加密原语由调用方注入:生产路径每条密文独立抽临时密钥(防 keystream 复用)。
	for _, name := range secretFields {
		s, convErr := secretToString(bizData[name])
		if convErr != nil {
			return nil, convErr
		}
		ct, encErr := encryptSecret([]byte(s))
		if encErr != nil {
			return nil, fmt.Errorf("%w: encrypt secret %q: %v", errPipeline, name, encErr)
		}
		merged[name] = base64.StdEncoding.EncodeToString(ct)
	}
	for k, v := range bizData { // 未被置换的普通业务键原样并入
		if _, replaced := merged[k]; !replaced {
			merged[k] = v
		}
	}

	// ④ 注入五个系统键 + 升序规范 JSON 签名。
	InjectSystemFields(merged, sys)
	sorted, mjErr := Marshal(merged)
	if mjErr != nil {
		return nil, fmt.Errorf("%w: canonical marshal: %v", errPipeline, mjErr)
	}

	signature, sigErr := signSorted(string(sorted))
	if sigErr != nil {
		return nil, sigErr
	}

	// ⑥ 头 JSON(bean 序)+ ⑦ 剥离头字段成 body。
	headerJSON, hjErr := buildHeaderJSON(eff, sys)
	if hjErr != nil {
		return nil, hjErr
	}
	body := stripProtocolHeaderFields(merged)

	return &BuiltRequest{
		SortedSignJSON: string(sorted),
		Signature:      signature,
		HeaderJSON:     headerJSON,
		Body:           body,
	}, nil
}

// putBasicParamKeys 把生效参数集写进合并 map(出现规则见 RiskParams 注释)。
func putBasicParamKeys(m map[string]any, p RiskParams) {
	m["bizId"] = p.BizID
	m["userId"] = p.UserID
	if p.Platform != "" {
		m["platform"] = p.Platform
	}
	m["eventType"] = p.EventType
	if p.FingerToken != "" {
		m["fingerToken"] = p.FingerToken
	}
	if p.IP != "" {
		m["ip"] = p.IP
	}
	if p.BizTime != 0 {
		m["bizTime"] = p.BizTime
	}
	m["tenantId"] = p.TenantID
	m["siteType"] = p.SiteType
}

// buildHeaderJSON 按 bean 声明序输出 X-RISK-BASIC 明文:14 个潜在键,空值跳过
// (NON_NULL);数字裸写(Long 形态)。此处刻意不走升序 Marshal——golden 三条
// entry 实证 bean 序是独立于 TreeMap 的第二种确定序。
func buildHeaderJSON(eff RiskParams, sys SystemFields) (string, error) {
	values := map[string]any{
		"bizId": eff.BizID, "userId": eff.UserID, "eventType": eff.EventType,
		"tenantId": eff.TenantID, "siteType": eff.SiteType,
		"traceId": sys.TraceID, "requestIp": sys.RequestIP,
		"requestTime": sys.RequestTime, "clientVersion": sys.ClientVersion,
		"clientId": sys.ClientID,
	}
	if eff.Platform != "" {
		values["platform"] = eff.Platform
	}
	if eff.FingerToken != "" {
		values["fingerToken"] = eff.FingerToken
	}
	if eff.IP != "" {
		values["ip"] = eff.IP
	}
	if eff.BizTime != 0 {
		values["bizTime"] = eff.BizTime
	}

	e := &canonEncoder{}
	e.buf = append(e.buf, '{')
	first := true
	writeKV := func(key string) {
		v, ok := values[key]
		if !ok || firstSkip(v) {
			return
		}
		if !first {
			e.buf = append(e.buf, ',')
		}
		first = false
		e.writeString(key)
		e.buf = append(e.buf, ':')
		e.writeValue(v, 1) // 头字段是受控标量集,永不触达深度上限
	}
	for _, k := range headerBeanOrder {
		writeKV(k)
	}
	e.buf = append(e.buf, '}')
	if e.err != nil {
		return "", fmt.Errorf("%w: header json: %v", errPipeline, e.err)
	}
	return string(e.buf), nil
}

// firstSkip 统一"未设置就不出现在头 JSON 里"的判定:仅允许非空标量通过;
// 显式写入 nil / 空串之外的兜底防御(值表本身受控,这里防未来扩展遗漏)。
func firstSkip(v any) bool {
	switch t := v.(type) {
	case string:
		return t == ""
	case int64:
		return t == 0
	default:
		return false
	}
}

// secretToString 把受控类型的敏感值转成待加密字节串(int 十进制对齐 Jackson Long 输出)。
func secretToString(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case int:
		return strconv.FormatInt(int64(t), 10), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	default:
		return "", fmt.Errorf("%w: unsupported secret type %T", ErrParamAlias, v)
	}
}

// BuildCaseQueryRequest 装配审核案件查询载荷(Java RiskSimpleClient#queryAuditCase 同构):
// 签名输入 = TreeMap{eventType,bizId} + 注入五键,恒为 7 键;
// body 只有 eventType/bizId 两键(Map.of 语义,键集合与签名输入不同!);
// 头 JSON 走仅含默认值基础参数的 bean 序(userId=UNKNOWN 等)。
func BuildCaseQueryRequest(eventType, bizID string, sgn *Signer,
	sys SystemFields) (*BuiltRequest, error) {

	if eventType == "" || bizID == "" {
		return nil, fmt.Errorf("%w: case query requires eventType and bizID", ErrParamAlias)
	}
	eff := applyRiskDefaults(RiskParams{BizID: bizID, EventType: eventType})
	eph, err := ecdh.P256().GenerateKey(cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: random ephemeral key: %v", errPipeline, err)
	}
	return buildCaseQueryWithEphemeral(eff, sgn, eph, sys)
}

func buildCaseQueryWithEphemeral(eff RiskParams, sgn *Signer, eph *ecdh.PrivateKey,
	sys SystemFields) (*BuiltRequest, error) {

	merged := map[string]any{"eventType": eff.EventType, "bizId": eff.BizID}
	InjectSystemFields(merged, sys)

	sorted, mjErr := Marshal(merged)
	if mjErr != nil {
		return nil, fmt.Errorf("%w: canonical marshal: %v", errPipeline, mjErr)
	}
	signature, sigErr := sgn.signatureWithEphemeral(string(sorted), eph)
	if sigErr != nil {
		return nil, sigErr
	}
	headerJSON, hjErr := buildHeaderJSON(eff, sys)
	if hjErr != nil {
		return nil, hjErr
	}
	// body 与签名输入不同源:Java 用 Map.of 只放两键(RiskSimpleClient.java:159);
	// 键序按升序规范形态输出(golden bodyJson 即 bizId<eventType 升序)。
	body := map[string]any{"eventType": eff.EventType, "bizId": eff.BizID}
	return &BuiltRequest{
		SortedSignJSON: string(sorted),
		Signature:      signature,
		HeaderJSON:     headerJSON,
		Body:           body,
	}, nil
}

// stripProtocolHeaderFields 从合并 map 移除全部协议头字段,剩余键构成 HTTP body
// (可为空对象——body 允许 "{}")。剥离集合与保留字段集合是同一份清单。
func stripProtocolHeaderFields(merged map[string]any) map[string]any {
	body := make(map[string]any, len(merged))
	for k, v := range merged {
		reserved := false
		for _, r := range ReservedFieldNames {
			if k == r {
				reserved = true
				break
			}
		}
		if !reserved {
			body[k] = v
		}
	}
	return body
}
