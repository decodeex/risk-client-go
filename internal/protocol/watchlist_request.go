package protocol

import (
	"encoding/base64"
	"fmt"
)

// 本文件是名单外部上报(watch-list-external-input design C1)的请求装配,与问询装配
// (request.go)共用 ECIES/签名/canonjson 原语,但契约有两处刻意差异:
//
//	① 签名原文==线上发送字节:body 就是合并 map 的 canonjson 字节本身,不再剥离
//	  协议头字段后二次序列化——嵌套 items 不允许第二种序列化路径(design C1 硬条件)。
//	  服务端 RiskSignVerifier 以 merge(body, X-RISK-BASIC) 重排比对摘要;头内容是
//	  body 五个注入键的子集(同值),merge 幂等,重排字节==body 字节,验签即通过。
//	② 固定字段加密:itemValue/reason 在每个 item 内原位置换为 ECIES 密文(标准
//	  Base64),密文即签名载荷的一部分;每条密文独立临时密钥(与 BuildRiskRequest
//	  生产口径一致,防 keystream 复用)。

// watchListSecretKeys 是名单上报的固定加密字段(design C1):itemValue 必在,
// reason 存在才加密。调用方(门面)不得把这两键以明文形态放入 items。
var watchListSecretKeys = [2]string{"itemValue", "reason"}

// watchListHeaderBeanOrder 是名单上报 X-RISK-BASIC 的 bean 序:仅五个注入键。
// 名单上报无 basicParam 语义;头键集必须 ⊆ body 键集且同值(见文件头①),否则
// 服务端 merge 会引入 body 没有的键,摘要比对必然失败。
var watchListHeaderBeanOrder = [5]string{"traceId", "requestIp", "requestTime", "clientVersion", "clientId"}

// BuiltWatchListRequest 是名单上报的装配产物。与 BuiltRequest 的本质差异:
// Body 直接就是线上发送字节(== 签名原文),不是待二次序列化的 map——调用方
// 不得再改动或重序列化这些字节。
type BuiltWatchListRequest struct {
	Body       []byte // 线上发送字节 == 签名原文(canonjson)
	Signature  string // 标准 Base64 密文(X-SIGNATURE 头的值)
	HeaderJSON string // bean 声明序:X-RISK-BASIC 解码后的明文
}

// BuildWatchListReportRequest 装配一次名单外部上报(生产入口)。
//
// items 是本次调用专有的载体 map(门面逐次新建),本函数对其做密文原位置换;
// 每个 item 的键即 wire 字段:objectType/listType/itemValue/ttlMinutes 明文,
// itemValue/reason 置换为密文。ttlMinutes 未设置的 item 整键不出现(NON_NULL);
// reason 门面层必填预检,协议层容忍缺席(服务端对缺席 reason 按 invalid 拒绝)。
// 任何一步失败都不产生部分产物。
func BuildWatchListReportRequest(items []map[string]any, sgn *Signer,
	sys SystemFields) (*BuiltWatchListRequest, error) {

	if sgn == nil || sgn.pub == nil {
		return nil, fmt.Errorf("%w: signer with gateway public key is required", ErrConfigAlias)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: watch list report requires at least one item", ErrParamAlias)
	}

	// ① 固定字段加密(canonjson 的数组支线只收 []any,此处完成形态转换)
	arr := make([]any, len(items))
	for i, item := range items {
		enc, err := encryptWatchListItem(item, sgn)
		if err != nil {
			return nil, err
		}
		arr[i] = enc
	}

	// ② 合并注入五键 → canonjson 字节。这同一份字节既是签名原文也是发送 body,
	//    不再走"剥离头字段重组"的第二条序列化路径(与问询装配的根本差异)。
	merged := map[string]any{"items": arr}
	InjectSystemFields(merged, sys)
	body, mjErr := Marshal(merged)
	if mjErr != nil {
		return nil, fmt.Errorf("%w: canonical marshal: %v", errPipeline, mjErr)
	}

	signature, sigErr := sgn.Signature(string(body))
	if sigErr != nil {
		return nil, sigErr
	}
	headerJSON, hjErr := buildWatchListHeaderJSON(sys)
	if hjErr != nil {
		return nil, hjErr
	}
	return &BuiltWatchListRequest{Body: body, Signature: signature, HeaderJSON: headerJSON}, nil
}

// encryptWatchListItem 对单个 item 的固定字段做 ECIES 原位置换(标准 Base64)。
// itemValue 必须存在且为 string(缺席/类型不符=装配期 ErrParam,宁拒勿猜);
// reason 存在才加密,缺席保持缺席。
func encryptWatchListItem(item map[string]any, sgn *Signer) (map[string]any, error) {
	for _, key := range watchListSecretKeys {
		v, ok := item[key]
		if !ok || v == nil {
			if key == "itemValue" {
				return nil, fmt.Errorf("%w: watch list item missing itemValue", ErrParamAlias)
			}
			continue // reason 允许缺席(NON_NULL:整键不出现)
		}
		s, isStr := v.(string)
		if !isStr {
			return nil, fmt.Errorf("%w: watch list %q must be string, got %T",
				ErrParamAlias, key, v)
		}
		ct, encErr := Encrypt(sgn.PublicKey(), []byte(s))
		if encErr != nil {
			return nil, fmt.Errorf("%w: encrypt watch list %q: %v", errPipeline, key, encErr)
		}
		item[key] = base64.StdEncoding.EncodeToString(ct)
	}
	return item, nil
}

// buildWatchListHeaderJSON 按 bean 序输出仅含五个注入键的头明文(空值跳过,
// firstSkip 语义与问询头一致)。刻意不升序——与 buildHeaderJSON 同属
// "bean 声明序"这第二种确定序,只是键集只剩注入键。
func buildWatchListHeaderJSON(sys SystemFields) (string, error) {
	values := map[string]any{
		"traceId": sys.TraceID, "requestIp": sys.RequestIP, "requestTime": sys.RequestTime,
		"clientVersion": sys.ClientVersion, "clientId": sys.ClientID,
	}
	e := &canonEncoder{}
	e.buf = append(e.buf, '{')
	first := true
	for _, k := range watchListHeaderBeanOrder {
		v, ok := values[k]
		if !ok || firstSkip(v) {
			continue
		}
		if !first {
			e.buf = append(e.buf, ',')
		}
		first = false
		e.writeString(k)
		e.buf = append(e.buf, ':')
		e.writeValue(v, 1) // 头字段是受控标量集,永不触达深度上限
	}
	e.buf = append(e.buf, '}')
	if e.err != nil {
		return "", fmt.Errorf("%w: watch list header json: %v", errPipeline, e.err)
	}
	return string(e.buf), nil
}
