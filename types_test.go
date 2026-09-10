package riskclient

import (
	"encoding/json"
	"testing"
)

// TestAuditCaseResultAuditTimeTolerance 锁定 auditTime 数值/字符串双形态兼容
// (个别历史环境曾以字符串下发)。回归点:回退路径曾对原始报文
// 直接重解析,在同一字段上以同样原因再次失败,字符串兼容实际不生效。
func TestAuditCaseResultAuditTimeTolerance(t *testing.T) {
	var num AuditCaseResult
	if err := json.Unmarshal([]byte(`{"caseNo":"C-1","auditTime":1756272000000}`), &num); err != nil {
		t.Fatalf("数字形态应可解析: %v", err)
	}
	var str AuditCaseResult
	if err := json.Unmarshal([]byte(`{"caseNo":"C-2","auditTime":"1756272000000","remark":"ok"}`), &str); err != nil {
		t.Fatalf("字符串形态应可解析: %v", err)
	}
	if num.AuditTime != 1756272000000 || str.AuditTime != 1756272000000 ||
		str.CaseNo != "C-2" || str.Remark != "ok" {
		t.Fatalf("两形态应等价: num=%+v str=%+v", num, str)
	}

	var bad AuditCaseResult
	if err := json.Unmarshal([]byte(`{"auditTime":"abc"}`), &bad); err == nil {
		t.Fatal("不可解析的字符串应报错")
	}

	// 非 auditTime 字段的真问题照常上抛(不被兼容逻辑吞掉)
	var other AuditCaseResult
	if err := json.Unmarshal([]byte(`{"caseNo":123,"auditTime":"5"}`), &other); err == nil {
		t.Fatal("非 auditTime 字段类型错误应照常报错")
	}
}
