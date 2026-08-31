package protocol

import (
	"crypto/rand"
	"fmt"
)

// NewUUIDv4 生成 RFC 4122 v4 随机 UUID(小写带连字符),对齐 Java 版
// UUID.randomUUID().toString() 的产物形态(case_payload.json 的 traceIdFormat:
// "UUIDv4,小写带连字符")。零第三方依赖:版本位/变体位手工设置后按 8-4-4-4-12 格式化。
//
// 与 java.util.UUID 的唯一可观察差异可能在碰撞概率之外——没有(JVM 同为 122 位随机);
// 测试用例锁定格式与两个位的数学约束。crypto/rand 失败属系统性故障,原样上抛。
func NewUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("protocol: read random for uuid v4: %w", err)
	}
	b[6] = (b[6] & 0x0F) | 0x40 // version 4
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 变体(10xx)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]),
		uint16(b[8])<<8|uint16(b[9]),
		uint64(b[10])<<40|uint64(b[11])<<32|uint64(b[12])<<24|uint64(b[13])<<16|uint64(b[14])<<8|uint64(b[15]),
	), nil
}
