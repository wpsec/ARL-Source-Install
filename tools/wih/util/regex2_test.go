package util

import "testing"

// TestRegex2Limit 验证正则匹配数量限制。
func TestRegex2Limit(t *testing.T) {
	result, err := Regex2Limit("a1 a2 a3", `a\d`, 2)
	if err != nil {
		t.Fatalf("Regex2Limit 返回错误: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("Regex2Limit 数量异常: got=%d", len(result))
	}
}
