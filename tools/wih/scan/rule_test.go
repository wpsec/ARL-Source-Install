package scan

import (
	"testing"
	datatype "wih/dataType"
)

// TestResolvePatternBuiltin 验证内置规则可正常取到默认正则。
func TestResolvePatternBuiltin(t *testing.T) {
	item := datatype.Rule{Id: "domain", Enabled: true}
	if resolvePattern(item) == "" {
		t.Fatal("domain 内置规则未返回默认 pattern")
	}
}

// TestMatchExcludeField 验证排除规则字段匹配逻辑。
func TestMatchExcludeField(t *testing.T) {
	if !matchExcludeField("", "anything") {
		t.Fatal("空规则应匹配任意输入")
	}
	if !matchExcludeField("exact", "exact") {
		t.Fatal("精确匹配失败")
	}
	if matchExcludeField("exact", "not-exact") {
		t.Fatal("精确匹配应当失败")
	}
	if !matchExcludeField("regex:^abc", "abc123") {
		t.Fatal("正则匹配失败")
	}
}
