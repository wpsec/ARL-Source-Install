package util

import "testing"

// TestUnjson 验证 JSON 解析。
func TestUnjson(t *testing.T) {
	jsonText := `{"name":"wih"}`
	data := Unjson(jsonText)
	if data == nil {
		t.Fatal("Unjson 返回 nil")
	}
	if data["name"] != "wih" {
		t.Fatalf("字段解析异常: got=%v", data["name"])
	}
}
