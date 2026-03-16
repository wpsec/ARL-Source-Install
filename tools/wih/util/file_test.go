package util

import "testing"

// TestFileExists 验证文件存在检查。
func TestFileExists(t *testing.T) {
	if !FileExists("file.go") {
		t.Fatal("当前目录 file.go 应存在")
	}
	if FileExists("not-exists-xxx.txt") {
		t.Fatal("不存在文件不应返回 true")
	}
}
