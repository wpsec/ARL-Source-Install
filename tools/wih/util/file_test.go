package util

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFileExists 验证文件存在检查。
func TestFileExists(t *testing.T) {
	if !FileExists("file.go") {
		t.Fatal("当前目录 file.go 应存在")
	}
	if FileExists("not-exists-xxx.txt") {
		t.Fatal("不存在文件不应返回 true")
	}
}

// TestWriteFileCreatesParentDir 验证写文件时会自动创建父目录。
func TestWriteFileCreatesParentDir(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "output", "result", "result.csv")
	WriteFile(targetPath, "demo")

	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read file failed: %v", err)
	}
	if string(content) != "demo" {
		t.Fatalf("unexpected file content: %s", string(content))
	}
}

// TestWriteFileOverwriteCreatesParentDir 验证覆盖写入时会自动创建父目录。
func TestWriteFileOverwriteCreatesParentDir(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "output", "result", "result.json")
	WriteFileOverwrite(targetPath, `{"ok":true}`)

	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read file failed: %v", err)
	}
	if string(content) != `{"ok":true}` {
		t.Fatalf("unexpected file content: %s", string(content))
	}
}
