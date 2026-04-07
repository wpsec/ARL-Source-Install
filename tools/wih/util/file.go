package util

import (
	"bufio"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed rules_embed.yaml
var embeddedRulesFS embed.FS

// ReadFile2Line 按行读取文件并返回去空白后的结果。
func ReadFile2Line(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		ErrPrint(fmt.Errorf("打开文件失败 %s: %w", filePath, err))
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	results := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		results = append(results, line)
	}

	if err = scanner.Err(); err != nil {
		ErrPrint(fmt.Errorf("读取文件失败 %s: %w", filePath, err))
		return nil
	}
	return results
}

// ReadFile2Byte 读取整个文件并返回字节数组。
func ReadFile2Byte(filePath string) []byte {
	content, err := os.ReadFile(filePath)
	if err != nil {
		ErrPrint(fmt.Errorf("读取文件失败 %s: %w", filePath, err))
		return nil
	}
	return content
}

// ReadFile2Str 读取整个文件并返回字符串。
func ReadFile2Str(filePath string) string {
	return string(ReadFile2Byte(filePath))
}

// WriteFile 以 append 模式写入文件。
func WriteFile(filePath string, content string) {
	if err := ensureParentDir(filePath); err != nil {
		ErrPrint(fmt.Errorf("创建目录失败 %s: %w", filePath, err))
		return
	}
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		ErrPrint(fmt.Errorf("写入文件失败 %s: %w", filePath, err))
		return
	}
	defer file.Close()

	if _, err = file.WriteString(content); err != nil {
		ErrPrint(fmt.Errorf("写入文件失败 %s: %w", filePath, err))
	}
}

// WriteFileOverwrite 以覆盖模式写入文件。
func WriteFileOverwrite(filePath string, content string) {
	if err := ensureParentDir(filePath); err != nil {
		ErrPrint(fmt.Errorf("创建目录失败 %s: %w", filePath, err))
		return
	}
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		ErrPrint(fmt.Errorf("覆盖写入文件失败 %s: %w", filePath, err))
	}
}

// EnsureRuleTemplate 初始化规则模板到 config/rules.yml。
func EnsureRuleTemplate() {
	targetPath := filepath.Join("config", "rules.yml")
	if _, err := os.Stat(targetPath); err == nil {
		return
	}

	if err := os.MkdirAll("config", 0o755); err != nil {
		ErrPrint(fmt.Errorf("创建目录失败 config: %w", err))
		return
	}

	content, err := embeddedRulesFS.ReadFile("rules_embed.yaml")
	if err != nil {
		ErrPrint(fmt.Errorf("读取内置规则模板失败: %w", err))
		return
	}

	if err = os.WriteFile(targetPath, content, 0o644); err != nil {
		ErrPrint(fmt.Errorf("写入规则模板失败 %s: %w", targetPath, err))
	}
}

// GenerateRuleTemplate 输出规则模板（stdout 或指定文件）。
func GenerateRuleTemplate(outputPath string) error {
	content, err := embeddedRulesFS.ReadFile("rules_embed.yaml")
	if err != nil {
		return fmt.Errorf("读取内置规则模板失败: %w", err)
	}

	if outputPath == "" || outputPath == "-" {
		fmt.Print(string(content))
		return nil
	}

	if err = ensureParentDir(outputPath); err != nil {
		return fmt.Errorf("创建目录失败 %s: %w", outputPath, err)
	}
	if err = os.WriteFile(outputPath, content, 0o644); err != nil {
		return fmt.Errorf("写入规则模板失败 %s: %w", outputPath, err)
	}
	return nil
}

// ReadEmbeddedRuleTemplate 读取内置规则模板内容。
func ReadEmbeddedRuleTemplate() []byte {
	content, err := embeddedRulesFS.ReadFile("rules_embed.yaml")
	if err != nil {
		return nil
	}
	return content
}

// FileExists 判断路径是否存在且为普通文件。
func FileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	return err == nil && !info.IsDir()
}

func ensureParentDir(filePath string) error {
	path := strings.TrimSpace(filePath)
	if path == "" || path == "-" {
		return nil
	}

	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
