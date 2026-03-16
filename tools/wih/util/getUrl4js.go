package util

import "strings"

// GetURLFromJSONResult 从 JSON 文本中提取 "source" 字段中的 URL。
// 该能力用于兼容历史输入场景（jsonPath）。
func GetURLFromJSONResult(data string) []string {
	results, err := Regex2(data, `(?<="source"\s*:\s*")([^"]+)(?=")`)
	if err != nil {
		ErrPrint(err)
		return nil
	}
	cleaned := make([]string, 0, len(results))
	for _, item := range results {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		cleaned = append(cleaned, value)
	}
	return cleaned
}
