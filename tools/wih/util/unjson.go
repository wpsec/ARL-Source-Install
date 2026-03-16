package util

import "encoding/json"

// Unjson 将 JSON 文本解析为 map。
func Unjson(jsonText string) map[string]any {
	data := make(map[string]any)
	if err := json.Unmarshal([]byte(jsonText), &data); err != nil {
		ErrPrint(err)
		return nil
	}
	return data
}
