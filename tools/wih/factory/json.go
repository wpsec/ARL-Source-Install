package factory

import "wih/util"

// factoryJSON 从 JSON 输入中提取 source 字段 URL 列表。
func factoryJSON(filePath string) []string {
	jsonText := util.ReadFile2Str(filePath)
	jsURLs := util.GetURLFromJSONResult(jsonText)
	return uniqueStrings(jsURLs)
}
