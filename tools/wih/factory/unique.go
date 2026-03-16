package factory

import "strings"

// uniqueStrings 去重并清洗字符串列表。
func uniqueStrings(items []string) []string {
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{})
	for _, raw := range items {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}
