package factory

import "wih/util"

// factoryFile 从文本文件读取目标列表。
func factoryFile(filePath string) []string {
	return uniqueStrings(util.ReadFile2Line(filePath))
}
