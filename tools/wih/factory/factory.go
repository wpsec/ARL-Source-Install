package factory

import (
	"strings"
	datatype "wih/dataType"
)

// Factory 根据参数选择目标输入源并返回去重后的目标列表。
func Factory(option *datatype.Option) []string {
	if option == nil {
		return nil
	}

	if strings.TrimSpace(option.JsonFilePath) != "" {
		return factoryJSON(option.JsonFilePath)
	}
	if strings.TrimSpace(option.FilePath) != "" {
		return factoryFile(option.FilePath)
	}
	if strings.TrimSpace(option.URL) != "" {
		return []string{strings.TrimSpace(option.URL)}
	}
	return nil
}
