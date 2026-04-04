package util

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	datatype "wih/dataType"
	"wih/global"

	"github.com/gookit/color"
)

// FormatOutput 按当前模式输出到标准输出。
func FormatOutput(result *datatype.ScanResult, outputJSON bool) {
	if result == nil || global.LogLevel == "zero" {
		return
	}

	content := renderResult(result, outputJSON)
	if strings.TrimSpace(content) == "" {
		return
	}

	if global.DisableColor || outputJSON || global.OutputMode != "text" {
		fmt.Print(content)
		return
	}
	color.C256(46).Print(content)
}

// FormatOutputWrite 按当前模式输出到文件。
func FormatOutputWrite(result *datatype.ScanResult, writePath string, outputJSON bool) {
	if result == nil {
		return
	}
	if writePath == "" || writePath == "-" {
		return
	}

	content := renderResult(result, outputJSON)
	if strings.TrimSpace(content) == "" {
		return
	}
	WriteFile(writePath, content)
}

// WriteStructuredOutputFiles 将 endpoint/parameter 结构化结果独立落盘。
func WriteStructuredOutputFiles(result *datatype.ScanResult, endpointPath string, parameterPath string) {
	if result == nil {
		return
	}
	writeStructuredJSON(endpointPath, result.Endpoints)
	writeStructuredJSON(parameterPath, result.Parameters)
}

// ResolveStructuredOutputPaths 根据主输出文件推导结构化输出文件路径。
func ResolveStructuredOutputPaths(mainOutputPath string, endpointOutputPath string, parameterOutputPath string) (string, string) {
	endpointPath := strings.TrimSpace(endpointOutputPath)
	parameterPath := strings.TrimSpace(parameterOutputPath)
	if endpointPath != "" || parameterPath != "" {
		return endpointPath, parameterPath
	}

	mainPath := strings.TrimSpace(mainOutputPath)
	if mainPath == "" || mainPath == "-" {
		return "", ""
	}

	ext := filepath.Ext(mainPath)
	base := strings.TrimSuffix(mainPath, ext)
	if base == "" {
		base = mainPath
	}
	return base + "_endpoint.json", base + "_parameter.json"
}

// renderResult 将扫描结果渲染为指定格式。
func renderResult(result *datatype.ScanResult, outputJSON bool) string {
	if result == nil {
		return ""
	}
	if outputJSON {
		line, err := json.Marshal(result)
		if err != nil {
			ErrPrint(err)
			return ""
		}
		return string(line) + "\n"
	}

	switch global.OutputMode {
	case "csv":
		return renderCSV(result)
	case "html":
		return renderHTML(result)
	case "md":
		return renderMarkdown(result)
	default:
		return renderText(result)
	}
}

func writeStructuredJSON[T any](writePath string, items []T) {
	path := strings.TrimSpace(writePath)
	if path == "" {
		return
	}
	if len(items) == 0 {
		return
	}

	mergedItems := make([]T, 0)
	if FileExists(path) {
		raw := strings.TrimSpace(ReadFile2Str(path))
		if raw != "" {
			var existing []T
			if err := json.Unmarshal([]byte(raw), &existing); err == nil {
				mergedItems = append(mergedItems, existing...)
			}
		}
	}
	mergedItems = append(mergedItems, items...)

	data, err := json.MarshalIndent(mergedItems, "", "  ")
	if err != nil {
		ErrPrint(err)
		return
	}
	if !strings.HasSuffix(string(data), "\n") {
		data = append(data, '\n')
	}
	WriteFileOverwrite(path, string(data))
}

// renderText 生成文本输出。
func renderText(result *datatype.ScanResult) string {
	if len(result.Records) == 0 && len(result.Endpoints) == 0 && len(result.Parameters) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("[+] %s\n", result.Target))
	for _, record := range result.Records {
		builder.WriteString(fmt.Sprintf("    %s: %s\n", record.Id, record.Content))
	}
	if len(result.Endpoints) > 0 {
		builder.WriteString("    [endpoints]\n")
		for _, endpoint := range result.Endpoints {
			builder.WriteString(fmt.Sprintf("      %s %s\n", endpoint.Method, endpoint.URL))
		}
	}
	if len(result.Parameters) > 0 {
		builder.WriteString("    [parameters]\n")
		for _, parameter := range result.Parameters {
			builder.WriteString(
				fmt.Sprintf(
					"      %s (%s/%s)\n",
					parameter.ParamName,
					parameter.Location,
					parameter.ParamType,
				),
			)
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

// renderMarkdown 生成 Markdown 表格输出。
func renderMarkdown(result *datatype.ScanResult) string {
	if len(result.Records) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("## %s\n\n", result.Target))
	builder.WriteString("| 类型 | 内容 | 来源 |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, record := range result.Records {
		builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n", escapePipes(record.Id), escapePipes(record.Content), escapePipes(record.Source)))
	}
	builder.WriteString("\n")
	return builder.String()
}

// renderCSV 生成 CSV 输出（每个目标包含表头）。
func renderCSV(result *datatype.ScanResult) string {
	if len(result.Records) == 0 {
		return ""
	}
	builder := &strings.Builder{}
	writer := csv.NewWriter(builder)
	if err := writer.Write([]string{"target", "id", "content", "source", "hash"}); err != nil {
		ErrPrint(err)
		return ""
	}
	for _, record := range result.Records {
		row := []string{result.Target, record.Id, record.Content, record.Source, fmt.Sprintf("%d", record.Hash)}
		if err := writer.Write(row); err != nil {
			ErrPrint(err)
			return ""
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		ErrPrint(err)
		return ""
	}
	return builder.String()
}

// renderHTML 生成 HTML 表格输出。
func renderHTML(result *datatype.ScanResult) string {
	if len(result.Records) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("<h3>%s</h3>\n", htmlEscape(result.Target)))
	builder.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"4\">\n")
	builder.WriteString("<thead><tr><th>类型</th><th>内容</th><th>来源</th><th>哈希</th></tr></thead>\n<tbody>\n")
	for _, record := range result.Records {
		builder.WriteString("<tr>")
		builder.WriteString("<td>" + htmlEscape(record.Id) + "</td>")
		builder.WriteString("<td>" + htmlEscape(record.Content) + "</td>")
		builder.WriteString("<td>" + htmlEscape(record.Source) + "</td>")
		builder.WriteString("<td>" + fmt.Sprintf("%d", record.Hash) + "</td>")
		builder.WriteString("</tr>\n")
	}
	builder.WriteString("</tbody>\n</table>\n")
	return builder.String()
}

// escapePipes 转义 Markdown 管道符。
func escapePipes(value string) string {
	return strings.ReplaceAll(value, "|", `\|`)
}

// htmlEscape 做最小化 HTML 转义。
func htmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}
