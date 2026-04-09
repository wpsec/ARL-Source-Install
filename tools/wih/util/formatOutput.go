package util

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	if ShouldWriteWorkbookOutput(writePath, outputJSON) {
		if err := writeWorkbookOutput(result, ResolveWorkbookPath(writePath)); err != nil {
			ErrPrint(err)
		}
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
	writeStructuredEndpointCSV(endpointCSVPath(endpointPath), result.Endpoints)
	writeStructuredParameterCSV(parameterCSVPath(parameterPath), result.Parameters)
}

// ResolveStructuredOutputPaths 根据主输出文件推导结构化输出文件路径。
func ResolveStructuredOutputPaths(mainOutputPath string, targetURL string, endpointOutputPath string, parameterOutputPath string) (string, string) {
	resolvedMainPath := ResolveOutputPathForTarget(targetURL, mainOutputPath)
	endpointPath := strings.TrimSpace(endpointOutputPath)
	parameterPath := strings.TrimSpace(parameterOutputPath)
	if endpointPath != "" || parameterPath != "" {
		return ResolveOutputPathInScope(resolvedMainPath, targetURL, endpointPath), ResolveOutputPathInScope(resolvedMainPath, targetURL, parameterPath)
	}

	mainPath := strings.TrimSpace(resolvedMainPath)
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

func writeStructuredEndpointCSV(writePath string, items []datatype.EndpointRecord) {
	writeStructuredCSVTable(writePath, buildEndpointCSVTable(items))
}

func writeStructuredParameterCSV(writePath string, items []datatype.ParameterRecord) {
	writeStructuredCSVTable(writePath, buildParameterCSVTable(items))
}

func writeStructuredCSVTable(writePath string, table [][]string) {
	path := strings.TrimSpace(writePath)
	if path == "" || len(table) == 0 {
		return
	}

	isNewFile := !FileExists(path)
	if err := ensureParentDir(path); err != nil {
		ErrPrint(fmt.Errorf("创建目录失败 %s: %w", path, err))
		return
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		ErrPrint(fmt.Errorf("写入 CSV 文件失败 %s: %w", path, err))
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	startIndex := 0
	if !isNewFile && len(table) > 1 {
		startIndex = 1
	}
	for index, row := range table {
		if index < startIndex {
			continue
		}
		if err = writer.Write(row); err != nil {
			ErrPrint(fmt.Errorf("写入 CSV 内容失败 %s: %w", path, err))
			return
		}
	}
	writer.Flush()
	if err = writer.Error(); err != nil {
		ErrPrint(fmt.Errorf("刷新 CSV 失败 %s: %w", path, err))
	}
}

func endpointCSVPath(jsonPath string) string {
	return structuredCSVPath(jsonPath)
}

func parameterCSVPath(jsonPath string) string {
	return structuredCSVPath(jsonPath)
}

func structuredCSVPath(path string) string {
	text := strings.TrimSpace(path)
	if text == "" || text == "-" {
		return ""
	}
	ext := filepath.Ext(text)
	if ext == "" {
		return text + ".csv"
	}
	return strings.TrimSuffix(text, ext) + ".csv"
}

func firstNonEmptyStructuredText(values ...string) string {
	for _, value := range values {
		text := strings.TrimSpace(value)
		if text != "" {
			return text
		}
	}
	return ""
}

func ShouldWriteWorkbookOutput(writePath string, outputJSON bool) bool {
	return !outputJSON && global.OutputMode == "csv" && strings.TrimSpace(writePath) != "" && strings.TrimSpace(writePath) != "-"
}

func ShouldWriteTaskAggregateOutput(writePath string, outputJSON bool, autoSaveName bool) bool {
	if outputJSON || global.OutputMode != "csv" {
		return false
	}

	path := strings.TrimSpace(writePath)
	if path != "" && path != "-" {
		return true
	}
	return autoSaveName
}

func writeWorkbookOutput(result *datatype.ScanResult, writePath string) error {
	if result == nil {
		return nil
	}
	sheets := make([]workbookSheet, 0, 3)
	if recordsSheet := buildRecordsCSVTable(result); len(recordsSheet) > 0 {
		sheets = append(sheets, workbookSheet{Name: "记录", Rows: recordsSheet})
	}
	if endpointsSheet := buildEndpointCSVTable(result.Endpoints); len(endpointsSheet) > 0 {
		sheets = append(sheets, workbookSheet{Name: "接口", Rows: endpointsSheet})
	}
	if parametersSheet := buildParameterCSVTable(result.Parameters); len(parametersSheet) > 0 {
		sheets = append(sheets, workbookSheet{Name: "参数", Rows: parametersSheet})
	}
	return writeWorkbookFile(writePath, sheets)
}

// WriteAggregateCSVOutput 将多目标主记录汇总到单个 CSV 文件。
func WriteAggregateCSVOutput(results []*datatype.ScanResult, writePath string) error {
	filtered := normalizeAggregateResults(results)
	if len(filtered) == 0 {
		return nil
	}

	table := buildAggregateRecordsCSVTable(filtered)
	if len(table) == 0 {
		return nil
	}
	return writeCSVTableOverwrite(writePath, table)
}

// WriteAggregateWorkbookOutput 将多目标结果汇总到一个工作簿。
func WriteAggregateWorkbookOutput(results []*datatype.ScanResult, writePath string) error {
	filtered := normalizeAggregateResults(results)
	if len(filtered) == 0 {
		return nil
	}

	sheets := make([]workbookSheet, 0, 3)
	if recordsSheet := buildAggregateRecordsCSVTable(filtered); len(recordsSheet) > 0 {
		sheets = append(sheets, workbookSheet{Name: "记录", Rows: recordsSheet})
	}
	if endpointsSheet := buildAggregateEndpointCSVTable(filtered); len(endpointsSheet) > 0 {
		sheets = append(sheets, workbookSheet{Name: "接口", Rows: endpointsSheet})
	}
	if parametersSheet := buildAggregateParameterCSVTable(filtered); len(parametersSheet) > 0 {
		sheets = append(sheets, workbookSheet{Name: "参数", Rows: parametersSheet})
	}
	return writeWorkbookFile(writePath, sheets)
}

func normalizeAggregateResults(results []*datatype.ScanResult) []*datatype.ScanResult {
	filtered := make([]*datatype.ScanResult, 0, len(results))
	for _, result := range results {
		if result == nil {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}

func writeCSVTableOverwrite(writePath string, table [][]string) error {
	path := strings.TrimSpace(writePath)
	if path == "" || path == "-" || len(table) == 0 {
		return nil
	}

	if err := ensureParentDir(path); err != nil {
		return fmt.Errorf("创建目录失败 %s: %w", path, err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("写入 CSV 文件失败 %s: %w", path, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	for _, row := range table {
		if err = writer.Write(row); err != nil {
			return fmt.Errorf("写入 CSV 内容失败 %s: %w", path, err)
		}
	}
	writer.Flush()
	if err = writer.Error(); err != nil {
		return fmt.Errorf("刷新 CSV 失败 %s: %w", path, err)
	}
	return nil
}

func buildRecordsCSVTable(result *datatype.ScanResult) [][]string {
	if result == nil || len(result.Records) == 0 {
		return nil
	}

	rows := [][]string{
		{"目标", "类型", "URL", "内容", "状态码", "标题", "大小", "来源", "标签", "哈希"},
	}
	for _, record := range result.Records {
		urlText := ""
		contentText := record.Content
		statusText := ""
		titleText := ""
		sizeText := ""

		if strings.EqualFold(strings.TrimSpace(record.Id), "path_url") || strings.EqualFold(strings.TrimSpace(record.Id), "page_url") {
			urlText = strings.TrimSpace(record.Content)
			contentText = ""
		}
		if statusValue, titleValue, sizeValue := extractRecordStatusTitleAndSize(record.Tag); statusValue != "" || titleValue != "" || sizeValue != "" {
			statusText = statusValue
			titleText = titleValue
			sizeText = sizeValue
		}

		rows = append(rows, []string{
			result.Target,
			record.Id,
			urlText,
			contentText,
			statusText,
			titleText,
			sizeText,
			record.Source,
			record.Tag,
			fmt.Sprintf("%d", record.Hash),
		})
	}
	return rows
}

func buildEndpointCSVTable(items []datatype.EndpointRecord) [][]string {
	if len(items) == 0 {
		return nil
	}
	rows := [][]string{
		{
			"接口ID", "站点", "页面URL", "接口URL", "路径", "方法", "协议",
			"来源类型", "触发页面", "触发事件", "触发提示",
			"内容类型", "正文类型", "状态码", "响应大小", "置信度", "请求报文",
		},
	}
	for _, item := range items {
		rows = append(rows, []string{
			item.EndpointID,
			item.Site,
			item.PageURL,
			item.URL,
			item.Path,
			item.Method,
			item.Protocol,
			strings.Join(item.SourceTypes, "|"),
			item.TriggerContext.Page,
			item.TriggerContext.Event,
			item.TriggerContext.DOMHint,
			item.ContentType,
			item.BodyKind,
			formatOptionalInt(item.ResponseStatus),
			formatOptionalInt64(item.ResponseSize),
			fmt.Sprintf("%.2f", item.Confidence),
			firstNonEmptyStructuredText(strings.TrimSpace(item.RequestTemplate.RequestPacket), formatEndpointTextBlock(item, nil)),
		})
	}
	return rows
}

func buildParameterCSVTable(items []datatype.ParameterRecord) [][]string {
	if len(items) == 0 {
		return nil
	}
	rows := [][]string{
		{
			"参数ID", "接口ID", "参数名", "位置", "参数类型", "必填",
			"示例", "默认值", "枚举", "来源", "页面URL", "JS文件", "Schema库",
			"敏感", "熵", "置信度", "出现次数",
		},
	}
	for _, item := range items {
		rows = append(rows, []string{
			item.ParameterID,
			item.EndpointID,
			item.ParamName,
			item.Location,
			item.ParamType,
			fmt.Sprintf("%t", item.Required),
			item.Example,
			item.Default,
			strings.Join(item.Enum, "|"),
			item.Source,
			item.SourceDetail.PageURL,
			item.SourceDetail.JSFile,
			item.SourceDetail.SchemaLib,
			fmt.Sprintf("%t", item.IsPII),
			fmt.Sprintf("%.4f", item.Entropy),
			fmt.Sprintf("%.2f", item.Confidence),
			fmt.Sprintf("%d", item.OccurrenceCount),
		})
	}
	return rows
}

func buildAggregateRecordsCSVTable(results []*datatype.ScanResult) [][]string {
	rows := make([][]string, 0)
	for _, result := range results {
		table := buildRecordsCSVTable(result)
		if len(table) == 0 {
			continue
		}
		if len(rows) == 0 {
			rows = append(rows, table[0])
		}
		rows = append(rows, table[1:]...)
	}
	return rows
}

func buildAggregateEndpointCSVTable(results []*datatype.ScanResult) [][]string {
	rows := [][]string{
		{
			"目标", "接口ID", "站点", "页面URL", "接口URL", "路径", "方法", "协议",
			"来源类型", "触发页面", "触发事件", "触发提示",
			"内容类型", "正文类型", "状态码", "响应大小", "置信度", "请求报文",
		},
	}
	for _, result := range results {
		if result == nil {
			continue
		}
		for _, item := range result.Endpoints {
			rows = append(rows, []string{
				result.Target,
				item.EndpointID,
				item.Site,
				item.PageURL,
				item.URL,
				item.Path,
				item.Method,
				item.Protocol,
				strings.Join(item.SourceTypes, "|"),
				item.TriggerContext.Page,
				item.TriggerContext.Event,
				item.TriggerContext.DOMHint,
				item.ContentType,
				item.BodyKind,
				formatOptionalInt(item.ResponseStatus),
				formatOptionalInt64(item.ResponseSize),
				fmt.Sprintf("%.2f", item.Confidence),
				firstNonEmptyStructuredText(strings.TrimSpace(item.RequestTemplate.RequestPacket), formatEndpointTextBlock(item, nil)),
			})
		}
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func buildAggregateParameterCSVTable(results []*datatype.ScanResult) [][]string {
	rows := [][]string{
		{
			"目标", "参数ID", "接口ID", "参数名", "位置", "参数类型", "必填",
			"示例", "默认值", "枚举", "来源", "页面URL", "JS文件", "Schema库",
			"敏感", "熵", "置信度", "出现次数",
		},
	}
	for _, result := range results {
		if result == nil {
			continue
		}
		for _, item := range result.Parameters {
			rows = append(rows, []string{
				result.Target,
				item.ParameterID,
				item.EndpointID,
				item.ParamName,
				item.Location,
				item.ParamType,
				fmt.Sprintf("%t", item.Required),
				item.Example,
				item.Default,
				strings.Join(item.Enum, "|"),
				item.Source,
				item.SourceDetail.PageURL,
				item.SourceDetail.JSFile,
				item.SourceDetail.SchemaLib,
				fmt.Sprintf("%t", item.IsPII),
				fmt.Sprintf("%.4f", item.Entropy),
				fmt.Sprintf("%.2f", item.Confidence),
				fmt.Sprintf("%d", item.OccurrenceCount),
			})
		}
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func formatOptionalInt(value int) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", value)
}

func formatOptionalInt64(value int64) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", value)
}

// renderText 生成文本输出。
func renderText(result *datatype.ScanResult) string {
	if len(result.Records) == 0 && len(result.Endpoints) == 0 && len(result.Parameters) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("[+] %s\n", result.Target))
	for _, record := range result.Records {
		line := fmt.Sprintf("    %s: %s", record.Id, record.Content)
		if strings.TrimSpace(record.Tag) != "" {
			line += "    [" + strings.TrimSpace(record.Tag) + "]"
		}
		builder.WriteString(line + "\n")
	}
	if len(result.Endpoints) > 0 {
		builder.WriteString("    [endpoints]\n")
		parameterMap, orphans := groupParametersByEndpoint(result.Endpoints, result.Parameters)
		for _, endpoint := range result.Endpoints {
			writeIndentedBlock(&builder, "      ", formatEndpointTextBlock(endpoint, parameterMap[endpoint.EndpointID]))
			builder.WriteString("\n")
		}
		if len(orphans) > 0 {
			builder.WriteString("    [parameters]\n")
			for _, parameter := range orphans {
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
	} else if len(result.Parameters) > 0 {
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

func formatEndpointTextBlock(endpoint datatype.EndpointRecord, parameters []datatype.ParameterRecord) string {
	packetText := strings.TrimSpace(endpoint.RequestTemplate.RequestPacket)
	if packetText != "" {
		return packetText
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s %s", endpoint.Method, endpoint.URL))
	for _, summary := range summarizeEndpointParameters(parameters) {
		builder.WriteString("\n" + summary)
	}
	return builder.String()
}

func writeIndentedBlock(builder *strings.Builder, indent string, block string) {
	if builder == nil {
		return
	}

	text := strings.TrimRight(block, "\n")
	if text == "" {
		return
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			builder.WriteString("\n")
			continue
		}
		builder.WriteString(indent + line + "\n")
	}
}

func groupParametersByEndpoint(endpoints []datatype.EndpointRecord, parameters []datatype.ParameterRecord) (map[string][]datatype.ParameterRecord, []datatype.ParameterRecord) {
	grouped := make(map[string][]datatype.ParameterRecord)
	knownEndpointIDs := make(map[string]struct{})
	for _, endpoint := range endpoints {
		endpointID := strings.TrimSpace(endpoint.EndpointID)
		if endpointID == "" {
			continue
		}
		knownEndpointIDs[endpointID] = struct{}{}
	}

	orphans := make([]datatype.ParameterRecord, 0)
	for _, parameter := range parameters {
		endpointID := strings.TrimSpace(parameter.EndpointID)
		if endpointID == "" {
			orphans = append(orphans, parameter)
			continue
		}
		if _, ok := knownEndpointIDs[endpointID]; !ok {
			orphans = append(orphans, parameter)
			continue
		}
		grouped[endpointID] = append(grouped[endpointID], parameter)
	}
	return grouped, orphans
}

func summarizeEndpointParameters(parameters []datatype.ParameterRecord) []string {
	if len(parameters) == 0 {
		return nil
	}
	locationOrder := []string{"query", "path", "body", "header", "graphql_variable", "cookie"}
	locationBuckets := make(map[string][]string)

	for _, parameter := range parameters {
		location := strings.TrimSpace(parameter.Location)
		if location == "" {
			location = "body"
		}
		label := strings.TrimSpace(parameter.ParamName)
		paramType := strings.TrimSpace(parameter.ParamType)
		if paramType != "" && paramType != "unknown" {
			label += "(" + paramType + ")"
		}
		if parameter.Required {
			label += "!"
		}
		if strings.TrimSpace(parameter.Default) != "" {
			label += "=" + parameter.Default
		} else if strings.TrimSpace(parameter.Example) != "" {
			label += "~" + parameter.Example
		}
		locationBuckets[location] = append(locationBuckets[location], label)
	}

	result := make([]string, 0, len(locationBuckets))
	seen := make(map[string]struct{})
	for _, location := range locationOrder {
		items := uniqueStrings(locationBuckets[location])
		if len(items) == 0 {
			continue
		}
		seen[location] = struct{}{}
		result = append(result, fmt.Sprintf("%s: %s", location, strings.Join(items, ", ")))
	}

	extraLocations := make([]string, 0)
	for location := range locationBuckets {
		if _, ok := seen[location]; ok {
			continue
		}
		extraLocations = append(extraLocations, location)
	}
	if len(extraLocations) > 0 {
		sort.Strings(extraLocations)
		for _, location := range extraLocations {
			items := uniqueStrings(locationBuckets[location])
			if len(items) == 0 {
				continue
			}
			result = append(result, fmt.Sprintf("%s: %s", location, strings.Join(items, ", ")))
		}
	}
	return result
}

func uniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// renderMarkdown 生成 Markdown 表格输出。
func renderMarkdown(result *datatype.ScanResult) string {
	if len(result.Records) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("## %s\n\n", result.Target))
	builder.WriteString("| 类型 | 内容 | 来源 | 标签 |\n")
	builder.WriteString("| --- | --- | --- | --- |\n")
	for _, record := range result.Records {
		builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", escapePipes(record.Id), escapePipes(record.Content), escapePipes(record.Source), escapePipes(record.Tag)))
	}
	builder.WriteString("\n")
	return builder.String()
}

// renderCSV 生成 CSV 输出（每个目标包含表头）。
func renderCSV(result *datatype.ScanResult) string {
	table := buildRecordsCSVTable(result)
	if len(table) == 0 {
		return ""
	}
	builder := &strings.Builder{}
	writer := csv.NewWriter(builder)
	for _, row := range table {
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
	builder.WriteString("<thead><tr><th>类型</th><th>内容</th><th>来源</th><th>标签</th><th>哈希</th></tr></thead>\n<tbody>\n")
	for _, record := range result.Records {
		builder.WriteString("<tr>")
		builder.WriteString("<td>" + htmlEscape(record.Id) + "</td>")
		builder.WriteString("<td>" + htmlEscape(record.Content) + "</td>")
		builder.WriteString("<td>" + htmlEscape(record.Source) + "</td>")
		builder.WriteString("<td>" + htmlEscape(record.Tag) + "</td>")
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

func extractRecordStatusAndTitle(tag string) (string, string) {
	statusText, titleText, _ := extractRecordStatusTitleAndSize(tag)
	return statusText, titleText
}

func extractRecordStatusTitleAndSize(tag string) (string, string, string) {
	text := strings.TrimSpace(tag)
	if text == "" {
		return "", "", ""
	}

	statusText := ""
	if statusIndex := strings.Index(text, "status="); statusIndex >= 0 {
		start := statusIndex + len("status=")
		end := start
		for end < len(text) && text[end] >= '0' && text[end] <= '9' {
			end++
		}
		statusText = strings.TrimSpace(text[start:end])
	}

	titleText := ""
	if titleIndex := strings.Index(text, "title="); titleIndex >= 0 {
		titleText = strings.TrimSpace(text[titleIndex+len("title="):])
		if sizeIndex := strings.Index(titleText, " size="); sizeIndex >= 0 {
			titleText = strings.TrimSpace(titleText[:sizeIndex])
		}
	}

	sizeText := ""
	if sizeIndex := strings.Index(text, "size="); sizeIndex >= 0 {
		start := sizeIndex + len("size=")
		end := start
		for end < len(text) && text[end] >= '0' && text[end] <= '9' {
			end++
		}
		sizeText = strings.TrimSpace(text[start:end])
	}

	return statusText, titleText, sizeText
}
