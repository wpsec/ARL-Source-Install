package util

import (
	"archive/zip"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	datatype "wih/dataType"
	"wih/global"
)

// TestResolveStructuredOutputPaths 验证结构化输出路径推导。
func TestResolveStructuredOutputPaths(t *testing.T) {
	previousTimestamp := defaultOutputRunTimestamp
	defaultOutputRunTimestamp = "20260406_120000"
	defer func() { defaultOutputRunTimestamp = previousTimestamp }()

	endpointPath, parameterPath := ResolveStructuredOutputPaths("result.json", "https://example.com", "", "")
	if endpointPath != filepath.Join("output", "example.com_20260406_120000", "result_endpoint.json") {
		t.Fatalf("unexpected endpoint path: %s", endpointPath)
	}
	if parameterPath != filepath.Join("output", "example.com_20260406_120000", "result_parameter.json") {
		t.Fatalf("unexpected parameter path: %s", parameterPath)
	}

	customEndpoint, customParameter := ResolveStructuredOutputPaths("result.json", "https://example.com", "a.json", "b.json")
	if customEndpoint != filepath.Join("output", "example.com_20260406_120000", "a.json") || customParameter != filepath.Join("output", "example.com_20260406_120000", "b.json") {
		t.Fatalf("unexpected custom paths endpoint=%s parameter=%s", customEndpoint, customParameter)
	}
}

// TestResolveOutputPathForTarget 验证相对输出文件会被归入 output/<hostname_timestamp>/。
func TestResolveOutputPathForTarget(t *testing.T) {
	previousTimestamp := defaultOutputRunTimestamp
	defaultOutputRunTimestamp = "20260406_120000"
	defer func() { defaultOutputRunTimestamp = previousTimestamp }()

	if got := ResolveOutputPathForTarget("https://example.com", "result.csv"); got != filepath.Join("output", "example.com_20260406_120000", "result.csv") {
		t.Fatalf("unexpected resolved output path: %s", got)
	}
	if got := ResolveOutputPathForTarget("https://example.com", filepath.Join("custom", "result.csv")); got != filepath.Join("custom", "result.csv") {
		t.Fatalf("unexpected custom output path: %s", got)
	}
}

// TestResolveOutputPathForTargetUsesConfiguredRootDir 验证输出根目录可配置。
func TestResolveOutputPathForTargetUsesConfiguredRootDir(t *testing.T) {
	previousTimestamp := defaultOutputRunTimestamp
	previousRootDir := defaultOutputRootDir
	defaultOutputRunTimestamp = "20260406_120000"
	SetDefaultOutputRootDir("reports")
	defer func() {
		defaultOutputRunTimestamp = previousTimestamp
		SetDefaultOutputRootDir(previousRootDir)
	}()

	if got := ResolveOutputPathForTarget("https://example.com", "result.csv"); got != filepath.Join("reports", "example.com_20260406_120000", "result.csv") {
		t.Fatalf("unexpected resolved output path with custom root: %s", got)
	}
}

// TestResolveWorkbookPath 验证 CSV 文件输出路径会切换为 xlsx。
func TestResolveWorkbookPath(t *testing.T) {
	if got := ResolveWorkbookPath("result.csv"); got != "result.xlsx" {
		t.Fatalf("unexpected workbook path: %s", got)
	}
	if got := ResolveWorkbookPath("result"); got != "result.xlsx" {
		t.Fatalf("unexpected workbook path without ext: %s", got)
	}
	if got := ResolveWorkbookPath("result.xlsx"); got != "result.xlsx" {
		t.Fatalf("unexpected workbook path keep xlsx: %s", got)
	}
}

// TestResolveTaskAggregatePath 验证多目标任务会生成独立汇总文件路径。
func TestResolveTaskAggregatePath(t *testing.T) {
	previousTimestamp := defaultOutputRunTimestamp
	defaultOutputRunTimestamp = "20260406_120000"
	defer func() { defaultOutputRunTimestamp = previousTimestamp }()

	if got := ResolveTaskAggregatePath("result.csv"); got != filepath.Join("output", "task_20260406_120000", "result_aggregate.csv") {
		t.Fatalf("unexpected aggregate path: %s", got)
	}
}

// TestResolveTaskAggregatePathUsesConfiguredRootDir 验证任务汇总输出根目录可配置。
func TestResolveTaskAggregatePathUsesConfiguredRootDir(t *testing.T) {
	previousTimestamp := defaultOutputRunTimestamp
	previousRootDir := defaultOutputRootDir
	defaultOutputRunTimestamp = "20260406_120000"
	SetDefaultOutputRootDir("reports")
	defer func() {
		defaultOutputRunTimestamp = previousTimestamp
		SetDefaultOutputRootDir(previousRootDir)
	}()

	if got := ResolveTaskAggregatePath("result.csv"); got != filepath.Join("reports", "task_20260406_120000", "result_aggregate.csv") {
		t.Fatalf("unexpected aggregate path with custom root: %s", got)
	}
}

// TestResolveTaskAggregateCSVPath 验证任务级汇总 CSV 始终使用 csv 后缀。
func TestResolveTaskAggregateCSVPath(t *testing.T) {
	previousTimestamp := defaultOutputRunTimestamp
	defaultOutputRunTimestamp = "20260406_120000"
	defer func() { defaultOutputRunTimestamp = previousTimestamp }()

	if got := ResolveTaskAggregateCSVPath("result.xlsx"); got != filepath.Join("output", "task_20260406_120000", "result_aggregate.csv") {
		t.Fatalf("unexpected aggregate csv path: %s", got)
	}
	if got := ResolveTaskAggregateCSVPath("-"); got != filepath.Join("output", "task_20260406_120000", "aggregate.csv") {
		t.Fatalf("unexpected aggregate csv path for auto-save: %s", got)
	}
}

// TestShouldWriteTaskAggregateOutput 验证任务级汇总输出触发条件。
func TestShouldWriteTaskAggregateOutput(t *testing.T) {
	previousMode := global.OutputMode
	global.OutputMode = "csv"
	defer func() { global.OutputMode = previousMode }()

	if !ShouldWriteTaskAggregateOutput("result.csv", false, false) {
		t.Fatal("explicit csv output should write aggregate output")
	}
	if !ShouldWriteTaskAggregateOutput("-", false, true) {
		t.Fatal("auto-save csv output should write aggregate output")
	}
	if ShouldWriteTaskAggregateOutput("-", false, false) {
		t.Fatal("stdout csv output without auto-save should not write aggregate output")
	}
	if ShouldWriteTaskAggregateOutput("result.csv", true, false) {
		t.Fatal("json output should not write aggregate output")
	}
}

// TestWriteStructuredOutputFilesAppend 验证多次写结构化输出会累加结果，而不是覆盖。
func TestWriteStructuredOutputFilesAppend(t *testing.T) {
	tmpDir := t.TempDir()
	endpointPath := filepath.Join(tmpDir, "endpoint.json")
	parameterPath := filepath.Join(tmpDir, "parameter.json")

	first := &datatype.ScanResult{
		Target: "https://example.com",
		Endpoints: []datatype.EndpointRecord{
			{
				EndpointID: "ep-1",
				URL:        "https://example.com/api/user",
				Method:     "GET",
			},
		},
		Parameters: []datatype.ParameterRecord{
			{
				ParameterID: "param-1",
				EndpointID:  "ep-1",
				ParamName:   "id",
				Location:    "query",
			},
		},
	}
	second := &datatype.ScanResult{
		Target: "https://example.com",
		Endpoints: []datatype.EndpointRecord{
			{
				EndpointID: "ep-2",
				URL:        "https://example.com/api/order",
				Method:     "POST",
			},
		},
		Parameters: []datatype.ParameterRecord{
			{
				ParameterID: "param-2",
				EndpointID:  "ep-2",
				ParamName:   "keyword",
				Location:    "body",
			},
		},
	}

	WriteStructuredOutputFiles(first, endpointPath, parameterPath)
	WriteStructuredOutputFiles(second, endpointPath, parameterPath)

	endpointRaw, err := os.ReadFile(endpointPath)
	if err != nil {
		t.Fatalf("read endpoint file failed: %v", err)
	}
	parameterRaw, err := os.ReadFile(parameterPath)
	if err != nil {
		t.Fatalf("read parameter file failed: %v", err)
	}

	endpoints := []datatype.EndpointRecord{}
	parameters := []datatype.ParameterRecord{}
	if err := json.Unmarshal(endpointRaw, &endpoints); err != nil {
		t.Fatalf("unmarshal endpoint file failed: %v", err)
	}
	if err := json.Unmarshal(parameterRaw, &parameters); err != nil {
		t.Fatalf("unmarshal parameter file failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("unexpected endpoint count: %d", len(endpoints))
	}
	if len(parameters) != 2 {
		t.Fatalf("unexpected parameter count: %d", len(parameters))
	}

	endpointCSVRows := mustReadCSVRows(t, endpointCSVPath(endpointPath))
	parameterCSVRows := mustReadCSVRows(t, parameterCSVPath(parameterPath))
	if len(endpointCSVRows) != 3 {
		t.Fatalf("unexpected endpoint csv row count: %d", len(endpointCSVRows))
	}
	if len(parameterCSVRows) != 3 {
		t.Fatalf("unexpected parameter csv row count: %d", len(parameterCSVRows))
	}
}

// TestWriteWorkbookOutput 验证 CSV 文件输出可合并为 xlsx 工作簿。
func TestWriteWorkbookOutput(t *testing.T) {
	previousMode := global.OutputMode
	global.OutputMode = "csv"
	defer func() { global.OutputMode = previousMode }()

	tmpDir := t.TempDir()
	workbookPath := filepath.Join(tmpDir, "result.xlsx")
	result := &datatype.ScanResult{
		Target: "https://example.com",
		Records: []datatype.ScanRecord{
			{Id: "path", Content: "/api/user/list", Source: "https://example.com"},
		},
		Endpoints: []datatype.EndpointRecord{
			{
				EndpointID:     "ep-1",
				URL:            "https://example.com/api/login",
				Method:         "POST",
				ResponseStatus: 200,
				ResponseSize:   256,
				RequestTemplate: datatype.EndpointRequestTemplate{
					RequestPacket: "POST /api/login HTTP/1.1\nHost: example.com\n\n{\n  \"username\": \"<value>\"\n}",
				},
			},
		},
		Parameters: []datatype.ParameterRecord{
			{
				ParameterID: "param-1",
				EndpointID:  "ep-1",
				ParamName:   "username",
				Location:    "body",
				ParamType:   "string",
			},
		},
	}

	FormatOutputWrite(result, workbookPath, false)

	reader, err := zip.OpenReader(workbookPath)
	if err != nil {
		t.Fatalf("open workbook failed: %v", err)
	}
	defer reader.Close()

	entries := make(map[string]string)
	for _, file := range reader.File {
		rc, openErr := file.Open()
		if openErr != nil {
			t.Fatalf("open workbook entry failed: %v", openErr)
		}
		raw, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			t.Fatalf("read workbook entry failed: %v", readErr)
		}
		entries[file.Name] = string(raw)
	}

	if !strings.Contains(entries["xl/workbook.xml"], `sheet name="记录"`) {
		t.Fatalf("workbook should contain records sheet: %s", entries["xl/workbook.xml"])
	}
	if !strings.Contains(entries["xl/workbook.xml"], `sheet name="接口"`) {
		t.Fatalf("workbook should contain endpoints sheet: %s", entries["xl/workbook.xml"])
	}
	if !strings.Contains(entries["xl/workbook.xml"], `sheet name="参数"`) {
		t.Fatalf("workbook should contain parameters sheet: %s", entries["xl/workbook.xml"])
	}
	if !strings.Contains(entries["xl/worksheets/sheet2.xml"], "POST /api/login HTTP/1.1") {
		t.Fatalf("endpoints sheet should include request packet: %s", entries["xl/worksheets/sheet2.xml"])
	}
	if !strings.Contains(entries["xl/worksheets/sheet2.xml"], ">200<") {
		t.Fatalf("endpoints sheet should include response status: %s", entries["xl/worksheets/sheet2.xml"])
	}
	if !strings.Contains(entries["xl/worksheets/sheet2.xml"], ">256<") {
		t.Fatalf("endpoints sheet should include response size: %s", entries["xl/worksheets/sheet2.xml"])
	}
}

// TestWriteAggregateWorkbookOutput 验证多目标结果会合并为一个工作簿。
func TestWriteAggregateWorkbookOutput(t *testing.T) {
	tmpDir := t.TempDir()
	workbookPath := filepath.Join(tmpDir, "aggregate.xlsx")

	results := []*datatype.ScanResult{
		{
			Target: "https://a.example.com",
			Records: []datatype.ScanRecord{
				{Id: "path", Content: "/api/a", Source: "https://a.example.com"},
			},
			Endpoints: []datatype.EndpointRecord{
				{
					EndpointID: "ep-a",
					URL:        "https://a.example.com/api/a",
					Method:     "GET",
				},
			},
			Parameters: []datatype.ParameterRecord{
				{
					ParameterID: "param-a",
					EndpointID:  "ep-a",
					ParamName:   "id",
					Location:    "query",
				},
			},
		},
		{
			Target: "https://b.example.com",
			Records: []datatype.ScanRecord{
				{Id: "path", Content: "/api/b", Source: "https://b.example.com"},
			},
			Endpoints: []datatype.EndpointRecord{
				{
					EndpointID: "ep-b",
					URL:        "https://b.example.com/api/b",
					Method:     "POST",
					RequestTemplate: datatype.EndpointRequestTemplate{
						RequestPacket: "POST /api/b HTTP/1.1\nHost: b.example.com",
					},
				},
			},
			Parameters: []datatype.ParameterRecord{
				{
					ParameterID: "param-b",
					EndpointID:  "ep-b",
					ParamName:   "name",
					Location:    "body",
				},
			},
		},
	}

	if err := WriteAggregateWorkbookOutput(results, workbookPath); err != nil {
		t.Fatalf("write aggregate workbook failed: %v", err)
	}

	reader, err := zip.OpenReader(workbookPath)
	if err != nil {
		t.Fatalf("open aggregate workbook failed: %v", err)
	}
	defer reader.Close()

	entries := make(map[string]string)
	for _, file := range reader.File {
		rc, openErr := file.Open()
		if openErr != nil {
			t.Fatalf("open workbook entry failed: %v", openErr)
		}
		raw, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			t.Fatalf("read workbook entry failed: %v", readErr)
		}
		entries[file.Name] = string(raw)
	}

	if !strings.Contains(entries["xl/worksheets/sheet2.xml"], "目标") {
		t.Fatalf("aggregate endpoint sheet should include target column: %s", entries["xl/worksheets/sheet2.xml"])
	}
	if !strings.Contains(entries["xl/worksheets/sheet2.xml"], "https://a.example.com") || !strings.Contains(entries["xl/worksheets/sheet2.xml"], "https://b.example.com") {
		t.Fatalf("aggregate endpoint sheet should include both targets: %s", entries["xl/worksheets/sheet2.xml"])
	}
	if !strings.Contains(entries["xl/worksheets/sheet3.xml"], "param-b") {
		t.Fatalf("aggregate parameter sheet should include merged parameters: %s", entries["xl/worksheets/sheet3.xml"])
	}
}

// TestWriteAggregateCSVOutput 验证多目标主记录会合并为一个 CSV。
func TestWriteAggregateCSVOutput(t *testing.T) {
	tmpDir := t.TempDir()
	aggregatePath := filepath.Join(tmpDir, "aggregate.csv")

	results := []*datatype.ScanResult{
		{
			Target: "https://a.example.com",
			Records: []datatype.ScanRecord{
				{Id: "path", Content: "/api/a", Source: "https://a.example.com"},
			},
		},
		{
			Target: "https://b.example.com",
			Records: []datatype.ScanRecord{
				{Id: "path_url", Content: "https://b.example.com/api/b", Source: "https://b.example.com/index"},
			},
		},
	}

	if err := WriteAggregateCSVOutput(results, aggregatePath); err != nil {
		t.Fatalf("write aggregate csv failed: %v", err)
	}

	rows := mustReadCSVRows(t, aggregatePath)
	if len(rows) != 3 {
		t.Fatalf("unexpected aggregate csv row count: %d", len(rows))
	}
	if got := rows[0][0]; got != "目标" {
		t.Fatalf("unexpected aggregate csv header: %s", got)
	}
	if got := rows[1][0]; got != "https://a.example.com" {
		t.Fatalf("unexpected first target: %s", got)
	}
	if got := rows[2][0]; got != "https://b.example.com" {
		t.Fatalf("unexpected second target: %s", got)
	}
	if got := rows[2][2]; got != "https://b.example.com/api/b" {
		t.Fatalf("unexpected path_url merged value: %s", got)
	}
}

// TestWriteStructuredEndpointCSVIncludesRequest 验证 endpoint CSV 会包含 request 格式内容。
func TestWriteStructuredEndpointCSVIncludesRequest(t *testing.T) {
	tmpDir := t.TempDir()
	endpointPath := filepath.Join(tmpDir, "endpoint.json")

	result := &datatype.ScanResult{
		Target: "https://example.com",
		Endpoints: []datatype.EndpointRecord{
			{
				EndpointID: "ep-1",
				URL:        "https://example.com/api/login",
				Method:     "POST",
				RequestTemplate: datatype.EndpointRequestTemplate{
					RequestPacket: "POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\n  \"username\": \"<value>\"\n}",
				},
			},
		},
	}

	WriteStructuredOutputFiles(result, endpointPath, filepath.Join(tmpDir, "parameter.json"))

	rows := mustReadCSVRows(t, endpointCSVPath(endpointPath))
	if len(rows) != 2 {
		t.Fatalf("unexpected endpoint csv row count: %d", len(rows))
	}
	if got := rows[0][16]; got != "请求报文" {
		t.Fatalf("unexpected endpoint csv request header: %s", got)
	}
	if got := rows[1][16]; !strings.Contains(got, "POST /api/login HTTP/1.1") || !strings.Contains(got, "\"username\": \"<value>\"") {
		t.Fatalf("unexpected endpoint csv request value: %s", got)
	}
}

// TestRenderTextIncludesTag 验证文本输出会展示 record tag。
func TestRenderTextIncludesTag(t *testing.T) {
	result := &datatype.ScanResult{
		Target: "https://example.com",
		Records: []datatype.ScanRecord{
			{
				Id:      "path_url",
				Content: "https://example.com/api/user/list",
				Source:  "https://example.com/index.html",
				Tag:     "path_probe status=200 title=Demo",
			},
		},
	}

	rendered := renderText(result)
	if !strings.Contains(rendered, "path_probe status=200 title=Demo") {
		t.Fatalf("rendered text should include tag: %s", rendered)
	}
}

// TestRenderTextLinksEndpointAndParameters 验证文本输出会按 endpoint 关联参数摘要。
func TestRenderTextLinksEndpointAndParameters(t *testing.T) {
	result := &datatype.ScanResult{
		Target: "https://example.com",
		Endpoints: []datatype.EndpointRecord{
			{
				EndpointID: "ep-1",
				URL:        "https://example.com/api/search",
				Method:     "POST",
			},
		},
		Parameters: []datatype.ParameterRecord{
			{
				EndpointID: "ep-1",
				ParamName:  "keyword",
				Location:   "body",
				ParamType:  "string",
				Required:   true,
			},
			{
				EndpointID: "ep-1",
				ParamName:  "pageNo",
				Location:   "query",
				ParamType:  "number",
				Default:    "1",
			},
		},
	}

	rendered := renderText(result)
	if !strings.Contains(rendered, "POST https://example.com/api/search") {
		t.Fatalf("rendered text should include endpoint: %s", rendered)
	}
	if !strings.Contains(rendered, "query: pageNo(number)=1") {
		t.Fatalf("rendered text should include query parameter summary: %s", rendered)
	}
	if !strings.Contains(rendered, "body: keyword(string)!") {
		t.Fatalf("rendered text should include body parameter summary: %s", rendered)
	}
}

// TestRenderTextUsesRequestPacket 验证文本输出会优先展示 endpoint request packet。
func TestRenderTextUsesRequestPacket(t *testing.T) {
	result := &datatype.ScanResult{
		Target: "https://example.com",
		Endpoints: []datatype.EndpointRecord{
			{
				EndpointID: "ep-1",
				URL:        "https://example.com/api/login",
				Method:     "POST",
				RequestTemplate: datatype.EndpointRequestTemplate{
					RequestPacket: "POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\n  \"username\": \"<value>\"\n}",
				},
			},
		},
		Parameters: []datatype.ParameterRecord{
			{
				EndpointID: "ep-1",
				ParamName:  "username",
				Location:   "body",
				ParamType:  "string",
			},
		},
	}

	rendered := renderText(result)
	if !strings.Contains(rendered, "POST /api/login HTTP/1.1") {
		t.Fatalf("rendered text should include request packet first line: %s", rendered)
	}
	if !strings.Contains(rendered, "Host: example.com") {
		t.Fatalf("rendered text should include request packet host: %s", rendered)
	}
	if !strings.Contains(rendered, "\"username\": \"<value>\"") {
		t.Fatalf("rendered text should include request packet body: %s", rendered)
	}
	if strings.Contains(rendered, "body: username(string)") {
		t.Fatalf("rendered text should not fallback to summary when packet exists: %s", rendered)
	}
}

// TestExtractRecordStatusAndTitle 验证 record tag 中的 status/title 可被拆分。
func TestExtractRecordStatusAndTitle(t *testing.T) {
	statusText, titleText := extractRecordStatusAndTitle("path_probe status=302 title=Login Page")
	if statusText != "302" {
		t.Fatalf("unexpected status text: %s", statusText)
	}
	if titleText != "Login Page" {
		t.Fatalf("unexpected title text: %s", titleText)
	}
}

// TestExtractRecordStatusTitleAndSize 验证 record tag 中的 status/title/size 可被拆分。
func TestExtractRecordStatusTitleAndSize(t *testing.T) {
	statusText, titleText, sizeText := extractRecordStatusTitleAndSize("path_probe status=200 title=Demo User List size=2048")
	if statusText != "200" {
		t.Fatalf("unexpected status text: %s", statusText)
	}
	if titleText != "Demo User List" {
		t.Fatalf("unexpected title text: %s", titleText)
	}
	if sizeText != "2048" {
		t.Fatalf("unexpected size text: %s", sizeText)
	}
}

// TestRenderCSVIncludesURLStatusTitleAndSize 验证 CSV 输出会为 path_url 拆出 url/status/title/size 列。
func TestRenderCSVIncludesURLStatusTitleAndSize(t *testing.T) {
	result := &datatype.ScanResult{
		Target: "https://example.com",
		Records: []datatype.ScanRecord{
			{
				Id:      "path_url",
				Content: "https://example.com/api/user/list",
				Source:  "https://example.com/index.html",
				Tag:     "path_probe status=200 title=Demo User List size=2048",
				Hash:    123,
			},
		},
	}

	rendered := renderCSV(result)
	reader := csv.NewReader(strings.NewReader(rendered))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv failed: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("unexpected csv row count: %d", len(rows))
	}
	if got := rows[0][2]; got != "URL" {
		t.Fatalf("unexpected csv header url column: %s", got)
	}
	if got := rows[0][4]; got != "状态码" {
		t.Fatalf("unexpected csv header status column: %s", got)
	}
	if got := rows[0][5]; got != "标题" {
		t.Fatalf("unexpected csv header title column: %s", got)
	}
	if got := rows[0][6]; got != "大小" {
		t.Fatalf("unexpected csv header size column: %s", got)
	}
	if got := rows[1][2]; got != "https://example.com/api/user/list" {
		t.Fatalf("unexpected csv url value: %s", got)
	}
	if got := rows[1][4]; got != "200" {
		t.Fatalf("unexpected csv status value: %s", got)
	}
	if got := rows[1][5]; got != "Demo User List" {
		t.Fatalf("unexpected csv title value: %s", got)
	}
	if got := rows[1][6]; got != "2048" {
		t.Fatalf("unexpected csv size value: %s", got)
	}
}

func TestRenderCSVPlacesPageURLRecordIntoURLColumn(t *testing.T) {
	result := &datatype.ScanResult{
		Target: "https://example.com",
		Records: []datatype.ScanRecord{
			{
				Id:      "page_url",
				Content: "https://example.com/portal?tenant=demo",
				Source:  "https://example.com",
				Tag:     "js_page_candidate",
				Hash:    321,
			},
		},
	}

	rendered := renderCSV(result)
	reader := csv.NewReader(strings.NewReader(rendered))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv failed: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("unexpected csv row count: %d", len(rows))
	}
	if got := rows[1][2]; got != "https://example.com/portal?tenant=demo" {
		t.Fatalf("unexpected page_url csv url value: %s", got)
	}
	if got := rows[1][3]; got != "" {
		t.Fatalf("unexpected page_url csv content value: %s", got)
	}
}

// TestBuildEndpointCSVTableUsesChineseHeaders 验证接口表使用中文表头并包含状态码/响应大小。
func TestBuildEndpointCSVTableUsesChineseHeaders(t *testing.T) {
	rows := buildEndpointCSVTable([]datatype.EndpointRecord{
		{
			EndpointID:      "ep-1",
			URL:             "https://example.com/api/login",
			Method:          "POST",
			ResponseStatus:  201,
			ResponseSize:    512,
			RequestTemplate: datatype.EndpointRequestTemplate{RequestPacket: "POST /api/login HTTP/1.1"},
		},
	})
	if len(rows) != 2 {
		t.Fatalf("unexpected endpoint table row count: %d", len(rows))
	}
	if rows[0][13] != "状态码" {
		t.Fatalf("unexpected endpoint status header: %s", rows[0][13])
	}
	if rows[0][14] != "响应大小" {
		t.Fatalf("unexpected endpoint size header: %s", rows[0][14])
	}
	if rows[0][16] != "请求报文" {
		t.Fatalf("unexpected endpoint request header: %s", rows[0][16])
	}
	if rows[1][13] != "201" {
		t.Fatalf("unexpected endpoint status value: %s", rows[1][13])
	}
	if rows[1][14] != "512" {
		t.Fatalf("unexpected endpoint size value: %s", rows[1][14])
	}
}

func mustReadCSVRows(t *testing.T, path string) [][]string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv file failed path=%s err=%v", path, err)
	}
	reader := csv.NewReader(strings.NewReader(string(raw)))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("parse csv failed path=%s err=%v", path, err)
	}
	return rows
}
