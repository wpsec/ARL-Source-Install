package util

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	datatype "wih/dataType"
)

// TestResolveStructuredOutputPaths 验证结构化输出路径推导。
func TestResolveStructuredOutputPaths(t *testing.T) {
	endpointPath, parameterPath := ResolveStructuredOutputPaths("result.json", "", "")
	if endpointPath != "result_endpoint.json" {
		t.Fatalf("unexpected endpoint path: %s", endpointPath)
	}
	if parameterPath != "result_parameter.json" {
		t.Fatalf("unexpected parameter path: %s", parameterPath)
	}

	customEndpoint, customParameter := ResolveStructuredOutputPaths("result.json", "a.json", "b.json")
	if customEndpoint != "a.json" || customParameter != "b.json" {
		t.Fatalf("unexpected custom paths endpoint=%s parameter=%s", customEndpoint, customParameter)
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
}
