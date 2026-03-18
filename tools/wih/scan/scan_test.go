package scan

import (
	"testing"
	datatype "wih/dataType"
)

// TestNormalizeTargetURL 验证目标 URL 规范化行为。
func TestNormalizeTargetURL(t *testing.T) {
	if normalizeTargetURL("") != "" {
		t.Fatal("空输入应返回空字符串")
	}
	if normalizeTargetURL("https://example.com") != "https://example.com" {
		t.Fatal("https URL 不应被修改")
	}
	if normalizeTargetURL("example.com") != "http://example.com" {
		t.Fatal("无协议目标应自动补 http://")
	}
}

// TestExtractJSURLs 验证 JS URL 提取逻辑。
func TestExtractJSURLs(t *testing.T) {
	html := `<script src="/static/app.js"></script><script src="https://cdn.example.com/a.js"></script>`
	urls := extractJSURLs(html, "https://www.example.com/index")
	if len(urls) != 2 {
		t.Fatalf("提取 JS URL 数量异常: got=%d", len(urls))
	}
}

// TestBuildPathProbeCandidates 验证 path 探测候选构造是否同时覆盖根路径与当前目录。
func TestBuildPathProbeCandidates(t *testing.T) {
	records := []datatype.ScanRecord{
		{
			Id:      "path",
			Content: "/test123",
			Source:  "http://www.test.com/123/test.js",
		},
	}
	candidates := buildPathProbeCandidates("http://www.test.com/123/", records)
	if len(candidates) != 2 {
		t.Fatalf("path 探测候选数量异常: got=%d", len(candidates))
	}

	expected := map[string]bool{
		"http://www.test.com/test123":     false,
		"http://www.test.com/123/test123": false,
	}
	for _, item := range candidates {
		if _, ok := expected[item.URL]; ok {
			expected[item.URL] = true
		}
	}
	for urlValue, hit := range expected {
		if !hit {
			t.Fatalf("未命中期望候选 URL: %s", urlValue)
		}
	}
}
