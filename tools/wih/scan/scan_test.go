package scan

import "testing"

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
