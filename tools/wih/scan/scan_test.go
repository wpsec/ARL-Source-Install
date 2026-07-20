package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	datatype "wih/dataType"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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

func TestBuildBodyPreviewByKindSupportsAdditionalPostTypes(t *testing.T) {
	xmlPreview := buildBodyPreviewByKind("xml", map[string]string{"token": "<value>"}, "")
	if !strings.Contains(xmlPreview, "<token><value></token>") {
		t.Fatalf("unexpected xml body preview: %s", xmlPreview)
	}

	textPreview := buildBodyPreviewByKind("text", map[string]string{"message": "hello", "trace": "123"}, "")
	if textPreview != "message=hello\ntrace=123" {
		t.Fatalf("unexpected text body preview: %s", textPreview)
	}

	binaryPreview := buildBodyPreviewByKind("octet_stream", map[string]string{"file": "<value>"}, "")
	if binaryPreview != "file=<binary>" {
		t.Fatalf("unexpected octet-stream body preview: %s", binaryPreview)
	}

	emptyBinaryPreview := buildBodyPreviewByKind("application/octet-stream", nil, "")
	if emptyBinaryPreview != "<binary>" {
		t.Fatalf("unexpected empty binary body preview: %s", emptyBinaryPreview)
	}
}

func TestInferJSBodyProfileSupportsAdditionalPostTypes(t *testing.T) {
	cases := []struct {
		name        string
		window      string
		contentType string
		bodyKind    string
	}{
		{
			name:        "text plain",
			window:      `fetch("/api/log", { method: "POST", headers: { "Content-Type": "text/plain" }, body: "a=b" })`,
			contentType: "text/plain",
			bodyKind:    "text",
		},
		{
			name:        "xml",
			window:      `fetch("/api/xml", { method: "POST", headers: { "Content-Type": "application/xml" }, body: "<root></root>" })`,
			contentType: "application/xml",
			bodyKind:    "xml",
		},
		{
			name:        "octet stream",
			window:      `fetch("/api/upload", { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: new Uint8Array([1, 2]) })`,
			contentType: "application/octet-stream",
			bodyKind:    "octet_stream",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			contentType, bodyKind := inferJSBodyProfile(item.window, nil, nil)
			if contentType != item.contentType || bodyKind != item.bodyKind {
				t.Fatalf("unexpected body profile: contentType=%s bodyKind=%s", contentType, bodyKind)
			}
		})
	}
}

func TestInferRuntimeBodyKindSupportsAdditionalPostTypes(t *testing.T) {
	cases := map[string]string{
		"text/plain":               "text",
		"text/xml":                 "xml",
		"application/xml":          "xml",
		"application/octet-stream": "octet_stream",
	}

	for contentType, expected := range cases {
		if got := inferRuntimeBodyKind(contentType, nil, "a=b"); got != expected {
			t.Fatalf("unexpected runtime body kind contentType=%s got=%s expected=%s", contentType, got, expected)
		}
	}
}

// TestFilterRecordsByTargetScope 验证 domain/domain_url/email 仅保留同站点域范围。
func TestFilterRecordsByTargetScope(t *testing.T) {
	records := []datatype.ScanRecord{
		{Id: "domain", Content: "cube.example.com"},
		{Id: "domain", Content: "api.example.com"},
		{Id: "domain", Content: "vuejs.org"},
		{Id: "domain_url", Content: "https://api.example.com/open/api/list"},
		{Id: "domain_url", Content: "https://v3-migration.vuejs.org/breaking-changes/v-model.html"},
		{Id: "email", Content: "admin@example.com"},
		{Id: "email", Content: "jhruby.web@gmail.com"},
		{Id: "path", Content: "/api/user/list"},
	}

	filtered := filterRecordsByTargetScope("https://cube.example.com", records)
	if len(filtered) != 5 {
		t.Fatalf("unexpected filtered record count: %d", len(filtered))
	}

	contents := make(map[string]struct{}, len(filtered))
	for _, record := range filtered {
		contents[record.Content] = struct{}{}
	}

	for _, expected := range []string{
		"cube.example.com",
		"api.example.com",
		"https://api.example.com/open/api/list",
		"admin@example.com",
		"/api/user/list",
	} {
		if _, ok := contents[expected]; !ok {
			t.Fatalf("missing expected scoped record: %s", expected)
		}
	}

	for _, dropped := range []string{
		"vuejs.org",
		"https://v3-migration.vuejs.org/breaking-changes/v-model.html",
		"jhruby.web@gmail.com",
	} {
		if _, ok := contents[dropped]; ok {
			t.Fatalf("unexpected out-of-scope record retained: %s", dropped)
		}
	}
}

// TestIsHostInTargetScope 验证同注册域及其子域名会被视为站点范围内。
func TestIsHostInTargetScope(t *testing.T) {
	scope := buildTargetScope("https://cube.example.com")
	cases := map[string]bool{
		"cube.example.com":       true,
		"api.example.com":        true,
		"example.com":            true,
		"cube.other.com":         false,
		"v3-migration.vuejs.org": false,
	}

	for host, expected := range cases {
		got := isHostInTargetScope(host, scope)
		if got != expected {
			t.Fatalf("host scope mismatch host=%s got=%v expected=%v", host, got, expected)
		}
	}
}

// TestExtractLinkedPageURLs 验证静态页面探索仅保留同 host、可继续抓取的页面链接。
func TestExtractLinkedPageURLs(t *testing.T) {
	targetParsed, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse target failed: %v", err)
	}

	body := `
<html>
  <body>
    <a href="/login">login</a>
    <a href="https://example.com/admin?tab=user">admin</a>
    <a href="https://other.com/out">out</a>
    <a href="#top">top</a>
    <a href="mailto:test@example.com">mail</a>
    <iframe src="/frame/dashboard"></iframe>
    <a href="/assets/app.js">js</a>
  </body>
</html>
`

	links := extractLinkedPageURLs(body, targetParsed, "https://example.com")
	if len(links) != 3 {
		t.Fatalf("unexpected linked page count: %d", len(links))
	}

	expected := map[string]struct{}{
		"https://example.com/admin?tab=user":  {},
		"https://example.com/frame/dashboard": {},
		"https://example.com/login":           {},
	}
	for _, link := range links {
		if _, ok := expected[link]; !ok {
			t.Fatalf("unexpected linked page: %s", link)
		}
	}
}

// TestScanLinkedHTMLPagesCollectsFormSurface 验证静态页面探索会继续提取下一层页面的接口、参数和 JS。
func TestScanLinkedHTMLPagesCollectsFormSurface(t *testing.T) {
	rootBody := `<html><body><a href="/login">login</a></body></html>`
	loginBody := `
<html>
  <body>
    <form action="/api/login?scene=web" method="post">
      <input type="text" name="username" required>
      <input type="password" name="password">
    </form>
    <script src="/static/login.js"></script>
  </body>
</html>
`

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://example.com/login":
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: int64(len(loginBody)),
					Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
					Body:          io.NopCloser(strings.NewReader(loginBody)),
					Request:       req,
				}, nil
			default:
				return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
			}
		}),
	}

	result := scanLinkedHTMLPages(client, "https://example.com", rootBody)
	if len(result.Endpoints) != 1 {
		t.Fatalf("unexpected endpoint count: %d", len(result.Endpoints))
	}
	if result.Endpoints[0].URL != "https://example.com/api/login?scene=web" {
		t.Fatalf("unexpected endpoint url: %s", result.Endpoints[0].URL)
	}
	if len(result.Parameters) < 3 {
		t.Fatalf("unexpected parameter count: %d", len(result.Parameters))
	}

	paramMap := make(map[string]datatype.ParameterRecord)
	for _, parameter := range result.Parameters {
		paramMap[parameter.ParamName] = parameter
	}
	if paramMap["scene"].Location != "query" {
		t.Fatalf("expected scene query parameter, got=%s", paramMap["scene"].Location)
	}
	if paramMap["username"].Location != "body" || !paramMap["username"].Required {
		t.Fatalf("unexpected username parameter: %+v", paramMap["username"])
	}
	if paramMap["password"].Location != "body" {
		t.Fatalf("unexpected password parameter: %+v", paramMap["password"])
	}
	if len(result.JSURLs) != 1 || result.JSURLs[0] != "https://example.com/static/login.js" {
		t.Fatalf("unexpected js urls: %+v", result.JSURLs)
	}
}

// TestScanLinkedHTMLPagesCollectsFrameworkPageCandidates 验证静态 HTML 探索会从内联框架状态中恢复页面候选。
func TestScanLinkedHTMLPagesCollectsFrameworkPageCandidates(t *testing.T) {
	rootBody := `<html><body><a href="/shell">shell</a></body></html>`
	shellBody := `
<html>
  <head>
    <script>window.__NEXT_DATA__ = {"page":"/login","props":{"pageProps":{"loginUrl":"/loginAdmin"}}}</script>
    <script>window.__NUXT__ = {"fullPath":"/portal/home"}</script>
  </head>
  <body></body>
</html>
`

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://example.com/shell":
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: int64(len(shellBody)),
					Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
					Body:          io.NopCloser(strings.NewReader(shellBody)),
					Request:       req,
				}, nil
			default:
				return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
			}
		}),
	}

	result := scanLinkedHTMLPages(client, "https://example.com", rootBody)
	expected := map[string]bool{
		"https://example.com/login":       false,
		"https://example.com/loginAdmin":  false,
		"https://example.com/portal/home": false,
	}
	for _, item := range result.PageURLs {
		if _, ok := expected[item]; ok {
			expected[item] = true
		}
	}
	for pageURL, hit := range expected {
		if !hit {
			t.Fatalf("missing expected framework page candidate: %s pageURLs=%+v", pageURL, result.PageURLs)
		}
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
			Source:  "http://www.test.com/123/index.html",
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

// TestNormalizePathTokenFiltersNoise 验证 path 探测前的清洗逻辑。
func TestNormalizePathTokenFiltersNoise(t *testing.T) {
	cases := map[string]string{
		"/approve/rule/candidate_approvers|get": "/approve/rule/candidate_approvers",
		"/announcement/{id}/detail|get":         "",
		"/static/js/app.js":                     "",
		"/head":                                 "",
		"/api/user/list":                        "/api/user/list",
	}

	for raw, expected := range cases {
		got := normalizePathToken(raw)
		if got != expected {
			t.Fatalf("path token normalize mismatch raw=%s got=%s expected=%s", raw, got, expected)
		}
	}
}

// TestExtractHTMLFormSurface 验证 HTML 表单提取出的 endpoint/parameter 结构化结果。
func TestExtractHTMLFormSurface(t *testing.T) {
	html := `
<html>
  <body>
    <form action="/login" method="post">
      <input type="text" name="username" required>
      <input type="password" name="password">
      <input type="hidden" name="csrf_token" value="abc123">
    </form>
    <form action="/search?scene=web" method="get">
      <input type="text" name="keyword" value="arl">
      <select name="role" required>
        <option value="student">student</option>
        <option value="teacher" selected>teacher</option>
      </select>
    </form>
  </body>
</html>
`
	endpoints, parameters := extractHTMLFormSurface(html, "https://example.com/admin")
	if len(endpoints) != 2 {
		t.Fatalf("endpoint count mismatch got=%d", len(endpoints))
	}
	if len(parameters) < 5 {
		t.Fatalf("parameter count mismatch got=%d", len(parameters))
	}

	endpointMap := make(map[string]datatype.EndpointRecord)
	for _, endpoint := range endpoints {
		endpointMap[endpoint.URL] = endpoint
	}

	loginEndpoint, ok := endpointMap["https://example.com/login"]
	if !ok {
		t.Fatal("missing login endpoint")
	}
	if loginEndpoint.Method != "POST" {
		t.Fatalf("unexpected login method %s", loginEndpoint.Method)
	}
	if loginEndpoint.BodyKind != "form_urlencoded" {
		t.Fatalf("unexpected login body kind %s", loginEndpoint.BodyKind)
	}
	if loginEndpoint.RequestTemplate.Headers["User-Agent"] == "" {
		t.Fatal("login endpoint request template should include default user-agent")
	}
	if loginEndpoint.RequestTemplate.Headers["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("unexpected login content-type %s", loginEndpoint.RequestTemplate.Headers["Content-Type"])
	}
	if loginEndpoint.RequestTemplate.RequestPacket == "" {
		t.Fatal("login endpoint request packet should not be empty")
	}
	if !strings.Contains(loginEndpoint.RequestTemplate.RequestPacket, "POST /login HTTP/1.1") {
		t.Fatalf("unexpected login request packet: %s", loginEndpoint.RequestTemplate.RequestPacket)
	}

	searchEndpoint, ok := endpointMap["https://example.com/search?scene=web"]
	if !ok {
		t.Fatal("missing search endpoint")
	}
	if searchEndpoint.Method != "GET" {
		t.Fatalf("unexpected search method %s", searchEndpoint.Method)
	}
	if searchEndpoint.RequestTemplate.Query["scene"] != "<value>" {
		t.Fatalf("unexpected query template for scene: %+v", searchEndpoint.RequestTemplate.Query)
	}
	if searchEndpoint.RequestTemplate.QueryString == "" {
		t.Fatal("search endpoint query string should not be empty")
	}
	if !strings.Contains(searchEndpoint.RequestTemplate.RequestPacket, "GET /search?scene=web HTTP/1.1") {
		t.Fatalf("unexpected search request packet: %s", searchEndpoint.RequestTemplate.RequestPacket)
	}

	type paramExpect struct {
		location  string
		paramType string
		required  bool
	}
	expected := map[string]paramExpect{
		"username":   {location: "body", paramType: "string", required: true},
		"password":   {location: "body", paramType: "string", required: false},
		"csrf_token": {location: "body", paramType: "string", required: false},
		"scene":      {location: "query", paramType: "string", required: false},
		"keyword":    {location: "query", paramType: "string", required: false},
		"role":       {location: "query", paramType: "string", required: true},
	}

	hitMap := make(map[string]datatype.ParameterRecord)
	for _, parameter := range parameters {
		hitMap[parameter.ParamName] = parameter
	}

	for paramName, expect := range expected {
		param, ok := hitMap[paramName]
		if !ok {
			t.Fatalf("missing parameter %s", paramName)
		}
		if param.Location != expect.location {
			t.Fatalf("parameter location mismatch name=%s got=%s expected=%s", paramName, param.Location, expect.location)
		}
		if param.ParamType != expect.paramType {
			t.Fatalf("parameter type mismatch name=%s got=%s expected=%s", paramName, param.ParamType, expect.paramType)
		}
		if param.Required != expect.required {
			t.Fatalf("parameter required mismatch name=%s got=%v expected=%v", paramName, param.Required, expect.required)
		}
	}
	if !hitMap["password"].IsPII {
		t.Fatal("password 应被识别为疑似敏感参数")
	}
	if hitMap["csrf_token"].Entropy <= 0 {
		t.Fatal("csrf_token 示例值应生成熵值")
	}
}

// TestExtractJSStaticSurface 验证 JS 中的接口与参数可被结构化提取。
func TestExtractJSStaticSurface(t *testing.T) {
	jsBody := `
fetch("/api/search?scene=web", {
  method: "POST",
  headers: {
    "X-Token": token,
    "Authorization": authHeader
  },
  body: JSON.stringify({
    keyword,
    pageNo,
  })
})

axios.get("/api/user/detail", {
  params: {
    id,
    profile
  }
})

request({
  url: "/graphql",
  method: "POST",
  data: {
    query: "query Demo($userId: String!) { user(id: $userId) { id } }",
    variables: {
      userId,
      tenantId
    }
  }
})
`

	endpoints, parameters := extractJSStaticSurface(jsBody, "https://example.com/static/app.js")
	if len(endpoints) != 3 {
		t.Fatalf("js endpoint count mismatch got=%d", len(endpoints))
	}
	if len(parameters) < 8 {
		t.Fatalf("js parameter count mismatch got=%d", len(parameters))
	}

	endpointMap := make(map[string]datatype.EndpointRecord)
	for _, endpoint := range endpoints {
		endpointMap[endpoint.URL] = endpoint
	}

	searchEndpoint, ok := endpointMap["https://example.com/api/search?scene=web"]
	if !ok {
		t.Fatal("missing search endpoint")
	}
	if searchEndpoint.Method != "POST" {
		t.Fatalf("unexpected search method %s", searchEndpoint.Method)
	}
	if searchEndpoint.BodyKind != "json" {
		t.Fatalf("unexpected search body kind %s", searchEndpoint.BodyKind)
	}

	gqlEndpoint, ok := endpointMap["https://example.com/graphql"]
	if !ok {
		t.Fatal("missing graphql endpoint")
	}
	if gqlEndpoint.BodyKind != "graphql" {
		t.Fatalf("unexpected graphql body kind %s", gqlEndpoint.BodyKind)
	}
	if gqlEndpoint.RequestTemplate.BodyText == "" {
		t.Fatal("graphql endpoint body text should not be empty")
	}
	if !strings.Contains(gqlEndpoint.RequestTemplate.BodyText, "user(id: $userId)") {
		t.Fatalf("graphql endpoint body text should preserve original query: %s", gqlEndpoint.RequestTemplate.BodyText)
	}
	if gqlEndpoint.RequestTemplate.RequestPacket == "" {
		t.Fatal("graphql endpoint request packet should not be empty")
	}
	if !strings.Contains(gqlEndpoint.RequestTemplate.RequestPacket, "POST /graphql HTTP/1.1") {
		t.Fatalf("unexpected graphql request packet: %s", gqlEndpoint.RequestTemplate.RequestPacket)
	}
	if gqlEndpoint.RequestTemplate.Headers["User-Agent"] == "" {
		t.Fatal("graphql endpoint request template should include default user-agent")
	}

	type expectedParam struct {
		location string
	}
	expected := map[string]expectedParam{
		"scene":         {location: "query"},
		"id":            {location: "query"},
		"profile":       {location: "query"},
		"keyword":       {location: "body"},
		"pageNo":        {location: "body"},
		"X-Token":       {location: "header"},
		"Authorization": {location: "header"},
		"userId":        {location: "graphql_variable"},
		"tenantId":      {location: "graphql_variable"},
	}

	paramMap := make(map[string]datatype.ParameterRecord)
	for _, parameter := range parameters {
		paramMap[parameter.ParamName] = parameter
	}

	for name, expect := range expected {
		param, ok := paramMap[name]
		if !ok {
			t.Fatalf("missing js parameter %s", name)
		}
		if param.Location != expect.location {
			t.Fatalf("parameter location mismatch name=%s got=%s expected=%s", name, param.Location, expect.location)
		}
	}
	if !paramMap["X-Token"].IsPII {
		t.Fatal("X-Token 应被识别为疑似敏感参数")
	}
}

// TestExtractJSImportChunkURLs 验证静态 JS 会继续发现并跟踪懒加载 chunk。
func TestExtractJSImportChunkURLs(t *testing.T) {
	jsBody := "const loginChunk = \"./index-09e8886e.js\"\n" +
		"const assetList = [\"assets/layout-f4f7534c.js\", \"assets/admin-460f2767.js\"]\n" +
		"import(loginChunk)\n" +
		"import(\"./tenant-99eb85ef.js\")\n"

	urls := extractJSImportChunkURLs(
		jsBody,
		"https://example.com/assets/index-7b220f9f.js",
		buildJSVariableHints(jsBody),
	)
	expected := map[string]bool{
		"https://example.com/assets/index-09e8886e.js":  false,
		"https://example.com/assets/layout-f4f7534c.js": false,
		"https://example.com/assets/admin-460f2767.js":  false,
		"https://example.com/assets/tenant-99eb85ef.js": false,
	}
	if len(urls) < len(expected) {
		t.Fatalf("unexpected js chunk url count: %d urls=%+v", len(urls), urls)
	}
	for _, item := range urls {
		if _, ok := expected[item]; ok {
			expected[item] = true
		}
	}
	for urlValue, hit := range expected {
		if !hit {
			t.Fatalf("missing expected js chunk url: %s urls=%+v", urlValue, urls)
		}
	}
}

// TestExtractJSPageCandidateURLsFromRoutes 验证前端路由与导航字符串会转成页面候选。
func TestExtractJSPageCandidateURLsFromRoutes(t *testing.T) {
	jsBody := `{
  path: "/loginLayout",
  children: [{
    path: "/login/:sysCode?",
    name: "Login"
  }, {
    path: "/loginAdmin",
    name: "LoginAdmin"
  }]
}
const passwordLogin = "/Login?dt=frmw0c9n"
location.href = passwordLogin
`

	urls := extractJSPageCandidateURLs(
		jsBody,
		"https://example.com/assets/router.js",
		buildJSVariableHints(jsBody),
	)
	expected := map[string]bool{
		"https://example.com/login":             false,
		"https://example.com/loginLayout":       false,
		"https://example.com/loginAdmin":        false,
		"https://example.com/Login?dt=frmw0c9n": false,
	}
	for _, item := range urls {
		if _, ok := expected[item]; ok {
			expected[item] = true
		}
	}
	for urlValue, hit := range expected {
		if !hit {
			t.Fatalf("missing expected page candidate: %s urls=%+v", urlValue, urls)
		}
	}
}

// TestExtractJSPageCandidateURLsFromRecoveredStrings 验证 atob / decodeURIComponent / 字符串拼接会恢复成页面候选。
func TestExtractJSPageCandidateURLsFromRecoveredStrings(t *testing.T) {
	jsBody := `
const loginPrefix = decodeURIComponent("%2Flog")
const loginSuffix = atob("aW4=")
const loginUrl = loginPrefix + loginSuffix
const adminUrl = atob("L2xvZ2luQWRtaW4=")
router.push(loginUrl)
location.href = adminUrl
`

	urls := extractJSPageCandidateURLs(
		jsBody,
		"https://example.com/assets/router.js",
		buildJSVariableHints(jsBody),
	)
	expected := map[string]bool{
		"https://example.com/login":      false,
		"https://example.com/loginAdmin": false,
	}
	for _, item := range urls {
		if _, ok := expected[item]; ok {
			expected[item] = true
		}
	}
	for urlValue, hit := range expected {
		if !hit {
			t.Fatalf("missing recovered page candidate: %s urls=%+v", urlValue, urls)
		}
	}
}

// TestExtractJSPageCandidateURLsFromStateValues 验证 bootstrap/localStorage/sessionStorage 值会参与页面候选恢复。
func TestExtractJSPageCandidateURLsFromStateValues(t *testing.T) {
	jsBody := `
window.__BOOTSTRAP__ = {
  tenant: "tenant-a",
  appId: "campus",
  sysCode: "eysys"
}
localStorage.setItem("dt", "frmw0c9n")
const hiddenLogin = "/Login?dt=" + localStorage.getItem("dt")
const tenantPortal = "/portal/:tenant/app/:appId"
const loginRoute = "/login/:sysCode"
location.href = hiddenLogin
router.push(tenantPortal)
router.replace(loginRoute)
`

	urls := extractJSPageCandidateURLs(
		jsBody,
		"https://example.com/assets/app.js",
		buildJSVariableHints(jsBody),
	)
	expected := map[string]bool{
		"https://example.com/Login?dt=frmw0c9n":          false,
		"https://example.com/portal/tenant-a/app/campus": false,
		"https://example.com/login/eysys":                false,
	}
	for _, item := range urls {
		if _, ok := expected[item]; ok {
			expected[item] = true
		}
	}
	for urlValue, hit := range expected {
		if !hit {
			t.Fatalf("missing state-derived page candidate: %s urls=%+v", urlValue, urls)
		}
	}
}

// TestBuildJSPageCandidatePathRecordsSupportsHashRoute 验证 hash 路由也会沉淀成 path 候选。
func TestBuildJSPageCandidatePathRecordsSupportsHashRoute(t *testing.T) {
	records := buildJSPageCandidatePathRecords("https://example.com", []string{
		"https://example.com/#/login",
		"https://example.com/#/login",
		"https://example.com/#/portal/home",
	})

	got := make(map[string]bool)
	for _, record := range records {
		got[record.Content] = true
	}

	if !got["/login"] {
		t.Fatalf("expected hash route /login path record, got=%+v", records)
	}
	if !got["/portal/home"] {
		t.Fatalf("expected hash route /portal/home path record, got=%+v", records)
	}
	if len(records) != 2 {
		t.Fatalf("expected deduped hash route records, got=%d records=%+v", len(records), records)
	}
}

func TestBuildPageCandidateURLRecordsKeepsHiddenPageURLs(t *testing.T) {
	records := buildPageCandidateURLRecords("https://example.com", []string{
		"https://example.com/Login?dt=frmw0c9n",
		"https://example.com/login",
		"https://example.com/assets/app.js",
		"https://other.com/admin",
	}, "js_page_candidate")

	expected := map[string]bool{
		"https://example.com/Login?dt=frmw0c9n": false,
		"https://example.com/login":             false,
	}
	if len(records) != len(expected) {
		t.Fatalf("unexpected page_url record count: %d records=%+v", len(records), records)
	}
	for _, record := range records {
		if record.Id != "page_url" {
			t.Fatalf("unexpected page_url record id: %s", record.Id)
		}
		if _, ok := expected[record.Content]; ok {
			expected[record.Content] = true
		}
	}
	for urlValue, hit := range expected {
		if !hit {
			t.Fatalf("missing expected page_url record: %s records=%+v", urlValue, records)
		}
	}
}

// TestScanJSResourcesRecursivelyScansImportedChunks 验证懒加载 chunk 会继续被抓取并参与静态分析。
func TestScanJSResourcesRecursivelyScansImportedChunks(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := ""
			switch req.URL.String() {
			case "https://example.com/assets/app.js":
				body = `const loginChunk = "./chunk-login.js"; import(loginChunk);`
			case "https://example.com/assets/chunk-login.js":
				body = `const routes = [{ path: "/loginAdmin", name: "LoginAdmin" }]; axios.get("/api/admin/detail")`
			default:
				return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
			}
			return &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: int64(len(body)),
				Header:        http.Header{"Content-Type": []string{"application/javascript"}},
				Body:          io.NopCloser(strings.NewReader(body)),
				Request:       req,
			}, nil
		}),
	}

	result := scanJSResources(client, "https://example.com", []string{"https://example.com/assets/app.js"})
	if len(result.Endpoints) != 1 {
		t.Fatalf("unexpected recursive js endpoint count: %d", len(result.Endpoints))
	}
	if result.Endpoints[0].URL != "https://example.com/api/admin/detail" {
		t.Fatalf("unexpected recursive endpoint url: %s", result.Endpoints[0].URL)
	}
	foundLoginAdmin := false
	for _, item := range result.PageURLs {
		if item == "https://example.com/loginAdmin" {
			foundLoginAdmin = true
			break
		}
	}
	if !foundLoginAdmin {
		t.Fatalf("expected loginAdmin page candidate in recursive scan, got=%+v", result.PageURLs)
	}
}

// TestExtractJSStaticSurfaceAppliesSchemaHints 验证静态 JS 参数会吸收 schema 里的类型与必填信息。
func TestExtractJSStaticSurfaceAppliesSchemaHints(t *testing.T) {
	jsBody := `
const searchSchema = z.object({
  keyword: z.string().default("demo"),
  pageNo: z.number().optional(),
  role: z.enum(["student", "teacher"])
})

const profileSchema = yup.object({
  enabled: yup.boolean().required(),
  tenantId: yup.string().default("tenant-a")
})

const authSchema = Joi.object({
  token: Joi.string().required(),
  level: Joi.number().default(3)
})

const jsonSchema = {
  type: "object",
  properties: {
    category: { type: "string", enum: ["news", "notice"] }
  },
  required: ["category"]
}

request({
  url: "/api/search",
  method: "POST",
  data: {
    keyword,
    pageNo,
    role,
    enabled,
    tenantId,
    token,
    level,
    category
  }
})
`

	_, parameters := extractJSStaticSurface(jsBody, "https://example.com/static/app.js")
	if len(parameters) < 8 {
		t.Fatalf("unexpected schema parameter count: %d", len(parameters))
	}

	paramMap := make(map[string]datatype.ParameterRecord)
	for _, parameter := range parameters {
		paramMap[parameter.ParamName] = parameter
	}

	if paramMap["keyword"].ParamType != "string" {
		t.Fatalf("unexpected keyword param type: %s", paramMap["keyword"].ParamType)
	}
	if paramMap["keyword"].Default != "demo" {
		t.Fatalf("unexpected keyword default: %s", paramMap["keyword"].Default)
	}
	if paramMap["keyword"].SourceDetail.SchemaLib != "zod" {
		t.Fatalf("unexpected keyword schema lib: %s", paramMap["keyword"].SourceDetail.SchemaLib)
	}
	if paramMap["pageNo"].Required {
		t.Fatal("pageNo 应被识别为 optional")
	}
	if len(paramMap["role"].Enum) != 2 {
		t.Fatalf("unexpected role enum: %+v", paramMap["role"].Enum)
	}
	if paramMap["enabled"].ParamType != "boolean" || !paramMap["enabled"].Required {
		t.Fatalf("unexpected enabled schema hint: %+v", paramMap["enabled"])
	}
	if paramMap["tenantId"].Default != "tenant-a" {
		t.Fatalf("unexpected tenantId default: %s", paramMap["tenantId"].Default)
	}
	if paramMap["token"].SourceDetail.SchemaLib != "joi" || !paramMap["token"].Required {
		t.Fatalf("unexpected token schema hint: %+v", paramMap["token"])
	}
	if paramMap["level"].ParamType != "number" {
		t.Fatalf("unexpected level param type: %s", paramMap["level"].ParamType)
	}
	if paramMap["category"].SourceDetail.SchemaLib != "json_schema" || !paramMap["category"].Required {
		t.Fatalf("unexpected category schema hint: %+v", paramMap["category"])
	}
	if len(paramMap["category"].Enum) != 2 {
		t.Fatalf("unexpected category enum: %+v", paramMap["category"].Enum)
	}
}

// TestExtractJSStaticSurfaceResolvesVariableReferences 验证静态提取能解析对象变量与位置参数引用。
func TestExtractJSStaticSurfaceResolvesVariableReferences(t *testing.T) {
	jsBody := "const payload = {\n" +
		"  keyword,\n" +
		"  pageNo,\n" +
		"  role\n" +
		"}\n\n" +
		"const API = {\n" +
		"  search: \"/api/search\",\n" +
		"  detail: \"/api/detail\"\n" +
		"}\n\n" +
		"const queryData = {\n" +
		"  userId,\n" +
		"  profile\n" +
		"}\n\n" +
		"const authHeaders = {\n" +
		"  Authorization: authToken,\n" +
		"  \"X-Tenant\": tenantId\n" +
		"}\n\n" +
		"const Queries = {\n" +
		"  demo: gql`\n" +
		"\tquery Demo($tenantId: String!, $userId: String!) {\n" +
		"\t  user(id: $userId) { id }\n" +
		"\t}\n" +
		"`\n" +
		"}\n\n" +
		"const variables = {\n" +
		"  tenantId,\n" +
		"  userId\n" +
		"}\n\n" +
		"const requestConfig = {\n" +
		"  url: API.detail,\n" +
		"  method: \"GET\",\n" +
		"  params: queryData,\n" +
		"  headers: authHeaders\n" +
		"}\n\n" +
		"const fetchOptions = {\n" +
		"  headers: authHeaders,\n" +
		"  body: payload\n" +
		"}\n\n" +
		"axios.post(API.search, payload)\n\n" +
		"axios.get(API.detail, {\n" +
		"  params: queryData,\n" +
		"  headers: authHeaders\n" +
		"})\n\n" +
		"fetch(API.search, fetchOptions)\n\n" +
		"request(requestConfig)\n\n" +
		"request({\n" +
		"  url: \"/graphql\",\n" +
		"  method: \"POST\",\n" +
		"  data: {\n" +
		"    query: Queries.demo,\n" +
		"    variables: variables\n" +
		"  }\n" +
		"})\n"

	endpoints, parameters := extractJSStaticSurface(jsBody, "https://example.com/static/app.js")
	if len(endpoints) != 3 {
		t.Fatalf("unexpected variable-ref endpoint count: %d", len(endpoints))
	}
	if len(parameters) < 9 {
		t.Fatalf("unexpected variable-ref parameter count: %d", len(parameters))
	}

	paramMap := make(map[string]datatype.ParameterRecord)
	for _, parameter := range parameters {
		paramMap[parameter.ParamName] = parameter
	}

	if paramMap["keyword"].Location != "body" {
		t.Fatalf("keyword should resolve to body, got=%s", paramMap["keyword"].Location)
	}
	if paramMap["userId"].Location != "graphql_variable" {
		t.Fatalf("userId should resolve to graphql_variable, got=%s", paramMap["userId"].Location)
	}
	if paramMap["Authorization"].Location != "header" {
		t.Fatalf("Authorization should resolve to header, got=%s", paramMap["Authorization"].Location)
	}
	if paramMap["profile"].Location != "query" {
		t.Fatalf("profile should resolve to query, got=%s", paramMap["profile"].Location)
	}

	gqlFound := false
	for _, endpoint := range endpoints {
		if endpoint.URL == "https://example.com/graphql" {
			gqlFound = true
			if !strings.Contains(endpoint.RequestTemplate.BodyText, "query Demo($tenantId: String!, $userId: String!)") {
				t.Fatalf("graphql query text should be resolved from variable: %s", endpoint.RequestTemplate.BodyText)
			}
		}
	}
	if !gqlFound {
		t.Fatal("graphql endpoint should exist")
	}
}

// TestExtractJSStaticSurfaceResolvesNestedMemberReferences 验证静态提取支持嵌套对象成员引用。
func TestExtractJSStaticSurfaceResolvesNestedMemberReferences(t *testing.T) {
	jsBody := "const API = {\n" +
		"  urls: {\n" +
		"    search: \"/api/search\",\n" +
		"    graphql: \"/graphql\"\n" +
		"  },\n" +
		"  payloads: {\n" +
		"    search: {\n" +
		"      keyword,\n" +
		"      pageNo\n" +
		"    }\n" +
		"  },\n" +
		"  headers: {\n" +
		"    auth: {\n" +
		"      Authorization: authToken,\n" +
		"      \"X-Tenant\": tenantId\n" +
		"    }\n" +
		"  },\n" +
		"  config: {\n" +
		"    search: {\n" +
		"      url: \"/api/search\",\n" +
		"      method: \"POST\",\n" +
		"      data: {\n" +
		"        keyword,\n" +
		"        pageNo\n" +
		"      },\n" +
		"      headers: {\n" +
		"        Authorization: authToken\n" +
		"      }\n" +
		"    }\n" +
		"  },\n" +
		"  queries: {\n" +
		"    user: {\n" +
		"      userId,\n" +
		"      profile\n" +
		"    }\n" +
		"  },\n" +
		"  gql: {\n" +
		"    demo: gql`\n" +
		"\tquery Demo($tenantId: String!, $userId: String!) {\n" +
		"\t  user(id: $userId) { id }\n" +
		"\t}\n" +
		"`\n" +
		"  }\n" +
		"}\n\n" +
		"fetch(API.urls.search, {\n" +
		"  method: \"POST\",\n" +
		"  headers: API.headers.auth,\n" +
		"  body: API.payloads.search\n" +
		"})\n\n" +
		"request(API.config.search)\n\n" +
		"request({\n" +
		"  url: API.urls.graphql,\n" +
		"  method: \"POST\",\n" +
		"  data: {\n" +
		"    query: API.gql.demo,\n" +
		"    variables: API.queries.user\n" +
		"  }\n" +
		"})\n"

	endpoints, parameters := extractJSStaticSurface(jsBody, "https://example.com/static/app.js")
	if len(endpoints) != 2 {
		t.Fatalf("unexpected nested-member endpoint count: %d", len(endpoints))
	}
	if len(parameters) < 6 {
		t.Fatalf("unexpected nested-member parameter count: %d", len(parameters))
	}

	paramMap := make(map[string]datatype.ParameterRecord)
	for _, parameter := range parameters {
		paramMap[parameter.ParamName] = parameter
	}

	if paramMap["keyword"].Location != "body" {
		t.Fatalf("keyword should resolve from nested payload, got=%s", paramMap["keyword"].Location)
	}
	if paramMap["Authorization"].Location != "header" {
		t.Fatalf("Authorization should resolve from nested headers, got=%s", paramMap["Authorization"].Location)
	}
	if paramMap["userId"].Location != "graphql_variable" {
		t.Fatalf("userId should resolve from nested graphql vars, got=%s", paramMap["userId"].Location)
	}

	for _, endpoint := range endpoints {
		if endpoint.URL == "https://example.com/graphql" && !strings.Contains(endpoint.RequestTemplate.BodyText, "query Demo($tenantId: String!, $userId: String!)") {
			t.Fatalf("nested graphql query should be preserved: %s", endpoint.RequestTemplate.BodyText)
		}
	}
}

// TestExtractJSStaticSurfaceFiltersNoiseLiterals 验证静态 endpoint 提取会过滤明显噪声字面量。
func TestExtractJSStaticSurfaceFiltersNoiseLiterals(t *testing.T) {
	jsBody := "const API = {\n" +
		"  mode: \"text\",\n" +
		"  header: \"set-cookie\",\n" +
		"  asset: \"index-9edb2d11.js\",\n" +
		"  search: \"/api/search\"\n" +
		"}\n\n" +
		"fetch(API.mode)\n" +
		"fetch(API.asset)\n" +
		"request({ url: API.header })\n" +
		"axios.get(API.search)\n"

	endpoints, _ := extractJSStaticSurface(jsBody, "https://example.com/assets/app.js")
	if len(endpoints) != 1 {
		t.Fatalf("unexpected filtered endpoint count: %d", len(endpoints))
	}
	if endpoints[0].URL != "https://example.com/api/search" {
		t.Fatalf("unexpected filtered endpoint url: %s", endpoints[0].URL)
	}
}

// TestSanitizeRuleRecordsForJS 验证 JS 规则命中会过滤明显噪声。
func TestSanitizeRuleRecordsForJS(t *testing.T) {
	records := []datatype.ScanRecord{
		{Id: "ip", Content: "1.2.3.4", Source: "https://example.com/assets/app.js"},
		{Id: "domain", Content: "o.app", Source: "https://example.com/assets/app.js"},
		{Id: "path", Content: "/runtime-core", Source: "https://example.com/assets/app.js"},
		{Id: "path", Content: "/api/user/list", Source: "https://example.com/assets/app.js"},
		{Id: "domain_url", Content: "https://vuejs.org/error-reference/#runtime-${n}", Source: "https://example.com/assets/app.js"},
		{Id: "password", Content: `PASSWORD="password"`, Source: "https://example.com/assets/app.js"},
	}

	filtered := sanitizeRuleRecords(records, "js")
	if len(filtered) != 1 {
		t.Fatalf("unexpected sanitized record count: %d", len(filtered))
	}
	if filtered[0].Id != "path" || filtered[0].Content != "/api/user/list" {
		t.Fatalf("unexpected sanitized record: %+v", filtered[0])
	}
}

// TestBuildPathProbeCandidatesSkipsJSSource 验证 path probe 不再消费来自 JS 资源的 path 记录。
func TestBuildPathProbeCandidatesSkipsJSSource(t *testing.T) {
	records := []datatype.ScanRecord{
		{Id: "path", Content: "/api/user/list", Source: "https://example.com/assets/app.js"},
	}
	candidates := buildPathProbeCandidates("https://example.com", records)
	if len(candidates) == 0 {
		t.Fatal("meaningful js-source path should produce probe candidates")
	}
}

// TestCollapseProbedPathRecords 验证已成功探测出的 path_url 会折叠原始 path 记录。
func TestCollapseProbedPathRecords(t *testing.T) {
	records := []datatype.ScanRecord{
		{Id: "path", Content: "/api/user/list", Source: "https://example.com/app.js"},
		{Id: "path_url", Content: "https://example.com/api/user/list", Source: "https://example.com/app.js", Tag: "path_probe status=200 title=demo"},
	}
	collapsed := collapseProbedPathRecords("https://example.com", records)
	if len(collapsed) != 1 {
		t.Fatalf("unexpected collapsed record count: %d", len(collapsed))
	}
	if collapsed[0].Id != "path_url" {
		t.Fatalf("unexpected collapsed record: %+v", collapsed[0])
	}
}

// TestExtractHTMLTitle 验证 path probe 可从 HTML 中提取标题。
func TestExtractHTMLTitle(t *testing.T) {
	body := []byte("<html><head><title> Demo Title </title></head><body></body></html>")
	titleText := extractHTMLTitle(body)
	if titleText != "Demo Title" {
		t.Fatalf("unexpected html title: %s", titleText)
	}
}

// TestProbeSinglePathCandidateIncludesTitleAndSize 验证 path probe 记录会带出标题与响应大小。
func TestProbeSinglePathCandidateIncludesTitleAndSize(t *testing.T) {
	body := "<html><head><title>Probe Demo</title></head><body>ok</body></html>"
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("X-WIH-Target"); got != "https://example.com" {
				t.Fatalf("unexpected X-WIH-Target header: %s", got)
			}
			return &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: int64(len(body)),
				Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:          io.NopCloser(strings.NewReader(body)),
				Request:       req,
			}, nil
		}),
	}

	record := probeSinglePathCandidate(client, "https://example.com", pathProbeCandidate{
		URL:    "https://example.com/api/demo",
		Source: "https://example.com/index.html",
	})
	if record == nil {
		t.Fatal("path probe record should not be nil")
	}
	if !strings.Contains(record.Tag, "title=Probe Demo") {
		t.Fatalf("path probe tag should include title: %s", record.Tag)
	}
	expectedSize := fmt.Sprintf("size=%d", len(body))
	if !strings.Contains(record.Tag, expectedSize) {
		t.Fatalf("path probe tag should include size: %s", record.Tag)
	}
}

// TestExtractRuntimeSurfaceDisabled 验证运行时采集默认关闭时不会返回结果。
func TestExtractRuntimeSurfaceDisabled(t *testing.T) {
	result := extractRuntimeSurface("https://example.com", nil)
	if len(result.Endpoints) != 0 || len(result.Parameters) != 0 {
		t.Fatalf("runtime surface should be empty when disabled: %+v", result)
	}
}

// TestParseRuntimeSurfaceResponseFiltersCrossHost 验证 external runtime 结果会继续受 host 过滤。
func TestParseRuntimeSurfaceResponseFiltersCrossHost(t *testing.T) {
	payload := map[string]any{
		"records": []map[string]any{
			{
				"id":      "page_url",
				"content": "https://example.com/portal?tenant=demo",
				"tag":     "runtime_page_candidate",
			},
			{
				"id":      "page_url",
				"content": "https://other.com/out",
			},
		},
		"endpoints": []map[string]any{
			{
				"endpoint_id": "runtime-ep-1",
				"url":         "https://example.com/api/user",
				"method":      "GET",
				"trigger_context": map[string]any{
					"page":  "https://example.com/admin",
					"event": "fetch",
				},
			},
			{
				"url":    "https://other.com/api/out",
				"method": "GET",
			},
		},
		"parameters": []map[string]any{
			{
				"endpoint_id": "runtime-ep-1",
				"param_name":  "id",
				"location":    "query",
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal runtime payload failed: %v", err)
	}

	result := parseRuntimeSurfaceResponse(raw, "https://example.com")
	if len(result.Records) != 1 {
		t.Fatalf("unexpected runtime record count: %d", len(result.Records))
	}
	if result.Records[0].Id != "page_url" || result.Records[0].Content != "https://example.com/portal?tenant=demo" {
		t.Fatalf("unexpected runtime record: %+v", result.Records[0])
	}
	if len(result.Endpoints) != 1 {
		t.Fatalf("unexpected runtime endpoint count: %d", len(result.Endpoints))
	}
	if result.Endpoints[0].URL != "https://example.com/api/user" {
		t.Fatalf("unexpected runtime endpoint url: %s", result.Endpoints[0].URL)
	}
	if result.Endpoints[0].PageURL != "https://example.com/admin" {
		t.Fatalf("unexpected runtime endpoint page url: %s", result.Endpoints[0].PageURL)
	}
	if result.Endpoints[0].RequestTemplate.RequestPacket == "" {
		t.Fatal("runtime endpoint request packet should be normalized")
	}
	if len(result.Parameters) != 1 {
		t.Fatalf("unexpected runtime parameter count: %d", len(result.Parameters))
	}
	if result.Parameters[0].EndpointID != result.Endpoints[0].EndpointID {
		t.Fatalf("runtime parameter endpoint id mismatch got=%s expected=%s", result.Parameters[0].EndpointID, result.Endpoints[0].EndpointID)
	}
	if result.Parameters[0].Source != "runtime" {
		t.Fatalf("unexpected runtime parameter source: %s", result.Parameters[0].Source)
	}
	if result.Parameters[0].SourceDetail.PageURL != "https://example.com/admin" {
		t.Fatalf("unexpected runtime parameter page url: %s", result.Parameters[0].SourceDetail.PageURL)
	}
}

// TestParseRuntimeSurfaceResponseBuildsPostRequestTemplate 验证 external runtime 返回 POST 结果时会自动补齐模板。
func TestParseRuntimeSurfaceResponseBuildsPostRequestTemplate(t *testing.T) {
	payload := map[string]any{
		"endpoints": []map[string]any{
			{
				"url":          "https://example.com/api/login",
				"method":       "POST",
				"content_type": "application/json",
				"request_template": map[string]any{
					"body": map[string]string{
						"username": "<value>",
						"password": "<value>",
					},
				},
			},
		},
		"parameters": []map[string]any{
			{
				"param_name": "username",
				"location":   "body",
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal runtime payload failed: %v", err)
	}

	result := parseRuntimeSurfaceResponse(raw, "https://example.com")
	if len(result.Endpoints) != 1 {
		t.Fatalf("unexpected runtime endpoint count: %d", len(result.Endpoints))
	}
	endpoint := result.Endpoints[0]
	if endpoint.RequestTemplate.Headers["Content-Type"] != "application/json" {
		t.Fatalf("unexpected runtime content-type: %s", endpoint.RequestTemplate.Headers["Content-Type"])
	}
	if !strings.Contains(endpoint.RequestTemplate.RequestPacket, "POST /api/login HTTP/1.1") {
		t.Fatalf("unexpected runtime request packet: %s", endpoint.RequestTemplate.RequestPacket)
	}
	if endpoint.RequestTemplate.BodyText == "" {
		t.Fatal("runtime request body preview should not be empty")
	}
	if len(result.Parameters) != 1 {
		t.Fatalf("unexpected runtime parameter count: %d", len(result.Parameters))
	}
	if result.Parameters[0].Location != "body" {
		t.Fatalf("runtime parameter location should be inferred as body: %s", result.Parameters[0].Location)
	}
	if result.Parameters[0].ParamType != "string" {
		t.Fatalf("runtime parameter type should be inferred as string: %s", result.Parameters[0].ParamType)
	}
}

// TestParseRuntimeSurfaceResponseBuildsGraphQLTemplate 验证 external runtime GraphQL 结果会自动补全 body 模板。
func TestParseRuntimeSurfaceResponseBuildsGraphQLTemplate(t *testing.T) {
	payload := map[string]any{
		"endpoints": []map[string]any{
			{
				"endpoint_id": "runtime-gql-1",
				"url":         "https://example.com/graphql",
				"method":      "POST",
				"body_kind":   "graphql",
				"request_template": map[string]any{
					"body": map[string]string{
						"query":    "query Demo { __typename }",
						"userId":   "<value>",
						"tenantId": "<value>",
					},
				},
			},
		},
		"parameters": []map[string]any{
			{
				"endpoint_id": "runtime-gql-1",
				"param_name":  "userId",
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal runtime payload failed: %v", err)
	}

	result := parseRuntimeSurfaceResponse(raw, "https://example.com")
	if len(result.Endpoints) != 1 {
		t.Fatalf("unexpected runtime endpoint count: %d", len(result.Endpoints))
	}
	endpoint := result.Endpoints[0]
	if endpoint.BodyKind != "graphql" {
		t.Fatalf("unexpected runtime graphql body kind: %s", endpoint.BodyKind)
	}
	if endpoint.RequestTemplate.BodyText == "" {
		t.Fatal("runtime graphql body preview should not be empty")
	}
	if !strings.Contains(endpoint.RequestTemplate.RequestPacket, "POST /graphql HTTP/1.1") {
		t.Fatalf("unexpected runtime graphql packet: %s", endpoint.RequestTemplate.RequestPacket)
	}
	if len(result.Parameters) != 1 {
		t.Fatalf("unexpected runtime graphql parameter count: %d", len(result.Parameters))
	}
	if result.Parameters[0].Location != "graphql_variable" {
		t.Fatalf("runtime graphql parameter location should be inferred as graphql_variable: %s", result.Parameters[0].Location)
	}
}

// TestResolveBuiltInPlaywrightDriverPath 验证仓库内置 Playwright 驱动路径可被解析。
func TestResolveBuiltInPlaywrightDriverPath(t *testing.T) {
	driverPath := resolveBuiltInPlaywrightDriverPath()
	if strings.TrimSpace(driverPath) == "" {
		t.Fatal("playwright driver path should not be empty")
	}
	if !strings.HasSuffix(driverPath, "tools/wih/runtime/playwright_driver.js") &&
		!strings.HasSuffix(driverPath, "runtime/playwright_driver.js") {
		t.Fatalf("unexpected playwright driver path: %s", driverPath)
	}
	commandText := resolveBuiltInPlaywrightDriverCommand()
	if !strings.Contains(commandText, "playwright_driver.js") {
		t.Fatalf("unexpected playwright driver command: %s", commandText)
	}
}

// TestRuntimeErrorMessage 验证 runtime driver 错误码会转成可读提示。
func TestRuntimeErrorMessage(t *testing.T) {
	message := runtimeErrorMessage("playwright_not_installed")
	if !strings.Contains(message, "Node Playwright") {
		t.Fatalf("unexpected runtime error message: %s", message)
	}
}

func TestRuntimeCommandFailureMessageTimeout(t *testing.T) {
	message := runtimeCommandFailureMessage(errors.New("signal: killed"), "", context.DeadlineExceeded, 60)
	if !strings.Contains(message, "超时") {
		t.Fatalf("unexpected timeout failure message: %s", message)
	}
	if !strings.Contains(message, "60") {
		t.Fatalf("timeout failure message should include timeout seconds: %s", message)
	}
	if !strings.Contains(message, "--runtime-timeout") {
		t.Fatalf("timeout failure message should suggest runtime-timeout: %s", message)
	}
}

// TestExtractJSStaticSurfaceWithSourceMapMeta 验证静态提取支持保留 source map 来源元信息。
func TestExtractJSStaticSurfaceWithSourceMapMeta(t *testing.T) {
	jsBody := `
axios.get("/api/source-map/detail", {
  params: {
    userId,
    tenantId
  }
})
`

	endpoints, parameters := extractJSStaticSurfaceWithMeta(
		jsBody,
		"https://example.com/__wih_sourcemap__/src/api.ts",
		"source_map_js",
		"source_map_js",
	)
	if len(endpoints) != 1 {
		t.Fatalf("unexpected source map endpoint count: %d", len(endpoints))
	}
	if len(parameters) != 2 {
		t.Fatalf("unexpected source map parameter count: %d", len(parameters))
	}
	if len(endpoints[0].SourceTypes) == 0 || endpoints[0].SourceTypes[0] != "source_map_js" {
		t.Fatalf("unexpected source map endpoint source types: %+v", endpoints[0].SourceTypes)
	}
	for _, parameter := range parameters {
		if parameter.Source != "source_map_js" {
			t.Fatalf("unexpected source map parameter source: %s", parameter.Source)
		}
		if parameter.SourceDetail.JSFile != "https://example.com/__wih_sourcemap__/src/api.ts" {
			t.Fatalf("unexpected source map js file: %s", parameter.SourceDetail.JSFile)
		}
	}
}

// TestCollectSourceMapScanUnitsUsesSourcesContent 验证 source map 的 sourcesContent 会转成扫描单元。
func TestCollectSourceMapScanUnitsUsesSourcesContent(t *testing.T) {
	mapBody := `{
  "version": 3,
  "file": "app.js",
  "sourceRoot": "/assets/",
  "sources": [
    "src/search.ts",
    "webpack://src/admin.ts"
  ],
  "sourcesContent": [
    "fetch('/api/search', { method: 'GET' })",
    "axios.post('/api/admin', { id })"
  ]
}`

	units := collectSourceMapScanUnits(nil, "https://example.com", "https://example.com/static/app.js.map", mapBody)
	if len(units) != 2 {
		t.Fatalf("unexpected source map unit count: %d", len(units))
	}
	if units[0].SourceType != "source_map_js" || units[0].ParameterSource != "source_map_js" {
		t.Fatalf("unexpected source map unit metadata: %+v", units[0])
	}
	if !strings.HasPrefix(units[0].URL, "https://example.com/") {
		t.Fatalf("unexpected source map unit url: %s", units[0].URL)
	}
	if strings.TrimSpace(units[0].Body) == "" {
		t.Fatal("source map unit body should not be empty")
	}
}
