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
	if gqlEndpoint.RequestTemplate.RequestPacket == "" {
		t.Fatal("graphql endpoint request packet should not be empty")
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
