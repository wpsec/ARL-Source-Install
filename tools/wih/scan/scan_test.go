package scan

import (
	"encoding/json"
	"strings"
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

// TestExtractRuntimeSurfaceDisabled 验证运行时采集默认关闭时不会返回结果。
func TestExtractRuntimeSurfaceDisabled(t *testing.T) {
	result := extractRuntimeSurface("https://example.com")
	if len(result.Endpoints) != 0 || len(result.Parameters) != 0 {
		t.Fatalf("runtime surface should be empty when disabled: %+v", result)
	}
}

// TestParseRuntimeSurfaceResponseFiltersCrossHost 验证 external runtime 结果会继续受 host 过滤。
func TestParseRuntimeSurfaceResponseFiltersCrossHost(t *testing.T) {
	payload := map[string]any{
		"endpoints": []map[string]any{
			{
				"endpoint_id": "runtime-ep-1",
				"url":         "https://example.com/api/user",
				"method":      "GET",
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
	if len(result.Endpoints) != 1 {
		t.Fatalf("unexpected runtime endpoint count: %d", len(result.Endpoints))
	}
	if result.Endpoints[0].URL != "https://example.com/api/user" {
		t.Fatalf("unexpected runtime endpoint url: %s", result.Endpoints[0].URL)
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
