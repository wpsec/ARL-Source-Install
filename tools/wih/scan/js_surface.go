package scan

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	datatype "wih/dataType"
	"wih/util"
)

var (
	fetchCallPattern       = regexp.MustCompile(`(?is)fetch\s*\(\s*([\"'` + "`" + `])([^"'` + "`" + `]+)\1`)
	axiosMethodCallPattern = regexp.MustCompile(`(?is)(?:[A-Za-z_$][\w$]*\.)+(get|post|put|delete|patch)\s*\(\s*([\"'` + "`" + `])([^"'` + "`" + `]+)\2`)
	configRequestPatterns  = []*regexp.Regexp{
		regexp.MustCompile(`(?is)axios(?:\.[A-Za-z_$][\w$]*)?\s*\(\s*\{`),
		regexp.MustCompile(`(?is)(?:[A-Za-z_$][\w$]*\.)?request\s*\(\s*\{`),
	}
	graphQLVariablePattern = regexp.MustCompile(`(?is)variables\s*:\s*\{([^}]{1,1200})\}`)
	queryObjectPatterns    = []*regexp.Regexp{
		regexp.MustCompile(`(?is)params\s*:\s*\{([^}]{1,1200})\}`),
		regexp.MustCompile(`(?is)new\s+URLSearchParams\s*\(\s*\{([^}]{1,1200})\}\s*\)`),
	}
	bodyObjectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)data\s*:\s*\{([^}]{1,1200})\}`),
		regexp.MustCompile(`(?is)body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{1,1200})\}\s*\)`),
		regexp.MustCompile(`(?is)body\s*:\s*\{([^}]{1,1200})\}`),
	}
	headerObjectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)headers\s*:\s*\{([^}]{1,1200})\}`),
	}
	appendCallPattern      = regexp.MustCompile(`(?is)\.(append|set)\s*\(\s*([\"'])([^\"']{1,120})\2`)
	urlConfigPattern       = regexp.MustCompile(`(?is)url\s*:\s*([\"'` + "`" + `])([^"'` + "`" + `]+)\1`)
	methodConfigPattern    = regexp.MustCompile(`(?is)(?:type|method)\s*:\s*([\"'` + "`" + `])([A-Za-z]+)\1`)
	graphQLSignalPattern   = regexp.MustCompile(`(?is)\b(query|mutation|operationName)\b`)
	objectKeyQuotedPattern = regexp.MustCompile(`(?is)[\"']([A-Za-z_][\w.-]{0,63})[\"']\s*:`)
	objectKeyBarePattern   = regexp.MustCompile(`(?is)(?<![\"'])\b([A-Za-z_][\w.-]{0,63})\b\s*:`)
	objectShorthandPattern = regexp.MustCompile(`(?:^|,)\s*(\.\.\.)?\s*([A-Za-z_][\w.-]{0,63})\s*(?=,|$)`)
	templateSegmentPattern = regexp.MustCompile(`\$\{\s*([^}]{1,80})\s*\}`)
	doubleBracePattern     = regexp.MustCompile(`\{\{\s*([^}]{1,80})\s*\}\}`)
	pathPlaceholderPattern = regexp.MustCompile(`\{([A-Za-z_][\w.-]{0,63})\}`)
)

type jsEndpointCandidate struct {
	Method        string
	URL           string
	QueryParams   []string
	BodyParams    []string
	HeaderParams  []string
	GraphQLParams []string
	ContentType   string
	BodyKind      string
	SourceType    string
}

func extractJSStaticSurface(jsBody string, jsURL string) ([]datatype.EndpointRecord, []datatype.ParameterRecord) {
	if strings.TrimSpace(jsBody) == "" || strings.TrimSpace(jsURL) == "" {
		return nil, nil
	}

	baseURL, err := url.Parse(strings.TrimSpace(jsURL))
	if err != nil || baseURL.Host == "" {
		return nil, nil
	}

	candidates := make([]jsEndpointCandidate, 0)
	for _, indexPair := range fetchCallPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(indexPair) < 6 {
			continue
		}
		rawURL := jsBody[indexPair[4]:indexPair[5]]
		window := buildJSRequestWindow(jsBody, indexPair[0])
		candidate := buildJSEndpointCandidate(jsURL, rawURL, "GET", window)
		if candidate.URL != "" {
			candidates = append(candidates, candidate)
		}
	}

	for _, indexPair := range axiosMethodCallPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(indexPair) < 8 {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(jsBody[indexPair[2]:indexPair[3]]))
		rawURL := jsBody[indexPair[6]:indexPair[7]]
		window := buildJSRequestWindow(jsBody, indexPair[0])
		candidate := buildJSEndpointCandidate(jsURL, rawURL, method, window)
		if candidate.URL != "" {
			candidates = append(candidates, candidate)
		}
	}

	for _, pattern := range configRequestPatterns {
		for _, indexPair := range pattern.FindAllStringIndex(jsBody, -1) {
			start := indexPair[0]
			window := buildJSRequestWindow(jsBody, start)
			urlMatch := urlConfigPattern.FindStringSubmatch(window)
			if len(urlMatch) < 3 {
				continue
			}
			methodText := "GET"
			if methodMatch := methodConfigPattern.FindStringSubmatch(window); len(methodMatch) >= 3 {
				methodText = strings.ToUpper(strings.TrimSpace(methodMatch[2]))
			}
			candidate := buildJSEndpointCandidate(jsURL, urlMatch[2], methodText, window)
			if candidate.URL != "" {
				candidates = append(candidates, candidate)
			}
		}
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	site := fmt.Sprintf("%s://%s", baseURL.Scheme, baseURL.Host)
	endpoints := make([]datatype.EndpointRecord, 0)
	parameters := make([]datatype.ParameterRecord, 0)
	for _, candidate := range dedupeJSEndpointCandidates(candidates) {
		endpointID := fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
			jsURL,
			candidate.Method,
			candidate.URL,
		}, "|")))
		parsedURL, err := url.Parse(candidate.URL)
		if err != nil || parsedURL.Host == "" {
			continue
		}

		queryTemplate := make(map[string]string)
		bodyTemplate := make(map[string]string)
		headerTemplate := make(map[string]string)
		for key, values := range parsedURL.Query() {
			if strings.TrimSpace(key) == "" {
				continue
			}
			queryTemplate[key] = firstNonEmpty(firstSliceValue(values), "<value>")
		}
		for _, name := range candidate.QueryParams {
			queryTemplate[name] = "<value>"
		}
		for _, name := range candidate.BodyParams {
			bodyTemplate[name] = "<value>"
		}
		for _, name := range candidate.GraphQLParams {
			bodyTemplate[name] = "<value>"
		}
		for _, name := range candidate.HeaderParams {
			headerTemplate[name] = "<value>"
		}
		if candidate.ContentType != "" {
			headerTemplate["Content-Type"] = candidate.ContentType
		}

		endpoints = append(endpoints, datatype.EndpointRecord{
			EndpointID:  endpointID,
			Site:        site,
			PageURL:     "",
			URL:         candidate.URL,
			Path:        parsedURL.Path,
			Method:      candidate.Method,
			Protocol:    parsedURL.Scheme,
			SourceTypes: uniqueSortedStrings([]string{candidate.SourceType}),
			TriggerContext: datatype.EndpointTriggerContext{
				Page:    "",
				Event:   "js_static_extract",
				DOMHint: "script",
			},
			ContentType: candidate.ContentType,
			BodyKind:    candidate.BodyKind,
			RequestTemplate: datatype.EndpointRequestTemplate{
				Headers: normalizeTemplateMap(headerTemplate),
				Query:   normalizeTemplateMap(queryTemplate),
				Body:    normalizeTemplateMap(bodyTemplate),
			},
			Confidence: 0.68,
		})

		parameters = append(parameters, buildJSQueryParameters(endpointID, jsURL, parsedURL, candidate.QueryParams)...)
		parameters = append(parameters, buildJSNamedParameters(endpointID, jsURL, "body", candidate.BodyParams, candidate.BodyKind, 0.66)...)
		parameters = append(parameters, buildJSNamedParameters(endpointID, jsURL, "header", candidate.HeaderParams, "header", 0.62)...)
		parameters = append(parameters, buildJSNamedParameters(endpointID, jsURL, "graphql_variable", candidate.GraphQLParams, "graphql", 0.72)...)
		parameters = append(parameters, buildJSPathParameters(endpointID, jsURL, parsedURL.Path)...)
	}

	return mergeEndpointRecords(endpoints), mergeParameterRecords(parameters)
}

func buildJSEndpointCandidate(baseJSURL string, rawURL string, defaultMethod string, requestWindow string) jsEndpointCandidate {
	resolvedURL, err := normalizeStaticEndpointURL(baseJSURL, rawURL)
	if err != nil || resolvedURL == "" {
		return jsEndpointCandidate{}
	}

	method := strings.ToUpper(strings.TrimSpace(defaultMethod))
	if method == "" {
		method = "GET"
	}
	loweredWindow := strings.ToLower(requestWindow)
	queryParams := collectObjectLiteralParamNames(requestWindow, queryObjectPatterns...)
	bodyParams := collectObjectLiteralParamNames(requestWindow, bodyObjectPatterns...)
	headerParams := collectHeaderNames(requestWindow)
	graphqlParams := collectObjectLiteralParamNames(requestWindow, graphQLVariablePattern)
	appendNames := collectAppendParamNames(requestWindow)
	if strings.Contains(loweredWindow, "formdata") {
		bodyParams = append(bodyParams, appendNames...)
	}
	if strings.Contains(loweredWindow, "urlsearchparams") {
		if method == "GET" {
			queryParams = append(queryParams, appendNames...)
		} else {
			bodyParams = append(bodyParams, appendNames...)
		}
	}
	contentType, bodyKind := inferJSBodyProfile(requestWindow, bodyParams, graphqlParams)
	if bodyKind == "graphql" {
		contentType = "application/json"
	}
	if (bodyKind == "form_urlencoded" || bodyKind == "multipart") && method == "GET" {
		method = "POST"
	}
	if len(bodyParams) > 0 || len(graphqlParams) > 0 || bodyKind != "" {
		if method == "GET" {
			method = "POST"
		}
	}

	return jsEndpointCandidate{
		Method:        method,
		URL:           resolvedURL,
		QueryParams:   uniqueSortedStrings(queryParams),
		BodyParams:    uniqueSortedStrings(bodyParams),
		HeaderParams:  uniqueSortedStrings(headerParams),
		GraphQLParams: uniqueSortedStrings(graphqlParams),
		ContentType:   contentType,
		BodyKind:      bodyKind,
		SourceType:    "static_js",
	}
}

func normalizeStaticEndpointURL(baseJSURL string, rawURL string) (string, error) {
	candidate := strings.TrimSpace(rawURL)
	if candidate == "" {
		return "", fmt.Errorf("empty url")
	}
	if strings.Contains(strings.ToLower(candidate), "javascript:") {
		return "", fmt.Errorf("javascript scheme")
	}

	candidate = templateSegmentPattern.ReplaceAllStringFunc(candidate, func(segment string) string {
		match := templateSegmentPattern.FindStringSubmatch(segment)
		if len(match) < 2 {
			return segment
		}
		return "{" + sanitizeTemplateToken(match[1]) + "}"
	})
	candidate = doubleBracePattern.ReplaceAllStringFunc(candidate, func(segment string) string {
		match := doubleBracePattern.FindStringSubmatch(segment)
		if len(match) < 2 {
			return segment
		}
		return "{" + sanitizeTemplateToken(match[1]) + "}"
	})
	if strings.Contains(candidate, "${") || strings.Contains(candidate, "{{") || strings.Contains(candidate, "}}") {
		return "", fmt.Errorf("unresolved template marker")
	}

	baseParsed, err := url.Parse(strings.TrimSpace(baseJSURL))
	if err != nil || baseParsed.Host == "" {
		return "", fmt.Errorf("invalid base js url")
	}

	if strings.HasPrefix(candidate, "//") {
		candidate = baseParsed.Scheme + ":" + candidate
	}

	targetURL, err := url.Parse(candidate)
	if err != nil {
		return "", err
	}
	resolved := baseParsed.ResolveReference(targetURL)
	if resolved == nil || resolved.Host == "" {
		return "", fmt.Errorf("invalid resolved url")
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme")
	}
	if !strings.EqualFold(resolved.Hostname(), baseParsed.Hostname()) {
		return "", fmt.Errorf("cross host endpoint")
	}
	if resolved.Path == "" {
		resolved.Path = "/"
	}
	resolved.Fragment = ""
	return resolved.String(), nil
}

func sanitizeTemplateToken(raw string) string {
	token := strings.TrimSpace(raw)
	token = regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(token, "_")
	token = strings.Trim(token, "._")
	if token == "" {
		return "param"
	}
	if len(token) > 40 {
		token = token[:40]
	}
	return token
}

func buildJSRequestWindow(content string, startIndex int) string {
	if startIndex < 0 {
		startIndex = 0
	}
	endIndex := startIndex + 1000
	if endIndex > len(content) {
		endIndex = len(content)
	}
	snippet := content[startIndex:endIndex]
	closeTokens := []string{");", "})", "};", "\n\n"}
	bestEnd := len(snippet)
	for _, token := range closeTokens {
		if pos := strings.Index(snippet, token); pos >= 0 && pos+len(token) < bestEnd {
			bestEnd = pos + len(token)
		}
	}
	return snippet[:bestEnd]
}

func collectObjectLiteralParamNames(source string, patterns ...*regexp.Regexp) []string {
	names := make([]string, 0)
	for _, pattern := range patterns {
		if pattern == nil {
			continue
		}
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			names = append(names, extractObjectLiteralKeys(match[1])...)
		}
	}
	return uniqueSortedStrings(names)
}

func collectAppendParamNames(source string) []string {
	names := make([]string, 0)
	for _, match := range appendCallPattern.FindAllStringSubmatch(source, -1) {
		if len(match) >= 4 {
			names = append(names, strings.TrimSpace(match[3]))
		}
	}
	return uniqueSortedStrings(names)
}

func collectHeaderNames(source string) []string {
	names := make([]string, 0)
	for _, pattern := range headerObjectPatterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			for _, headerName := range extractObjectLiteralKeys(match[1]) {
				lowered := strings.ToLower(strings.TrimSpace(headerName))
				if lowered == "" || lowered == "content-type" || lowered == "accept" {
					names = append(names, headerName)
					continue
				}
				names = append(names, headerName)
			}
		}
	}
	return uniqueSortedStrings(names)
}

func extractObjectLiteralKeys(raw string) []string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	result := make([]string, 0)
	seen := make(map[string]struct{})
	appendName := func(name string) {
		value := strings.TrimSpace(name)
		lowered := strings.ToLower(value)
		if value == "" {
			return
		}
		if _, ok := seen[lowered]; ok {
			return
		}
		switch lowered {
		case "method", "headers", "body", "url", "data", "params", "query", "variables":
			return
		}
		seen[lowered] = struct{}{}
		result = append(result, value)
	}

	for _, match := range objectKeyQuotedPattern.FindAllStringSubmatch(text, -1) {
		if len(match) >= 2 {
			appendName(match[1])
		}
	}
	for _, match := range objectKeyBarePattern.FindAllStringSubmatch(text, -1) {
		if len(match) >= 2 {
			appendName(match[1])
		}
	}

	normalized := regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	for _, match := range objectShorthandPattern.FindAllStringSubmatch(normalized, -1) {
		if len(match) < 3 {
			continue
		}
		if strings.TrimSpace(match[1]) != "" {
			continue
		}
		token := strings.TrimSpace(match[2])
		if token == "" || strings.ContainsAny(token, "()[]{}") {
			continue
		}
		appendName(token)
	}

	for _, match := range appendCallPattern.FindAllStringSubmatch(text, -1) {
		if len(match) >= 4 {
			appendName(match[3])
		}
	}
	return result
}

func inferJSBodyProfile(requestWindow string, bodyParams []string, graphqlParams []string) (string, string) {
	lowered := strings.ToLower(requestWindow)
	if len(graphqlParams) > 0 || graphQLSignalPattern.MatchString(requestWindow) {
		return "application/json", "graphql"
	}
	if strings.Contains(lowered, "multipart/form-data") {
		return "multipart/form-data", "multipart"
	}
	if strings.Contains(lowered, "application/x-www-form-urlencoded") || strings.Contains(lowered, "urlsearchparams") {
		return "application/x-www-form-urlencoded", "form_urlencoded"
	}
	if strings.Contains(lowered, "formdata") {
		return "multipart/form-data", "multipart"
	}
	if len(bodyParams) > 0 || strings.Contains(lowered, "json.stringify") || strings.Contains(lowered, "application/json") {
		return "application/json", "json"
	}
	return "", ""
}

func buildJSQueryParameters(endpointID string, jsURL string, endpointURL *url.URL, queryParams []string) []datatype.ParameterRecord {
	paramList := make([]datatype.ParameterRecord, 0)
	seen := make(map[string]struct{})
	if endpointURL != nil {
		for key, values := range endpointURL.Query() {
			name := strings.TrimSpace(key)
			if name == "" {
				continue
			}
			example := firstSliceValue(values)
			appendJSParameter(&paramList, seen, endpointID, jsURL, name, "query", "string", example, 0.64)
		}
	}
	for _, name := range queryParams {
		appendJSParameter(&paramList, seen, endpointID, jsURL, name, "query", "string", "", 0.66)
	}
	return paramList
}

func buildJSNamedParameters(endpointID string, jsURL string, location string, names []string, bodyKind string, confidence float64) []datatype.ParameterRecord {
	paramList := make([]datatype.ParameterRecord, 0)
	seen := make(map[string]struct{})
	paramType := "string"
	if location == "header" {
		paramType = "string"
	}
	if location == "graphql_variable" {
		paramType = "unknown"
	}
	for _, name := range names {
		appendJSParameter(&paramList, seen, endpointID, jsURL, name, location, paramType, "", confidence)
	}
	return paramList
}

func buildJSPathParameters(endpointID string, jsURL string, pathText string) []datatype.ParameterRecord {
	matches := pathPlaceholderPattern.FindAllStringSubmatch(pathText, -1)
	if len(matches) == 0 {
		return nil
	}
	paramList := make([]datatype.ParameterRecord, 0, len(matches))
	seen := make(map[string]struct{})
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		appendJSParameter(&paramList, seen, endpointID, jsURL, match[1], "path", "string", "", 0.64)
	}
	return paramList
}

func appendJSParameter(result *[]datatype.ParameterRecord, seen map[string]struct{}, endpointID string, jsURL string, name string, location string, paramType string, example string, confidence float64) {
	paramName := strings.TrimSpace(name)
	if paramName == "" {
		return
	}
	key := strings.ToLower(strings.TrimSpace(location)) + "|" + strings.ToLower(paramName)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}

	parameterID := fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
		endpointID,
		location,
		paramName,
	}, "|")))
	*result = append(*result, datatype.ParameterRecord{
		ParameterID: parameterID,
		EndpointID:  endpointID,
		ParamName:   paramName,
		Location:    location,
		ParamType:   paramType,
		Example:     strings.TrimSpace(example),
		Default:     strings.TrimSpace(example),
		Source:      "static_js",
		SourceDetail: datatype.ParameterSourceDetail{
			JSFile: jsURL,
		},
		Confidence:      confidence,
		OccurrenceCount: 1,
	})
}

func normalizeTemplateMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string)
	for key, value := range input {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		result[name] = firstNonEmpty(value, "<value>")
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func dedupeJSEndpointCandidates(candidates []jsEndpointCandidate) []jsEndpointCandidate {
	if len(candidates) <= 1 {
		return candidates
	}
	resultMap := make(map[string]jsEndpointCandidate)
	order := make([]string, 0)
	for _, candidate := range candidates {
		key := strings.Join([]string{
			strings.ToUpper(strings.TrimSpace(candidate.Method)),
			strings.TrimSpace(candidate.URL),
		}, "|")
		existing, ok := resultMap[key]
		if !ok {
			resultMap[key] = candidate
			order = append(order, key)
			continue
		}
		existing.QueryParams = uniqueSortedStrings(append(existing.QueryParams, candidate.QueryParams...))
		existing.BodyParams = uniqueSortedStrings(append(existing.BodyParams, candidate.BodyParams...))
		existing.HeaderParams = uniqueSortedStrings(append(existing.HeaderParams, candidate.HeaderParams...))
		existing.GraphQLParams = uniqueSortedStrings(append(existing.GraphQLParams, candidate.GraphQLParams...))
		if existing.ContentType == "" {
			existing.ContentType = candidate.ContentType
		}
		if existing.BodyKind == "" {
			existing.BodyKind = candidate.BodyKind
		}
		resultMap[key] = existing
	}
	result := make([]jsEndpointCandidate, 0, len(order))
	for _, key := range order {
		result = append(result, resultMap[key])
	}
	return result
}

func firstSliceValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
