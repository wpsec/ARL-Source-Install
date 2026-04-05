package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	datatype "wih/dataType"
	"wih/util"
)

var (
	fetchCallPattern       = regexp.MustCompile("(?is)fetch\\s*\\(\\s*(?:\"([^\"]+)\"|'([^']+)'|`([^`]+)`)")
	axiosMethodCallPattern = regexp.MustCompile("(?is)(?:[A-Za-z_$][\\w$]*\\.)+(get|post|put|delete|patch)\\s*\\(\\s*(?:\"([^\"]+)\"|'([^']+)'|`([^`]+)`)")
	configRequestPatterns  = []*regexp.Regexp{
		regexp.MustCompile(`(?is)axios(?:\.[A-Za-z_$][\w$]*)?\s*\(\s*\{`),
		regexp.MustCompile(`(?is)(?:[A-Za-z_$][\w$]*\.)?request\s*\(\s*\{`),
	}
	graphQLVariablePattern = regexp.MustCompile(`(?is)variables\s*:\s*\{([^}]{1,1000})\}`)
	queryObjectPatterns    = []*regexp.Regexp{
		regexp.MustCompile(`(?is)params\s*:\s*\{([^}]{1,1000})\}`),
		regexp.MustCompile(`(?is)new\s+URLSearchParams\s*\(\s*\{([^}]{1,1000})\}\s*\)`),
	}
	bodyObjectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)data\s*:\s*\{([^}]{1,1000})\}`),
		regexp.MustCompile(`(?is)body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{1,1000})\}\s*\)`),
		regexp.MustCompile(`(?is)body\s*:\s*\{([^}]{1,1000})\}`),
	}
	headerObjectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)headers\s*:\s*\{([^}]{1,1000})\}`),
	}
	appendCallPattern       = regexp.MustCompile(`(?is)\.(append|set)\s*\(\s*(?:"([^"]{1,120})"|'([^']{1,120})')`)
	fetchVarPattern         = regexp.MustCompile(`(?is)\bfetch\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	axiosMethodVarPattern   = regexp.MustCompile(`(?is)(?:[A-Za-z_$][\w$]*\.)+(get|post|put|delete|patch)\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	urlConfigPattern        = regexp.MustCompile("(?is)url\\s*:\\s*(?:\"([^\"]+)\"|'([^']+)'|`([^`]+)`)")
	urlConfigVarPattern     = regexp.MustCompile(`(?is)\burl\s*:\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	methodConfigPattern     = regexp.MustCompile("(?is)(?:type|method)\\s*:\\s*(?:\"([A-Za-z]+)\"|'([A-Za-z]+)'|`([A-Za-z]+)`)")
	requestConfigVarPattern = regexp.MustCompile(`(?is)(?:axios(?:\.[A-Za-z_$][\w$]*)?|(?:[A-Za-z_$][\w$]*\.)?request)\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\)`)
	graphQLSignalPattern    = regexp.MustCompile(`(?is)\b(query|mutation|operationName)\b`)
	graphQLQueryPattern     = regexp.MustCompile("(?is)\\bquery\\s*:\\s*(?:\"([^\"]{1,1000})\"|'([^']{1,1000})'|`([^`]{1,1000})`)")
	graphQLTaggedPattern    = regexp.MustCompile("(?is)gql\\s*`([^`]{1,1000})`")
	objectAssignPattern     = regexp.MustCompile(`(?is)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{`)
	urlSearchAssignPattern  = regexp.MustCompile(`(?is)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+URLSearchParams\s*\(\s*\{`)
	formDataAssignPattern   = regexp.MustCompile(`(?is)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+FormData\s*\(`)
	paramsVarPattern        = regexp.MustCompile(`(?is)\bparams\s*:\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	bodyVarPattern          = regexp.MustCompile(`(?is)\b(?:data|body)\s*:\s*(?:JSON\.stringify\s*\(\s*)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	headersVarPattern       = regexp.MustCompile(`(?is)\bheaders\s*:\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	graphQLVarsVarPattern   = regexp.MustCompile(`(?is)\bvariables\s*:\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	graphQLQueryVarPattern  = regexp.MustCompile(`(?is)\bquery\s*:\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
	objectKeyQuotedPattern  = regexp.MustCompile(`(?is)[\"']([A-Za-z_][\w.-]{0,63})[\"']\s*:`)
	objectKeyBarePattern    = regexp.MustCompile(`(?is)(?:^|[{\s,])([A-Za-z_][\w.-]{0,63})\s*:`)
	objectShorthandPattern  = regexp.MustCompile(`(?:^|,)\s*(\.\.\.)?\s*([A-Za-z_][\w.-]{0,63})\s*(?:,|$)`)
	templateSegmentPattern  = regexp.MustCompile(`\$\{\s*([^}]{1,80})\s*\}`)
	doubleBracePattern      = regexp.MustCompile(`\{\{\s*([^}]{1,80})\s*\}\}`)
	pathPlaceholderPattern  = regexp.MustCompile(`\{([A-Za-z_][\w.-]{0,63})\}`)
)

type jsEndpointCandidate struct {
	Method        string
	URL           string
	QueryParams   []string
	BodyParams    []string
	HeaderParams  []string
	GraphQLParams []string
	GraphQLQuery  string
	ContentType   string
	BodyKind      string
	SourceType    string
}

type jsVariableHints struct {
	ObjectFields   map[string][]string
	ObjectRaw      map[string]string
	MemberFields   map[string][]string
	MemberRaw      map[string]string
	URLSearchField map[string][]string
	FormDataFields map[string][]string
	StringValues   map[string]string
	MemberStrings  map[string]string
}

func extractJSStaticSurface(jsBody string, jsURL string) ([]datatype.EndpointRecord, []datatype.ParameterRecord) {
	return extractJSStaticSurfaceWithMeta(jsBody, jsURL, "static_js", "static_js")
}

func extractJSStaticSurfaceWithMeta(jsBody string, jsURL string, endpointSourceType string, parameterSource string) ([]datatype.EndpointRecord, []datatype.ParameterRecord) {
	if strings.TrimSpace(jsBody) == "" || strings.TrimSpace(jsURL) == "" {
		return nil, nil
	}

	baseURL, err := url.Parse(strings.TrimSpace(jsURL))
	if err != nil || baseURL.Host == "" {
		return nil, nil
	}
	variableHints := buildJSVariableHints(jsBody)

	candidates := make([]jsEndpointCandidate, 0)
	for _, match := range fetchCallPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(match) < 8 {
			continue
		}
		rawURL := firstIndexedValue(jsBody, match[2:4], match[4:6], match[6:8])
		window := expandJSRequestWindowWithConfig(buildJSRequestWindow(jsBody, match[0]), variableHints)
		candidate := buildJSEndpointCandidate(jsURL, rawURL, "GET", window, endpointSourceType, variableHints)
		if candidate.URL != "" {
			candidates = append(candidates, candidate)
		}
	}

	for _, match := range fetchVarPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(match) < 4 {
			continue
		}
		rawURL := firstIndexedValue(jsBody, match[2:4])
		window := expandJSRequestWindowWithConfig(buildJSRequestWindow(jsBody, match[0]), variableHints)
		candidate := buildJSEndpointCandidate(jsURL, rawURL, "GET", window, endpointSourceType, variableHints)
		if candidate.URL != "" {
			candidates = append(candidates, candidate)
		}
	}

	for _, match := range axiosMethodCallPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(match) < 10 {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(firstIndexedValue(jsBody, match[2:4])))
		rawURL := firstIndexedValue(jsBody, match[4:6], match[6:8], match[8:10])
		window := expandJSRequestWindowWithConfig(buildJSRequestWindow(jsBody, match[0]), variableHints)
		candidate := buildJSEndpointCandidate(jsURL, rawURL, method, window, endpointSourceType, variableHints)
		if candidate.URL != "" {
			candidates = append(candidates, candidate)
		}
	}

	for _, match := range axiosMethodVarPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(match) < 6 {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(firstIndexedValue(jsBody, match[2:4])))
		rawURL := firstIndexedValue(jsBody, match[4:6])
		window := expandJSRequestWindowWithConfig(buildJSRequestWindow(jsBody, match[0]), variableHints)
		candidate := buildJSEndpointCandidate(jsURL, rawURL, method, window, endpointSourceType, variableHints)
		if candidate.URL != "" {
			candidates = append(candidates, candidate)
		}
	}

	for _, pattern := range configRequestPatterns {
		for _, indexPair := range pattern.FindAllStringIndex(jsBody, -1) {
			start := indexPair[0]
			window := buildJSRequestWindow(jsBody, start)
			urlMatch := urlConfigPattern.FindStringSubmatch(window)
			rawURL := firstNonEmpty(matchValue(urlMatch, 1), collectReferencedStringValue(window, urlConfigVarPattern, variableHints.StringValues, variableHints.MemberStrings))
			if strings.TrimSpace(rawURL) == "" {
				continue
			}
			methodText := "GET"
			if methodMatch := methodConfigPattern.FindStringSubmatch(window); len(methodMatch) > 0 {
				methodText = strings.ToUpper(strings.TrimSpace(matchValue(methodMatch, 1)))
			}
			candidate := buildJSEndpointCandidate(jsURL, rawURL, methodText, window, endpointSourceType, variableHints)
			if candidate.URL != "" {
				candidates = append(candidates, candidate)
			}
		}
	}

	for _, match := range requestConfigVarPattern.FindAllStringSubmatch(jsBody, -1) {
		if len(match) < 2 {
			continue
		}
		configName := strings.ToLower(strings.TrimSpace(match[1]))
		configWindow, ok := resolveObjectReferenceRaw(configName, variableHints)
		if !ok || strings.TrimSpace(configWindow) == "" {
			continue
		}
		rawURL := firstNonEmpty(matchValue(urlConfigPattern.FindStringSubmatch(configWindow), 1), collectReferencedStringValue(configWindow, urlConfigVarPattern, variableHints.StringValues, variableHints.MemberStrings))
		if strings.TrimSpace(rawURL) == "" {
			continue
		}
		methodText := "GET"
		if methodMatch := methodConfigPattern.FindStringSubmatch(configWindow); len(methodMatch) > 0 {
			methodText = strings.ToUpper(strings.TrimSpace(matchValue(methodMatch, 1)))
		}
		candidate := buildJSEndpointCandidate(jsURL, rawURL, methodText, configWindow, endpointSourceType, variableHints)
		if candidate.URL != "" {
			candidates = append(candidates, candidate)
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
		bodyPreview := buildJSBodyPreview(candidate.BodyKind, bodyTemplate, candidate.GraphQLParams, candidate.GraphQLQuery)
		requestTemplate := buildRequestTemplate(
			candidate.Method,
			parsedURL,
			candidate.BodyKind,
			extractPathParameters(parsedURL.Path),
			queryTemplate,
			bodyTemplate,
			headerTemplate,
			bodyPreview,
		)

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
			ContentType:     candidate.ContentType,
			BodyKind:        candidate.BodyKind,
			RequestTemplate: requestTemplate,
			Confidence:      0.68,
		})

		parameters = append(parameters, buildJSQueryParameters(endpointID, jsURL, parsedURL, candidate.QueryParams, parameterSource)...)
		parameters = append(parameters, buildJSNamedParameters(endpointID, jsURL, "body", candidate.BodyParams, candidate.BodyKind, 0.66, parameterSource)...)
		parameters = append(parameters, buildJSNamedParameters(endpointID, jsURL, "header", candidate.HeaderParams, "header", 0.62, parameterSource)...)
		parameters = append(parameters, buildJSNamedParameters(endpointID, jsURL, "graphql_variable", candidate.GraphQLParams, "graphql", 0.72, parameterSource)...)
		parameters = append(parameters, buildJSPathParameters(endpointID, jsURL, parsedURL.Path, parameterSource)...)
	}

	parameters = applyJSSchemaHints(parameters, jsBody)
	return mergeEndpointRecords(endpoints), mergeParameterRecords(parameters)
}

func buildJSBodyPreview(bodyKind string, bodyMap map[string]string, graphqlParams []string, graphQLQuery string) string {
	normalizedBodyMap := normalizeTemplateMap(bodyMap)
	if len(normalizedBodyMap) == 0 {
		return ""
	}

	keys := make([]string, 0, len(normalizedBodyMap))
	for key := range normalizedBodyMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	switch strings.ToLower(strings.TrimSpace(bodyKind)) {
	case "json":
		payload := make(map[string]string, len(keys))
		for _, key := range keys {
			payload[key] = normalizedBodyMap[key]
		}
		raw, err := json.MarshalIndent(payload, "", "  ")
		if err == nil {
			return string(raw)
		}
	case "graphql":
		variables := make(map[string]string)
		for _, name := range graphqlParams {
			if value, ok := normalizedBodyMap[name]; ok {
				variables[name] = value
			}
		}
		payload := map[string]any{
			"query":     firstNonEmpty(strings.TrimSpace(graphQLQuery), "query Demo { __typename }"),
			"variables": variables,
		}
		raw, err := json.MarshalIndent(payload, "", "  ")
		if err == nil {
			return string(raw)
		}
	case "form_urlencoded":
		return buildBodyPreview(normalizedBodyMap)
	case "multipart":
		formNames := make([]string, 0, len(keys))
		formNames = append(formNames, keys...)
		return buildMultipartPreview(formNames)
	}
	return buildBodyPreview(normalizedBodyMap)
}

func buildJSEndpointCandidate(baseJSURL string, rawURL string, defaultMethod string, requestWindow string, sourceType string, variableHints jsVariableHints) jsEndpointCandidate {
	resolvedURL, err := resolveStaticEndpointExpression(baseJSURL, rawURL, variableHints.StringValues, variableHints.MemberStrings)
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
	queryParams = append(queryParams, collectReferencedNames(requestWindow, paramsVarPattern, variableHints.ObjectFields, variableHints.URLSearchField, variableHints.MemberFields)...)
	bodyParams = append(bodyParams, collectReferencedNames(requestWindow, bodyVarPattern, variableHints.ObjectFields, variableHints.FormDataFields, variableHints.MemberFields)...)
	headerParams = append(headerParams, collectReferencedNames(requestWindow, headersVarPattern, variableHints.ObjectFields, variableHints.MemberFields)...)
	graphqlParams = append(graphqlParams, collectReferencedNames(requestWindow, graphQLVarsVarPattern, variableHints.ObjectFields, variableHints.MemberFields)...)
	appendNames := collectAppendParamNames(requestWindow)
	positionalBodyExpr, _, hasPositional := extractAxiosPositionalExpressions(requestWindow)
	if hasPositional {
		bodyParams = append(bodyParams, extractFieldsFromExpression(positionalBodyExpr, variableHints)...)
	}
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
	graphQLQuery := ""
	if bodyKind == "graphql" {
		graphQLQuery = extractGraphQLQueryText(requestWindow)
		if strings.TrimSpace(graphQLQuery) == "" {
			graphQLQuery = collectReferencedStringValue(requestWindow, graphQLQueryVarPattern, variableHints.StringValues, variableHints.MemberStrings)
		}
	}
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
		GraphQLQuery:  graphQLQuery,
		ContentType:   contentType,
		BodyKind:      bodyKind,
		SourceType:    firstNonEmpty(strings.TrimSpace(sourceType), "static_js"),
	}
}

func buildJSVariableHints(jsBody string) jsVariableHints {
	hints := jsVariableHints{
		ObjectFields:   make(map[string][]string),
		ObjectRaw:      make(map[string]string),
		MemberFields:   make(map[string][]string),
		MemberRaw:      make(map[string]string),
		URLSearchField: make(map[string][]string),
		FormDataFields: make(map[string][]string),
		StringValues:   make(map[string]string),
		MemberStrings:  make(map[string]string),
	}

	for _, match := range objectAssignPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(match) < 4 {
			continue
		}
		name := strings.TrimSpace(firstIndexedValue(jsBody, match[2:4]))
		if name == "" {
			continue
		}
		block, ok := extractBalancedObject(jsBody, match[1]-1)
		if !ok || strings.TrimSpace(block) == "" {
			continue
		}
		hints.ObjectRaw[strings.ToLower(name)] = strings.TrimSpace(block)
		fields := extractObjectLiteralKeys(block)
		if len(fields) > 0 {
			hints.ObjectFields[strings.ToLower(name)] = uniqueSortedStrings(fields)
		}
	}

	for _, match := range urlSearchAssignPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(match) < 4 {
			continue
		}
		name := strings.TrimSpace(firstIndexedValue(jsBody, match[2:4]))
		if name == "" {
			continue
		}
		block, ok := extractBalancedObject(jsBody, match[1]-1)
		if !ok || strings.TrimSpace(block) == "" {
			continue
		}
		fields := extractObjectLiteralKeys(block)
		if len(fields) > 0 {
			hints.URLSearchField[strings.ToLower(name)] = uniqueSortedStrings(fields)
		}
	}

	for _, match := range formDataAssignPattern.FindAllStringSubmatchIndex(jsBody, -1) {
		if len(match) < 4 {
			continue
		}
		name := strings.TrimSpace(firstIndexedValue(jsBody, match[2:4]))
		if name == "" {
			continue
		}
		pattern := regexp.MustCompile(fmt.Sprintf(`(?is)\b%s\.(?:append|set)\s*\(\s*(?:"([^"]{1,120})"|'([^']{1,120})')`, regexp.QuoteMeta(name)))
		fields := make([]string, 0)
		for _, item := range pattern.FindAllStringSubmatch(jsBody, -1) {
			field := strings.TrimSpace(firstNonEmpty(matchValue(item, 1), matchValue(item, 2)))
			if field != "" {
				fields = append(fields, field)
			}
		}
		if len(fields) > 0 {
			hints.FormDataFields[strings.ToLower(name)] = uniqueSortedStrings(fields)
		}
	}

	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile("(?is)\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:gql\\s*)?`([^`]{1,1000})`"),
		regexp.MustCompile(`(?is)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"([^"]{1,1000})"`),
		regexp.MustCompile(`(?is)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*'([^']{1,1000})'`),
	} {
		for _, item := range pattern.FindAllStringSubmatch(jsBody, -1) {
			if len(item) < 3 {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(item[1]))
			value := strings.TrimSpace(item[2])
			if name == "" || value == "" {
				continue
			}
			hints.StringValues[name] = value
		}
	}

	visited := make(map[string]struct{})
	for objectName, rawObject := range hints.ObjectRaw {
		populateJSMemberHints(objectName, rawObject, &hints, visited, 0)
	}

	return hints
}

func populateJSMemberHints(baseName string, rawObject string, hints *jsVariableHints, visited map[string]struct{}, depth int) {
	if hints == nil || depth > 4 {
		return
	}
	objectName := strings.ToLower(strings.TrimSpace(baseName))
	objectText := strings.TrimSpace(rawObject)
	if objectName == "" || objectText == "" {
		return
	}
	visitKey := objectName + "|" + objectText
	if _, ok := visited[visitKey]; ok {
		return
	}
	visited[visitKey] = struct{}{}

	for fieldName, expr := range parseTopLevelObjectFields(objectText) {
		fieldKey := strings.ToLower(strings.TrimSpace(fieldName))
		exprText := strings.TrimSpace(expr)
		if fieldKey == "" || exprText == "" {
			continue
		}
		memberKey := objectName + "." + fieldKey

		if value, ok := resolveStringReferenceWithMembers(exprText, hints.StringValues, hints.MemberStrings); ok && strings.TrimSpace(value) != "" {
			hints.MemberStrings[memberKey] = strings.TrimSpace(value)
		} else if value, ok := extractInlineStringValue(exprText); ok && strings.TrimSpace(value) != "" {
			hints.MemberStrings[memberKey] = strings.TrimSpace(value)
		}

		if strings.HasPrefix(exprText, "{") && strings.HasSuffix(exprText, "}") {
			hints.MemberRaw[memberKey] = exprText
			if fields := extractObjectLiteralKeys(exprText); len(fields) > 0 {
				hints.MemberFields[memberKey] = uniqueSortedStrings(fields)
			}
			populateJSMemberHints(memberKey, exprText, hints, visited, depth+1)
			continue
		}

		refName := strings.ToLower(strings.TrimSpace(exprText))
		if refName == "" {
			continue
		}
		if rawRef, ok := hints.ObjectRaw[refName]; ok && strings.TrimSpace(rawRef) != "" {
			hints.MemberRaw[memberKey] = strings.TrimSpace(rawRef)
			if fields, ok := hints.ObjectFields[refName]; ok && len(fields) > 0 {
				hints.MemberFields[memberKey] = uniqueSortedStrings(fields)
			}
			populateJSMemberHints(memberKey, rawRef, hints, visited, depth+1)
			continue
		}
		if rawRef, ok := hints.MemberRaw[refName]; ok && strings.TrimSpace(rawRef) != "" {
			hints.MemberRaw[memberKey] = strings.TrimSpace(rawRef)
			if fields, ok := hints.MemberFields[refName]; ok && len(fields) > 0 {
				hints.MemberFields[memberKey] = uniqueSortedStrings(fields)
			}
			populateJSMemberHints(memberKey, rawRef, hints, visited, depth+1)
			continue
		}
		if fields, ok := hints.ObjectFields[refName]; ok && len(fields) > 0 {
			hints.MemberFields[memberKey] = uniqueSortedStrings(fields)
			continue
		}
		if fields, ok := hints.MemberFields[refName]; ok && len(fields) > 0 {
			hints.MemberFields[memberKey] = uniqueSortedStrings(fields)
			continue
		}
		if fields, ok := hints.URLSearchField[refName]; ok && len(fields) > 0 {
			hints.MemberFields[memberKey] = uniqueSortedStrings(fields)
			continue
		}
		if fields, ok := hints.FormDataFields[refName]; ok && len(fields) > 0 {
			hints.MemberFields[memberKey] = uniqueSortedStrings(fields)
		}
	}
}

func collectReferencedNames(source string, pattern *regexp.Regexp, sources ...map[string][]string) []string {
	if pattern == nil || strings.TrimSpace(source) == "" {
		return nil
	}
	result := make([]string, 0)
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		name := strings.ToLower(strings.TrimSpace(matchValue(match, 1)))
		if name == "" {
			continue
		}
		for _, sourceMap := range sources {
			if sourceMap == nil {
				continue
			}
			result = append(result, sourceMap[name]...)
		}
	}
	return uniqueSortedStrings(result)
}

func collectReferencedStringValue(source string, pattern *regexp.Regexp, valueMap map[string]string, memberMap map[string]string) string {
	if pattern == nil || valueMap == nil {
		if memberMap == nil {
			return ""
		}
	}
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		name := strings.ToLower(strings.TrimSpace(matchValue(match, 1)))
		if value, ok := resolveStringReferenceWithMembers(name, valueMap, memberMap); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func extractAxiosPositionalExpressions(requestWindow string) (string, string, bool) {
	text := strings.TrimSpace(requestWindow)
	if text == "" {
		return "", "", false
	}
	openIndex := strings.Index(text, "(")
	if openIndex < 0 {
		return "", "", false
	}
	argsText, ok := extractBalancedParenContent(text[openIndex:])
	if !ok {
		return "", "", false
	}
	parts := splitTopLevel(argsText, ',')
	if len(parts) < 2 {
		return "", "", false
	}
	bodyExpr := strings.TrimSpace(parts[1])
	configExpr := ""
	if len(parts) >= 3 {
		configExpr = strings.TrimSpace(parts[2])
	}
	return bodyExpr, configExpr, true
}

func extractFieldsFromExpression(expr string, variableHints jsVariableHints) []string {
	text := strings.TrimSpace(expr)
	if text == "" {
		return nil
	}
	if strings.HasPrefix(text, "{") {
		return extractObjectLiteralKeys(text)
	}
	name := strings.ToLower(strings.TrimSpace(text))
	if fields, ok := variableHints.ObjectFields[name]; ok {
		return fields
	}
	if fields, ok := variableHints.MemberFields[name]; ok {
		return fields
	}
	if fields, ok := variableHints.FormDataFields[name]; ok {
		return fields
	}
	if fields, ok := variableHints.URLSearchField[name]; ok {
		return fields
	}
	return nil
}

func extractGraphQLQueryText(requestWindow string) string {
	if strings.TrimSpace(requestWindow) == "" {
		return ""
	}
	if match := graphQLQueryPattern.FindStringSubmatch(requestWindow); len(match) > 0 {
		return strings.TrimSpace(matchValue(match, 1))
	}
	if match := graphQLTaggedPattern.FindStringSubmatch(requestWindow); len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func resolveStaticEndpointExpression(baseJSURL string, rawExpr string, stringValues map[string]string, memberStrings map[string]string) (string, error) {
	expr := strings.TrimSpace(rawExpr)
	if expr == "" {
		return "", fmt.Errorf("empty url expression")
	}
	if value, ok := resolveStringReferenceWithMembers(expr, stringValues, memberStrings); ok {
		expr = value
	}
	return normalizeStaticEndpointURL(baseJSURL, expr)
}

func resolveStringReference(expr string, valueMap map[string]string) (string, bool) {
	if valueMap == nil {
		return "", false
	}
	name := strings.ToLower(strings.TrimSpace(expr))
	if name == "" {
		return "", false
	}
	value, ok := valueMap[name]
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func resolveStringReferenceWithMembers(expr string, valueMap map[string]string, memberMap map[string]string) (string, bool) {
	if value, ok := resolveStringReference(expr, valueMap); ok {
		return value, true
	}
	if memberMap == nil {
		return "", false
	}
	name := strings.ToLower(strings.TrimSpace(expr))
	if name == "" {
		return "", false
	}
	value, ok := memberMap[name]
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func extractInlineStringValue(expr string) (string, bool) {
	text := strings.TrimSpace(expr)
	if text == "" {
		return "", false
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`^"([^"]{1,1000})"$`),
		regexp.MustCompile(`^'([^']{1,1000})'$`),
		regexp.MustCompile("^`([^`]{1,1000})`$"),
		regexp.MustCompile("(?is)^gql\\s*`([^`]{1,1000})`$"),
	} {
		match := pattern.FindStringSubmatch(text)
		if len(match) < 2 {
			continue
		}
		return strings.TrimSpace(match[1]), true
	}
	return "", false
}

func expandJSRequestWindowWithConfig(requestWindow string, variableHints jsVariableHints) string {
	text := strings.TrimSpace(requestWindow)
	if text == "" || len(variableHints.ObjectRaw) == 0 {
		return text
	}
	openIndex := strings.Index(text, "(")
	if openIndex < 0 {
		return text
	}
	argsText, ok := extractBalancedParenContent(text[openIndex:])
	if !ok || strings.TrimSpace(argsText) == "" {
		return text
	}
	parts := splitTopLevel(argsText, ',')
	if len(parts) < 2 {
		return text
	}

	result := text
	seen := make(map[string]struct{})
	for index := 1; index < len(parts) && index <= 2; index++ {
		name := strings.ToLower(strings.TrimSpace(parts[index]))
		if name == "" {
			continue
		}
		raw, ok := resolveObjectReferenceRaw(name, variableHints)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		if _, duplicated := seen[name]; duplicated {
			continue
		}
		seen[name] = struct{}{}
		result += "\n" + raw
	}
	return result
}

func resolveObjectReferenceRaw(expr string, hints jsVariableHints) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(expr))
	if name == "" {
		return "", false
	}
	if raw, ok := hints.ObjectRaw[name]; ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw), true
	}
	if raw, ok := hints.MemberRaw[name]; ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw), true
	}
	return "", false
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
			names = append(names, strings.TrimSpace(firstNonEmpty(match[2], match[3])))
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
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		text = strings.TrimSpace(text[1 : len(text)-1])
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

	normalized := strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(text, " "))
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

	for _, segment := range strings.Split(normalized, ",") {
		token := strings.TrimSpace(segment)
		if token == "" || strings.Contains(token, ":") {
			continue
		}
		token = strings.TrimPrefix(token, "...")
		token = strings.TrimSpace(token)
		if token == "" || strings.ContainsAny(token, "()[]{} ") {
			continue
		}
		appendName(token)
	}

	for _, match := range appendCallPattern.FindAllStringSubmatch(text, -1) {
		if len(match) >= 4 {
			appendName(firstNonEmpty(match[2], match[3]))
		}
	}
	return result
}

func firstIndexedValue(source string, pairs ...[]int) string {
	for _, pair := range pairs {
		if len(pair) < 2 {
			continue
		}
		start := pair[0]
		end := pair[1]
		if start < 0 || end < 0 || end <= start || end > len(source) {
			continue
		}
		value := strings.TrimSpace(source[start:end])
		if value != "" {
			return value
		}
	}
	return ""
}

func matchValue(match []string, start int) string {
	if len(match) <= start || start < 0 {
		return ""
	}
	return firstNonEmpty(match[start:]...)
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

func buildJSQueryParameters(endpointID string, jsURL string, endpointURL *url.URL, queryParams []string, parameterSource string) []datatype.ParameterRecord {
	paramList := make([]datatype.ParameterRecord, 0)
	seen := make(map[string]struct{})
	if endpointURL != nil {
		for key, values := range endpointURL.Query() {
			name := strings.TrimSpace(key)
			if name == "" {
				continue
			}
			example := firstSliceValue(values)
			appendJSParameter(&paramList, seen, endpointID, jsURL, name, "query", "string", example, 0.64, parameterSource)
		}
	}
	for _, name := range queryParams {
		appendJSParameter(&paramList, seen, endpointID, jsURL, name, "query", "string", "", 0.66, parameterSource)
	}
	return paramList
}

func buildJSNamedParameters(endpointID string, jsURL string, location string, names []string, bodyKind string, confidence float64, parameterSource string) []datatype.ParameterRecord {
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
		appendJSParameter(&paramList, seen, endpointID, jsURL, name, location, paramType, "", confidence, parameterSource)
	}
	return paramList
}

func buildJSPathParameters(endpointID string, jsURL string, pathText string, parameterSource string) []datatype.ParameterRecord {
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
		appendJSParameter(&paramList, seen, endpointID, jsURL, match[1], "path", "string", "", 0.64, parameterSource)
	}
	return paramList
}

func appendJSParameter(result *[]datatype.ParameterRecord, seen map[string]struct{}, endpointID string, jsURL string, name string, location string, paramType string, example string, confidence float64, parameterSource string) {
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
	paramRecord := datatype.ParameterRecord{
		ParameterID: parameterID,
		EndpointID:  endpointID,
		ParamName:   paramName,
		Location:    location,
		ParamType:   paramType,
		Example:     strings.TrimSpace(example),
		Default:     strings.TrimSpace(example),
		Source:      firstNonEmpty(strings.TrimSpace(parameterSource), "static_js"),
		SourceDetail: datatype.ParameterSourceDetail{
			JSFile: jsURL,
		},
		Confidence:      confidence,
		OccurrenceCount: 1,
	}
	*result = append(*result, enrichParameterMetadata(paramRecord))
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
