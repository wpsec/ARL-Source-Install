package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"

	datatype "wih/dataType"
	"wih/global"
	"wih/util"
)

// runtimeSurfaceResult 表示运行时参数采集结果。
type runtimeSurfaceResult struct {
	Endpoints  []datatype.EndpointRecord
	Parameters []datatype.ParameterRecord
}

type runtimeSurfaceRequest struct {
	TargetURL      string            `json:"target_url"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty"`
	MaxPages       int               `json:"max_pages"`
	MaxActions     int               `json:"max_actions"`
	MaxRequests    int               `json:"max_requests"`
	FollowRedirect bool              `json:"follow_redirect"`
	TimeoutSec     int               `json:"timeout_sec"`
}

type runtimeSurfaceResponse struct {
	Endpoints  []datatype.EndpointRecord  `json:"endpoints"`
	Parameters []datatype.ParameterRecord `json:"parameters"`
}

// extractRuntimeSurface 为运行时 Hook MVP 提供统一接入口。
//
// 当前支持两种模式：
// - noop: 默认空实现，保持独立工具稳定
// - external: 调用外部命令，通过 stdin/stdout 交换 JSON
func extractRuntimeSurface(targetURL string) runtimeSurfaceResult {
	if !global.RuntimeEnable {
		return runtimeSurfaceResult{}
	}

	switch strings.ToLower(strings.TrimSpace(global.RuntimeDriver)) {
	case "", "noop":
		return runtimeSurfaceResult{}
	case "external":
		return extractRuntimeSurfaceByExternalDriver(targetURL)
	default:
		return runtimeSurfaceResult{}
	}
}

func extractRuntimeSurfaceByExternalDriver(targetURL string) runtimeSurfaceResult {
	commandText := strings.TrimSpace(global.RuntimeCommand)
	if commandText == "" {
		return runtimeSurfaceResult{}
	}

	timeoutSec := int(global.RuntimeTimeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 20
	}

	requestPayload := runtimeSurfaceRequest{
		TargetURL: targetURL,
		DefaultHeaders: map[string]string{
			"User-Agent": global.DefaultUserAgent,
			"Accept":     "application/json, text/plain, */*",
		},
		MaxPages:       global.RuntimeMaxPages,
		MaxActions:     global.RuntimeMaxActions,
		MaxRequests:    global.RuntimeMaxRequests,
		FollowRedirect: global.FollowRedirect,
		TimeoutSec:     timeoutSec,
	}

	requestBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return runtimeSurfaceResult{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), global.RuntimeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", commandText)
	cmd.Stdin = bytes.NewReader(requestBytes)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return runtimeSurfaceResult{}
	}

	return parseRuntimeSurfaceResponse(stdout.Bytes(), targetURL)
}

func parseRuntimeSurfaceResponse(raw []byte, targetURL string) runtimeSurfaceResult {
	if len(bytes.TrimSpace(raw)) == 0 {
		return runtimeSurfaceResult{}
	}

	resp := runtimeSurfaceResponse{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return runtimeSurfaceResult{}
	}

	targetParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || targetParsed.Host == "" {
		return runtimeSurfaceResult{}
	}
	targetHost := strings.ToLower(strings.TrimSpace(targetParsed.Hostname()))

	endpoints := make([]datatype.EndpointRecord, 0, len(resp.Endpoints))
	parameters := make([]datatype.ParameterRecord, 0, len(resp.Parameters))
	allowedEndpointIDs := make(map[string]struct{})
	endpointIDAlias := make(map[string]string)
	endpointMap := make(map[string]datatype.EndpointRecord)

	for _, endpoint := range resp.Endpoints {
		originalEndpointID := strings.TrimSpace(endpoint.EndpointID)
		normalizedEndpoint, ok := normalizeRuntimeEndpoint(endpoint, targetURL, targetHost)
		if !ok {
			continue
		}
		allowedEndpointIDs[normalizedEndpoint.EndpointID] = struct{}{}
		if originalEndpointID != "" {
			endpointIDAlias[originalEndpointID] = normalizedEndpoint.EndpointID
		}
		endpointMap[normalizedEndpoint.EndpointID] = normalizedEndpoint
		endpoints = append(endpoints, normalizedEndpoint)
	}

	singleEndpointID := ""
	if len(endpoints) == 1 {
		singleEndpointID = endpoints[0].EndpointID
	}

	for _, parameter := range resp.Parameters {
		normalizedParameter, ok := normalizeRuntimeParameter(parameter, endpointIDAlias, singleEndpointID, endpointMap)
		if !ok {
			continue
		}
		if _, ok := allowedEndpointIDs[strings.TrimSpace(normalizedParameter.EndpointID)]; !ok {
			continue
		}
		parameters = append(parameters, enrichParameterMetadata(normalizedParameter))
	}

	return runtimeSurfaceResult{
		Endpoints:  mergeEndpointRecords(endpoints),
		Parameters: mergeParameterRecords(parameters),
	}
}

func normalizeRuntimeEndpoint(endpoint datatype.EndpointRecord, targetURL string, targetHost string) (datatype.EndpointRecord, bool) {
	urlText := strings.TrimSpace(endpoint.URL)
	if urlText == "" {
		return datatype.EndpointRecord{}, false
	}
	parsed, err := url.Parse(urlText)
	if err != nil || parsed.Host == "" {
		return datatype.EndpointRecord{}, false
	}
	if strings.ToLower(strings.TrimSpace(parsed.Hostname())) != targetHost {
		return datatype.EndpointRecord{}, false
	}

	methodText := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	if methodText == "" {
		methodText = "GET"
	}

	normalized := endpoint
	if strings.TrimSpace(normalized.EndpointID) == "" {
		normalized.EndpointID = fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
			targetURL,
			methodText,
			parsed.String(),
		}, "|")))
	}
	normalized.URL = parsed.String()
	normalized.Path = firstNonEmpty(strings.TrimSpace(parsed.Path), "/")
	normalized.Method = methodText
	normalized.Protocol = firstNonEmpty(strings.TrimSpace(parsed.Scheme), "https")
	normalized.SourceTypes = uniqueSortedStrings(append(normalized.SourceTypes, "runtime_hook"))
	normalized.ContentType = firstNonEmpty(
		strings.TrimSpace(normalized.ContentType),
		strings.TrimSpace((normalized.RequestTemplate.Headers)["Content-Type"]),
		strings.TrimSpace((normalized.RequestTemplate.Headers)["content-type"]),
	)
	if strings.TrimSpace(normalized.BodyKind) == "" {
		normalized.BodyKind = inferRuntimeBodyKind(normalized.ContentType, normalized.RequestTemplate.Body, normalized.RequestTemplate.BodyText)
	}
	normalized.RequestTemplate = buildRuntimeRequestTemplate(parsed, normalized.Method, normalized.ContentType, normalized.BodyKind, normalized.RequestTemplate)
	if strings.TrimSpace(normalized.TriggerContext.Event) == "" {
		normalized.TriggerContext.Event = "runtime_hook"
	}
	if normalized.Confidence <= 0 {
		normalized.Confidence = 0.93
	}
	return normalized, true
}

func normalizeRuntimeParameter(
	parameter datatype.ParameterRecord,
	endpointIDAlias map[string]string,
	singleEndpointID string,
	endpointMap map[string]datatype.EndpointRecord,
) (datatype.ParameterRecord, bool) {
	normalized := parameter
	normalized.ParamName = strings.TrimSpace(normalized.ParamName)
	if normalized.ParamName == "" {
		return datatype.ParameterRecord{}, false
	}

	locationText := strings.ToLower(strings.TrimSpace(normalized.Location))
	switch locationText {
	case "query", "path", "body", "header", "cookie", "graphql_variable":
		normalized.Location = locationText
	default:
		if locationText == "" {
			normalized.Location = "body"
		} else {
			normalized.Location = locationText
		}
	}

	endpointID := strings.TrimSpace(normalized.EndpointID)
	if endpointID != "" {
		if mappedID, ok := endpointIDAlias[endpointID]; ok {
			normalized.EndpointID = mappedID
		}
	} else if singleEndpointID != "" {
		normalized.EndpointID = singleEndpointID
	}

	if strings.TrimSpace(normalized.EndpointID) == "" {
		return datatype.ParameterRecord{}, false
	}

	endpoint := endpointMap[strings.TrimSpace(normalized.EndpointID)]
	normalized.Location = inferRuntimeParameterLocation(normalized.ParamName, normalized.Location, endpoint)
	normalized.ParamType = inferRuntimeParameterType(normalized, endpoint)
	if strings.TrimSpace(normalized.Example) == "" && strings.TrimSpace(normalized.Default) == "" {
		example, def := inferRuntimeParameterSample(normalized.ParamName, normalized.Location, endpoint)
		normalized.Example = example
		normalized.Default = def
	}

	if strings.TrimSpace(normalized.ParameterID) == "" {
		normalized.ParameterID = fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
			normalized.EndpointID,
			strings.ToLower(strings.TrimSpace(normalized.Location)),
			strings.ToLower(normalized.ParamName),
		}, "|")))
	}
	if normalized.OccurrenceCount <= 0 {
		normalized.OccurrenceCount = 1
	}
	if normalized.Confidence <= 0 {
		normalized.Confidence = 0.90
	}
	return normalized, true
}

func buildRuntimeRequestTemplate(
	endpointURL *url.URL,
	method string,
	contentType string,
	bodyKind string,
	template datatype.EndpointRequestTemplate,
) datatype.EndpointRequestTemplate {
	queryMap := cloneTemplateMap(template.Query)
	bodyMap := cloneTemplateMap(template.Body)
	headerMap := cloneTemplateMap(template.Headers)
	pathMap := cloneTemplateMap(template.Path)
	bodyText := buildBodyPreviewByKind(bodyKind, bodyMap, template.BodyText)

	clonedURL := *endpointURL
	if strings.TrimSpace(clonedURL.RawQuery) == "" && strings.TrimSpace(template.QueryString) != "" {
		clonedURL.RawQuery = strings.TrimSpace(template.QueryString)
	}
	if pathMap == nil {
		pathMap = extractPathParameters(firstNonEmpty(clonedURL.Path, "/"))
	}
	if headerMap == nil {
		headerMap = make(map[string]string)
	}
	if strings.TrimSpace(contentType) != "" {
		if _, ok := headerMap["Content-Type"]; !ok {
			headerMap["Content-Type"] = strings.TrimSpace(contentType)
		}
	}
	return buildRequestTemplate(
		method,
		&clonedURL,
		bodyKind,
		pathMap,
		queryMap,
		bodyMap,
		headerMap,
		bodyText,
	)
}

func inferRuntimeBodyKind(contentType string, bodyMap map[string]string, bodyText string) string {
	loweredContentType := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.Contains(loweredContentType, "graphql"):
		return "graphql"
	case strings.Contains(loweredContentType, "application/json"):
		if _, ok := bodyMap["query"]; ok {
			return "graphql"
		}
		return "json"
	case strings.Contains(loweredContentType, "application/x-www-form-urlencoded"):
		return "form_urlencoded"
	case strings.Contains(loweredContentType, "multipart/form-data"):
		return "multipart"
	case strings.Contains(loweredContentType, "xml"):
		return "xml"
	}

	trimmedBodyText := strings.TrimSpace(bodyText)
	switch {
	case strings.HasPrefix(trimmedBodyText, "{"), strings.HasPrefix(trimmedBodyText, "["):
		if _, ok := bodyMap["query"]; ok {
			return "graphql"
		}
		return "json"
	case strings.Contains(trimmedBodyText, multipartBoundary):
		return "multipart"
	case strings.HasPrefix(trimmedBodyText, "<"):
		return "xml"
	case strings.Contains(trimmedBodyText, "="):
		return "form_urlencoded"
	default:
		return ""
	}
}

func inferRuntimeParameterLocation(paramName string, currentLocation string, endpoint datatype.EndpointRecord) string {
	location := strings.ToLower(strings.TrimSpace(currentLocation))
	switch location {
	case "query", "path", "body", "header", "cookie", "graphql_variable":
		return location
	}
	name := strings.TrimSpace(paramName)
	if name == "" {
		return "body"
	}
	if _, ok := endpoint.RequestTemplate.Path[name]; ok {
		return "path"
	}
	if _, ok := endpoint.RequestTemplate.Query[name]; ok {
		return "query"
	}
	if _, ok := endpoint.RequestTemplate.Headers[name]; ok {
		return "header"
	}
	if _, ok := endpoint.RequestTemplate.Body[name]; ok {
		if strings.EqualFold(endpoint.BodyKind, "graphql") {
			return "graphql_variable"
		}
		return "body"
	}
	if strings.EqualFold(endpoint.Method, "GET") {
		return "query"
	}
	return "body"
}

func inferRuntimeParameterType(parameter datatype.ParameterRecord, endpoint datatype.EndpointRecord) string {
	paramType := strings.ToLower(strings.TrimSpace(parameter.ParamType))
	if paramType != "" && paramType != "unknown" {
		return paramType
	}
	name := strings.TrimSpace(parameter.ParamName)
	sample := firstNonEmpty(parameter.Example, parameter.Default)
	if strings.EqualFold(parameter.Location, "header") {
		return "string"
	}
	if looksLikeBooleanValue(sample) {
		return "boolean"
	}
	if looksLikeNumberValue(sample) {
		return "number"
	}
	loweredName := strings.ToLower(name)
	if strings.Contains(loweredName, "file") || strings.Contains(loweredName, "image") || strings.Contains(loweredName, "avatar") {
		return "file"
	}
	if strings.EqualFold(endpoint.BodyKind, "json") || strings.EqualFold(endpoint.BodyKind, "graphql") {
		return "string"
	}
	return "unknown"
}

func inferRuntimeParameterSample(paramName string, location string, endpoint datatype.EndpointRecord) (string, string) {
	name := strings.TrimSpace(paramName)
	if name == "" {
		return "", ""
	}
	switch strings.ToLower(strings.TrimSpace(location)) {
	case "path":
		if value, ok := endpoint.RequestTemplate.Path[name]; ok {
			return value, value
		}
	case "query":
		if value, ok := endpoint.RequestTemplate.Query[name]; ok {
			return value, value
		}
	case "header":
		if value, ok := endpoint.RequestTemplate.Headers[name]; ok {
			return value, value
		}
	case "graphql_variable", "body":
		if value, ok := endpoint.RequestTemplate.Body[name]; ok {
			return value, value
		}
	}
	return "", ""
}

func looksLikeBooleanValue(value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	return text == "true" || text == "false"
}

func looksLikeNumberValue(value string) bool {
	text := strings.TrimSpace(value)
	if text == "" {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
