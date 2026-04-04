package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	datatype "wih/dataType"
	"wih/global"
)

const multipartBoundary = "----WIHFormBoundary7MA4YWxkTrZu0gW"

func buildRequestTemplate(
	method string,
	endpointURL *url.URL,
	bodyKind string,
	pathParams map[string]string,
	queryParams map[string]string,
	bodyParams map[string]string,
	headerParams map[string]string,
	bodyText string,
) datatype.EndpointRequestTemplate {
	methodText := strings.ToUpper(strings.TrimSpace(method))
	if methodText == "" {
		methodText = "GET"
	}

	headers := cloneTemplateMap(headerParams)
	headers = ensureDefaultRequestHeaders(headers, methodText)

	pathMap := normalizeTemplateMap(pathParams)
	queryMap := normalizeTemplateMap(queryParams)
	bodyMap := normalizeTemplateMap(bodyParams)
	bodyPreview := buildBodyPreviewByKind(bodyKind, bodyMap, bodyText)

	if headers != nil {
		if contentType, ok := headers["Content-Type"]; ok {
			lowered := strings.ToLower(strings.TrimSpace(contentType))
			if strings.Contains(lowered, "multipart/form-data") && !strings.Contains(lowered, "boundary=") {
				headers["Content-Type"] = strings.TrimSpace(contentType) + "; boundary=" + multipartBoundary
			}
		}
	}

	queryString := buildQueryPreview(queryMap)
	if endpointURL != nil && endpointURL.RawQuery != "" {
		queryString = endpointURL.RawQuery
	}
	if queryString == "" && len(queryMap) > 0 {
		queryString = buildQueryPreview(queryMap)
	}

	if bodyPreview != "" && headers != nil {
		if _, ok := headers["Content-Length"]; !ok {
			headers["Content-Length"] = fmt.Sprintf("%d", len([]byte(bodyPreview)))
		}
	}

	requestPacket := buildRequestPacket(methodText, endpointURL, headers, bodyPreview)

	return datatype.EndpointRequestTemplate{
		Headers:       headers,
		Path:          pathMap,
		Query:         queryMap,
		Body:          bodyMap,
		QueryString:   queryString,
		BodyText:      bodyPreview,
		RequestPacket: requestPacket,
	}
}

func ensureDefaultRequestHeaders(headers map[string]string, method string) map[string]string {
	result := cloneTemplateMap(headers)
	if result == nil {
		result = make(map[string]string)
	}
	if _, ok := result["User-Agent"]; !ok {
		result["User-Agent"] = global.DefaultUserAgent
	}
	if _, ok := result["Accept"]; !ok {
		result["Accept"] = "application/json, text/plain, */*"
	}
	if _, ok := result["Connection"]; !ok {
		result["Connection"] = "close"
	}
	if strings.ToUpper(strings.TrimSpace(method)) == "GET" {
		delete(result, "Content-Length")
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func cloneTemplateMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		result[name] = strings.TrimSpace(value)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func buildQueryPreview(queryMap map[string]string) string {
	if len(queryMap) == 0 {
		return ""
	}
	keys := make([]string, 0, len(queryMap))
	for key := range queryMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(queryMap[key])))
	}
	return strings.Join(parts, "&")
}

func buildBodyPreview(bodyMap map[string]string) string {
	if len(bodyMap) == 0 {
		return ""
	}
	keys := make([]string, 0, len(bodyMap))
	for key := range bodyMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, bodyMap[key]))
	}
	return strings.Join(parts, "&")
}

func buildBodyPreviewByKind(bodyKind string, bodyMap map[string]string, bodyText string) string {
	trimmedBody := strings.TrimSpace(bodyText)
	if trimmedBody != "" {
		return trimmedBody
	}
	if len(bodyMap) == 0 {
		return ""
	}

	keys := make([]string, 0, len(bodyMap))
	for key := range bodyMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	switch strings.ToLower(strings.TrimSpace(bodyKind)) {
	case "json":
		payload := make(map[string]string, len(keys))
		for _, key := range keys {
			payload[key] = bodyMap[key]
		}
		raw, err := json.MarshalIndent(payload, "", "  ")
		if err == nil {
			return string(raw)
		}
	case "graphql":
		variables := make(map[string]string)
		queryText := "query Demo { __typename }"
		for _, key := range keys {
			if key == "query" && strings.TrimSpace(bodyMap[key]) != "" {
				queryText = strings.TrimSpace(bodyMap[key])
				continue
			}
			variables[key] = bodyMap[key]
		}
		payload := map[string]any{
			"query":     queryText,
			"variables": variables,
		}
		raw, err := json.MarshalIndent(payload, "", "  ")
		if err == nil {
			return string(raw)
		}
	case "multipart":
		return buildMultipartPreview(keys)
	case "xml":
		lines := []string{"<root>"}
		for _, key := range keys {
			lines = append(lines, fmt.Sprintf("  <%s>%s</%s>", key, bodyMap[key], key))
		}
		lines = append(lines, "</root>")
		return strings.Join(lines, "\n")
	case "form_urlencoded":
		return buildBodyPreview(bodyMap)
	}

	return buildBodyPreview(bodyMap)
}

func buildMultipartPreview(paramNames []string) string {
	if len(paramNames) == 0 {
		return ""
	}
	lines := make([]string, 0, len(paramNames)*4+1)
	for _, rawName := range paramNames {
		name := strings.TrimSpace(rawName)
		if name == "" {
			continue
		}
		lines = append(lines, "--"+multipartBoundary)
		lines = append(lines, fmt.Sprintf(`Content-Disposition: form-data; name="%s"`, name))
		lines = append(lines, "")
		lines = append(lines, "<value>")
	}
	lines = append(lines, "--"+multipartBoundary+"--")
	return strings.Join(lines, "\n")
}

func buildRequestPacket(method string, endpointURL *url.URL, headers map[string]string, bodyText string) string {
	if endpointURL == nil {
		return ""
	}
	requestPath := strings.TrimSpace(endpointURL.Path)
	if requestPath == "" {
		requestPath = "/"
	}
	if endpointURL.RawQuery != "" {
		requestPath = requestPath + "?" + endpointURL.RawQuery
	}

	lines := []string{fmt.Sprintf("%s %s HTTP/1.1", method, requestPath)}
	hostText := strings.TrimSpace(endpointURL.Host)
	if hostText != "" {
		lines = append(lines, "Host: "+hostText)
	}

	if len(headers) > 0 {
		keys := make([]string, 0, len(headers))
		for key := range headers {
			if strings.EqualFold(strings.TrimSpace(key), "Host") {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := strings.TrimSpace(headers[key])
			if value == "" {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s: %s", key, value))
		}
	}

	lines = append(lines, "")
	if strings.TrimSpace(bodyText) != "" {
		lines = append(lines, bodyText)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func extractPathParameters(pathText string) map[string]string {
	matches := pathPlaceholderPattern.FindAllStringSubmatch(pathText, -1)
	if len(matches) == 0 {
		return nil
	}
	result := make(map[string]string)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		result[name] = "<value>"
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
