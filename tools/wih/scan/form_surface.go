package scan

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	datatype "wih/dataType"
	"wih/util"
)

var (
	formPattern     = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputPattern    = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	textareaPattern = regexp.MustCompile(`(?is)<textarea\b([^>]*)>(.*?)</textarea>`)
	selectPattern   = regexp.MustCompile(`(?is)<select\b([^>]*)>(.*?)</select>`)
	optionPattern   = regexp.MustCompile(`(?is)<option\b([^>]*)>(.*?)</option>`)
	attrPattern     = regexp.MustCompile(`(?is)([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)
)

type formField struct {
	Name      string
	FieldType string
	Required  bool
	Default   string
	Example   string
	Enum      []string
}

func extractHTMLFormSurface(pageBody string, pageURL string) ([]datatype.EndpointRecord, []datatype.ParameterRecord) {
	if strings.TrimSpace(pageBody) == "" || strings.TrimSpace(pageURL) == "" {
		return nil, nil
	}

	pageParsed, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil || pageParsed.Host == "" {
		return nil, nil
	}

	site := fmt.Sprintf("%s://%s", pageParsed.Scheme, pageParsed.Host)
	endpoints := make([]datatype.EndpointRecord, 0)
	parameters := make([]datatype.ParameterRecord, 0)

	for _, formMatch := range formPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(formMatch) < 3 {
			continue
		}

		formAttrs := parseHTMLAttributes(formMatch[1])
		formInner := formMatch[2]
		actionRaw := firstNonEmpty(formAttrs["action"], pageURL)
		actionURL, err := resolveSameHostURL(pageParsed, actionRaw)
		if err != nil || actionURL == nil {
			continue
		}

		method := strings.ToUpper(strings.TrimSpace(firstNonEmpty(formAttrs["method"], "GET")))
		if method == "" {
			method = "GET"
		}

		enctype := strings.TrimSpace(strings.ToLower(formAttrs["enctype"]))
		contentType, bodyKind := inferFormContentType(method, enctype)
		fields := collectFormFields(formInner)
		if len(fields) == 0 && actionURL.RawQuery == "" {
			continue
		}

		endpointID := fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
			pageURL,
			method,
			actionURL.String(),
		}, "|")))
		requestTemplate := buildFormRequestTemplate(actionURL, method, fields, contentType)

		endpoint := datatype.EndpointRecord{
			EndpointID:  endpointID,
			Site:        site,
			PageURL:     pageURL,
			URL:         actionURL.String(),
			Path:        actionURL.Path,
			Method:      method,
			Protocol:    actionURL.Scheme,
			SourceTypes: []string{"dom_form"},
			TriggerContext: datatype.EndpointTriggerContext{
				Page:    pageURL,
				Event:   "form_submit",
				DOMHint: "form",
			},
			ContentType:     contentType,
			BodyKind:        bodyKind,
			RequestTemplate: requestTemplate,
			Confidence:      0.72,
		}
		endpoints = append(endpoints, endpoint)

		location := "body"
		if method == "GET" {
			location = "query"
		}
		parameters = append(parameters, buildActionQueryParameters(endpointID, pageURL, actionURL, method)...)
		for _, field := range fields {
			paramID := fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
				endpointID,
				location,
				field.Name,
			}, "|")))
			paramRecord := datatype.ParameterRecord{
				ParameterID: paramID,
				EndpointID:  endpointID,
				ParamName:   field.Name,
				Location:    location,
				ParamType:   field.FieldType,
				Required:    field.Required,
				Example:     field.Example,
				Default:     field.Default,
				Enum:        field.Enum,
				Source:      "dom_form",
				SourceDetail: datatype.ParameterSourceDetail{
					PageURL: pageURL,
				},
				Confidence:      0.72,
				OccurrenceCount: 1,
			}
			parameters = append(parameters, enrichParameterMetadata(paramRecord))
		}
	}

	return mergeEndpointRecords(endpoints), mergeParameterRecords(parameters)
}

func parseHTMLAttributes(raw string) map[string]string {
	attrs := make(map[string]string)
	for _, match := range attrPattern.FindAllStringSubmatch(raw, -1) {
		if len(match) < 5 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(match[1]))
		value := firstNonEmpty(match[2], match[3], match[4])
		if key == "" {
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
	return attrs
}

func collectFormFields(formInner string) []formField {
	fields := make([]formField, 0)
	fields = append(fields, collectInputFields(formInner)...)
	fields = append(fields, collectTextareaFields(formInner)...)
	fields = append(fields, collectSelectFields(formInner)...)
	return mergeFormFields(fields)
}

func collectInputFields(formInner string) []formField {
	fields := make([]formField, 0)
	for _, match := range inputPattern.FindAllStringSubmatch(formInner, -1) {
		if len(match) < 2 {
			continue
		}
		rawAttrs := match[1]
		attrs := parseHTMLAttributes(rawAttrs)
		name := strings.TrimSpace(attrs["name"])
		if name == "" {
			continue
		}
		inputType := strings.ToLower(strings.TrimSpace(firstNonEmpty(attrs["type"], "text")))
		fields = append(fields, formField{
			Name:      name,
			FieldType: mapInputFieldType(inputType),
			Required:  hasBooleanHTMLAttr(rawAttrs, "required"),
			Default:   strings.TrimSpace(attrs["value"]),
			Example:   strings.TrimSpace(attrs["value"]),
		})
	}
	return fields
}

func collectTextareaFields(formInner string) []formField {
	fields := make([]formField, 0)
	for _, match := range textareaPattern.FindAllStringSubmatch(formInner, -1) {
		if len(match) < 3 {
			continue
		}
		rawAttrs := match[1]
		attrs := parseHTMLAttributes(rawAttrs)
		name := strings.TrimSpace(attrs["name"])
		if name == "" {
			continue
		}
		value := strings.TrimSpace(stripHTMLTags(match[2]))
		fields = append(fields, formField{
			Name:      name,
			FieldType: "string",
			Required:  hasBooleanHTMLAttr(rawAttrs, "required"),
			Default:   value,
			Example:   value,
		})
	}
	return fields
}

func collectSelectFields(formInner string) []formField {
	fields := make([]formField, 0)
	for _, match := range selectPattern.FindAllStringSubmatch(formInner, -1) {
		if len(match) < 3 {
			continue
		}
		rawAttrs := match[1]
		attrs := parseHTMLAttributes(rawAttrs)
		name := strings.TrimSpace(attrs["name"])
		if name == "" {
			continue
		}
		enumValues := make([]string, 0)
		defaultValue := ""
		for _, optionMatch := range optionPattern.FindAllStringSubmatch(match[2], -1) {
			if len(optionMatch) < 3 {
				continue
			}
			optionAttrsRaw := optionMatch[1]
			optionAttrs := parseHTMLAttributes(optionAttrsRaw)
			optionValue := strings.TrimSpace(firstNonEmpty(optionAttrs["value"], stripHTMLTags(optionMatch[2])))
			if optionValue == "" {
				continue
			}
			enumValues = append(enumValues, optionValue)
			if defaultValue == "" || hasBooleanHTMLAttr(optionAttrsRaw, "selected") {
				defaultValue = optionValue
			}
		}
		fields = append(fields, formField{
			Name:      name,
			FieldType: "string",
			Required:  hasBooleanHTMLAttr(rawAttrs, "required"),
			Default:   defaultValue,
			Example:   defaultValue,
			Enum:      uniqueSortedStrings(enumValues),
		})
	}
	return fields
}

func mergeFormFields(fields []formField) []formField {
	if len(fields) <= 1 {
		return fields
	}
	resultMap := make(map[string]formField)
	order := make([]string, 0)
	for _, field := range fields {
		key := strings.ToLower(strings.TrimSpace(field.Name))
		if key == "" {
			continue
		}
		existing, ok := resultMap[key]
		if !ok {
			resultMap[key] = field
			order = append(order, key)
			continue
		}
		if existing.FieldType == "unknown" && field.FieldType != "unknown" {
			existing.FieldType = field.FieldType
		}
		existing.Required = existing.Required || field.Required
		if existing.Default == "" {
			existing.Default = field.Default
		}
		if existing.Example == "" {
			existing.Example = field.Example
		}
		existing.Enum = uniqueSortedStrings(append(existing.Enum, field.Enum...))
		resultMap[key] = existing
	}

	result := make([]formField, 0, len(order))
	for _, key := range order {
		result = append(result, resultMap[key])
	}
	return result
}

func inferFormContentType(method string, enctype string) (string, string) {
	if strings.ToUpper(strings.TrimSpace(method)) == "GET" {
		return "", "query"
	}

	switch strings.ToLower(strings.TrimSpace(enctype)) {
	case "multipart/form-data":
		return "multipart/form-data", "multipart"
	case "text/plain":
		return "text/plain", "text"
	default:
		return "application/x-www-form-urlencoded", "form_urlencoded"
	}
}

func buildFormRequestTemplate(actionURL *url.URL, method string, fields []formField, contentType string) datatype.EndpointRequestTemplate {
	queryTemplate := make(map[string]string)
	bodyTemplate := make(map[string]string)
	headerTemplate := make(map[string]string)
	bodyPreview := ""
	if strings.ToUpper(strings.TrimSpace(method)) == "GET" {
		for key := range actionURL.Query() {
			queryTemplate[key] = "<value>"
		}
		for _, field := range fields {
			queryTemplate[field.Name] = firstNonEmpty(field.Example, field.Default, "<value>")
		}
	} else {
		if contentType != "" {
			headerTemplate["Content-Type"] = contentType
		}
		for _, field := range fields {
			bodyTemplate[field.Name] = firstNonEmpty(field.Example, field.Default, "<value>")
		}
		switch strings.ToLower(strings.TrimSpace(contentType)) {
		case "multipart/form-data":
			fieldNames := make([]string, 0, len(fields))
			for _, field := range fields {
				fieldNames = append(fieldNames, field.Name)
			}
			bodyPreview = buildMultipartPreview(fieldNames)
		case "text/plain":
			lines := make([]string, 0, len(fields))
			for _, field := range fields {
				lines = append(lines, fmt.Sprintf("%s=%s", field.Name, firstNonEmpty(field.Example, field.Default, "<value>")))
			}
			bodyPreview = strings.Join(lines, "\n")
		}
	}
	return buildRequestTemplate(
		method,
		actionURL,
		bodyKind,
		extractPathParameters(actionURL.Path),
		queryTemplate,
		bodyTemplate,
		headerTemplate,
		bodyPreview,
	)
}

func buildActionQueryParameters(endpointID string, pageURL string, actionURL *url.URL, method string) []datatype.ParameterRecord {
	if actionURL == nil {
		return nil
	}
	queryValues := actionURL.Query()
	if len(queryValues) == 0 {
		return nil
	}

	parameters := make([]datatype.ParameterRecord, 0, len(queryValues))
	for name, values := range queryValues {
		paramName := strings.TrimSpace(name)
		if paramName == "" {
			continue
		}
		example := ""
		if len(values) > 0 {
			example = strings.TrimSpace(values[0])
		}
		paramID := fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
			endpointID,
			"query",
			paramName,
		}, "|")))
		paramRecord := datatype.ParameterRecord{
			ParameterID: paramID,
			EndpointID:  endpointID,
			ParamName:   paramName,
			Location:    "query",
			ParamType:   "string",
			Example:     example,
			Default:     example,
			Source:      "dom_form",
			SourceDetail: datatype.ParameterSourceDetail{
				PageURL: pageURL,
			},
			Confidence:      0.70,
			OccurrenceCount: 1,
		}
		parameters = append(parameters, enrichParameterMetadata(paramRecord))
	}
	return parameters
}

func mergeEndpointRecords(records []datatype.EndpointRecord) []datatype.EndpointRecord {
	if len(records) <= 1 {
		return records
	}
	resultMap := make(map[string]datatype.EndpointRecord)
	order := make([]string, 0)
	for _, record := range records {
		key := strings.TrimSpace(record.EndpointID)
		if key == "" {
			key = fmt.Sprintf("%s|%s|%s", record.Method, record.URL, record.PageURL)
		}
		existing, ok := resultMap[key]
		if !ok {
			resultMap[key] = record
			order = append(order, key)
			continue
		}
		existing.SourceTypes = uniqueSortedStrings(append(existing.SourceTypes, record.SourceTypes...))
		if existing.ContentType == "" {
			existing.ContentType = record.ContentType
		}
		if existing.BodyKind == "" {
			existing.BodyKind = record.BodyKind
		}
		if existing.Path == "" {
			existing.Path = record.Path
		}
		if existing.Protocol == "" {
			existing.Protocol = record.Protocol
		}
		if existing.RequestTemplate.Headers == nil {
			existing.RequestTemplate.Headers = record.RequestTemplate.Headers
		} else {
			for headerName, headerValue := range record.RequestTemplate.Headers {
				if _, exists := existing.RequestTemplate.Headers[headerName]; !exists {
					existing.RequestTemplate.Headers[headerName] = headerValue
				}
			}
		}
		if existing.RequestTemplate.Query == nil {
			existing.RequestTemplate.Query = record.RequestTemplate.Query
		} else {
			for keyName, value := range record.RequestTemplate.Query {
				if _, exists := existing.RequestTemplate.Query[keyName]; !exists {
					existing.RequestTemplate.Query[keyName] = value
				}
			}
		}
		if existing.RequestTemplate.Body == nil {
			existing.RequestTemplate.Body = record.RequestTemplate.Body
		} else {
			for keyName, value := range record.RequestTemplate.Body {
				if _, exists := existing.RequestTemplate.Body[keyName]; !exists {
					existing.RequestTemplate.Body[keyName] = value
				}
			}
		}
		if record.Confidence > existing.Confidence {
			existing.Confidence = record.Confidence
		}
		resultMap[key] = existing
	}

	result := make([]datatype.EndpointRecord, 0, len(order))
	for _, key := range order {
		result = append(result, resultMap[key])
	}
	return result
}

func mergeParameterRecords(records []datatype.ParameterRecord) []datatype.ParameterRecord {
	if len(records) <= 1 {
		return records
	}
	resultMap := make(map[string]datatype.ParameterRecord)
	order := make([]string, 0)
	for _, record := range records {
		key := strings.Join([]string{
			strings.TrimSpace(record.EndpointID),
			strings.ToLower(strings.TrimSpace(record.Location)),
			strings.ToLower(strings.TrimSpace(record.ParamName)),
		}, "|")
		existing, ok := resultMap[key]
		if !ok {
			resultMap[key] = record
			order = append(order, key)
			continue
		}
		existing.Required = existing.Required || record.Required
		if existing.ParamType == "" || existing.ParamType == "unknown" {
			existing.ParamType = record.ParamType
		}
		if existing.Example == "" {
			existing.Example = record.Example
		}
		if existing.Default == "" {
			existing.Default = record.Default
		}
		existing.Enum = uniqueSortedStrings(append(existing.Enum, record.Enum...))
		if record.Confidence > existing.Confidence {
			existing.Confidence = record.Confidence
		}
		existing.OccurrenceCount += record.OccurrenceCount
		resultMap[key] = existing
	}

	result := make([]datatype.ParameterRecord, 0, len(order))
	for _, key := range order {
		result = append(result, resultMap[key])
	}
	return result
}

func resolveSameHostURL(baseURL *url.URL, raw string) (*url.URL, error) {
	if baseURL == nil {
		return nil, fmt.Errorf("base url is nil")
	}
	targetRaw := strings.TrimSpace(raw)
	if targetRaw == "" {
		targetRaw = baseURL.String()
	}

	targetURL, err := url.Parse(targetRaw)
	if err != nil {
		return nil, err
	}
	resolved := baseURL.ResolveReference(targetURL)
	if resolved == nil || resolved.Host == "" {
		return nil, fmt.Errorf("resolved url invalid")
	}
	if !strings.EqualFold(resolved.Hostname(), baseURL.Hostname()) {
		return nil, fmt.Errorf("cross host form action")
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme")
	}
	if resolved.Path == "" {
		resolved.Path = "/"
	}
	resolved.Fragment = ""
	return resolved, nil
}

func mapInputFieldType(inputType string) string {
	switch strings.ToLower(strings.TrimSpace(inputType)) {
	case "number", "range":
		return "number"
	case "checkbox":
		return "boolean"
	case "file":
		return "file"
	case "hidden", "text", "search", "password", "email", "url", "tel", "radio", "date", "datetime-local", "month", "time", "week":
		return "string"
	default:
		return "unknown"
	}
}

func hasBooleanHTMLAttr(raw string, attrName string) bool {
	pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(strings.TrimSpace(attrName)) + `\b`)
	return pattern.MatchString(raw)
}

func stripHTMLTags(raw string) string {
	text := regexp.MustCompile(`(?is)<[^>]+>`).ReplaceAllString(raw, "")
	return strings.TrimSpace(text)
}

func uniqueSortedStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
