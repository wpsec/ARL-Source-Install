package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	datatype "wih/dataType"
)

var (
	zodObjectPattern        = regexp.MustCompile(`(?is)\bz(?:od)?\.object\s*\(`)
	yupObjectPattern        = regexp.MustCompile(`(?is)\b(?:yup|Yup)\.object\s*\(`)
	joiObjectPattern        = regexp.MustCompile(`(?is)\b(?:joi|Joi)\.object\s*\(`)
	jsonSchemaObjectPattern = regexp.MustCompile(`(?is)\bproperties\s*:\s*\{`)
	jsonTypePattern         = regexp.MustCompile(`(?is)\btype\s*:\s*["']([A-Za-z_][\w-]{0,31})["']`)
	jsonDefaultPattern      = regexp.MustCompile(`(?is)\bdefault\s*:\s*("([^"]*)"|'([^']*)'|true|false|-?\d+(?:\.\d+)?)`)
	jsonEnumPattern         = regexp.MustCompile(`(?is)\benum\s*:\s*\[([^\]]{1,500})\]`)
	jsonRequiredPattern     = regexp.MustCompile(`(?is)\brequired\s*:\s*\[([^\]]{1,500})\]`)
	literalStringPattern    = regexp.MustCompile(`["']([^"'\\]{1,120})["']`)
)

type schemaFieldHint struct {
	ParamType   string
	HasRequired bool
	Required    bool
	Default     string
	Enum        []string
	SchemaLib   string
	Confidence  float64
}

func applyJSSchemaHints(parameters []datatype.ParameterRecord, jsBody string) []datatype.ParameterRecord {
	if len(parameters) == 0 || strings.TrimSpace(jsBody) == "" {
		return parameters
	}

	hints := collectJSSchemaHints(jsBody)
	if len(hints) == 0 {
		return parameters
	}

	result := make([]datatype.ParameterRecord, 0, len(parameters))
	for _, parameter := range parameters {
		hint, ok := hints[strings.ToLower(strings.TrimSpace(parameter.ParamName))]
		if !ok {
			result = append(result, parameter)
			continue
		}

		enriched := parameter
		if strings.TrimSpace(hint.ParamType) != "" && shouldPreferSchemaType(enriched.ParamType, hint.ParamType) {
			enriched.ParamType = hint.ParamType
		}
		if hint.HasRequired {
			enriched.Required = hint.Required
		}
		if strings.TrimSpace(enriched.Default) == "" && strings.TrimSpace(hint.Default) != "" {
			enriched.Default = hint.Default
		}
		if strings.TrimSpace(enriched.Example) == "" && strings.TrimSpace(hint.Default) != "" {
			enriched.Example = hint.Default
		}
		if len(hint.Enum) > 0 {
			enriched.Enum = uniqueSortedStrings(append(enriched.Enum, hint.Enum...))
		}
		if strings.TrimSpace(enriched.SourceDetail.SchemaLib) == "" && strings.TrimSpace(hint.SchemaLib) != "" {
			enriched.SourceDetail.SchemaLib = hint.SchemaLib
		}
		if hint.Confidence > enriched.Confidence {
			enriched.Confidence = hint.Confidence
		}
		result = append(result, enrichParameterMetadata(enriched))
	}

	return result
}

func shouldPreferSchemaType(currentType string, schemaType string) bool {
	current := strings.ToLower(strings.TrimSpace(currentType))
	schema := strings.ToLower(strings.TrimSpace(schemaType))
	if schema == "" {
		return false
	}
	if current == "" || current == "unknown" {
		return true
	}
	if current == schema {
		return false
	}
	if current == "string" && schema != "string" {
		return true
	}
	return false
}

func collectJSSchemaHints(jsBody string) map[string]schemaFieldHint {
	hints := make(map[string]schemaFieldHint)
	mergeHints(hints, collectSchemaObjectHints(jsBody, zodObjectPattern, parseZodSchemaFields))
	mergeHints(hints, collectSchemaObjectHints(jsBody, yupObjectPattern, parseYupSchemaFields))
	mergeHints(hints, collectSchemaObjectHints(jsBody, joiObjectPattern, parseJoiSchemaFields))
	mergeHints(hints, collectJSONSchemaHints(jsBody))
	return hints
}

func mergeHints(target map[string]schemaFieldHint, source map[string]schemaFieldHint) {
	for key, hint := range source {
		existing, ok := target[key]
		if !ok {
			target[key] = hint
			continue
		}
		if existing.ParamType == "" {
			existing.ParamType = hint.ParamType
		}
		if !existing.HasRequired && hint.HasRequired {
			existing.HasRequired = true
			existing.Required = hint.Required
		}
		if existing.Default == "" {
			existing.Default = hint.Default
		}
		existing.Enum = uniqueSortedStrings(append(existing.Enum, hint.Enum...))
		if existing.SchemaLib == "" {
			existing.SchemaLib = hint.SchemaLib
		}
		if hint.Confidence > existing.Confidence {
			existing.Confidence = hint.Confidence
		}
		target[key] = existing
	}
}

func collectSchemaObjectHints(jsBody string, pattern *regexp.Regexp, parser func(string) map[string]schemaFieldHint) map[string]schemaFieldHint {
	result := make(map[string]schemaFieldHint)
	if pattern == nil {
		return result
	}

	for _, indexPair := range pattern.FindAllStringIndex(jsBody, -1) {
		if len(indexPair) < 2 {
			continue
		}
		rawObject, ok := extractBalancedObject(jsBody, indexPair[1])
		if !ok || strings.TrimSpace(rawObject) == "" {
			continue
		}
		mergeHints(result, parser(rawObject))
	}
	return result
}

func collectJSONSchemaHints(jsBody string) map[string]schemaFieldHint {
	result := make(map[string]schemaFieldHint)
	for _, indexPair := range jsonSchemaObjectPattern.FindAllStringIndex(jsBody, -1) {
		if len(indexPair) < 2 {
			continue
		}
		propertiesBlock, ok := extractBalancedObject(jsBody, indexPair[1]-1)
		if !ok {
			continue
		}
		requiredNames := make(map[string]struct{})
		if requiredBlock, ok := findSiblingJSONRequiredBlock(jsBody, indexPair[0]); ok {
			for _, name := range extractLiteralList(requiredBlock) {
				requiredNames[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
			}
		}

		for name, fieldExpr := range parseTopLevelObjectFields(propertiesBlock) {
			paramName := strings.TrimSpace(name)
			if paramName == "" {
				continue
			}
			hint := schemaFieldHint{
				ParamType:  normalizeSchemaType(matchFirstGroup(jsonTypePattern, fieldExpr)),
				Default:    extractDefaultValue(fieldExpr),
				Enum:       extractEnumValues(fieldExpr),
				SchemaLib:  "json_schema",
				Confidence: 0.83,
			}
			if _, ok := requiredNames[strings.ToLower(paramName)]; ok {
				hint.HasRequired = true
				hint.Required = true
			}
			result[strings.ToLower(paramName)] = hint
		}
	}
	return result
}

func parseZodSchemaFields(rawObject string) map[string]schemaFieldHint {
	result := make(map[string]schemaFieldHint)
	for name, expr := range parseTopLevelObjectFields(rawObject) {
		loweredExpr := strings.ToLower(expr)
		hint := schemaFieldHint{
			ParamType:  normalizeSchemaType(detectTypedCall(expr, "z")),
			SchemaLib:  "zod",
			Confidence: 0.84,
		}
		if strings.Contains(loweredExpr, ".optional(") || strings.Contains(loweredExpr, ".optional()") || strings.Contains(loweredExpr, ".nullish(") || strings.Contains(loweredExpr, ".nullish()") {
			hint.HasRequired = true
			hint.Required = false
		} else {
			hint.HasRequired = true
			hint.Required = true
		}
		hint.Default = extractDefaultValue(expr)
		hint.Enum = extractEnumValues(expr)
		result[strings.ToLower(strings.TrimSpace(name))] = hint
	}
	return result
}

func parseYupSchemaFields(rawObject string) map[string]schemaFieldHint {
	result := make(map[string]schemaFieldHint)
	for name, expr := range parseTopLevelObjectFields(rawObject) {
		loweredExpr := strings.ToLower(expr)
		hint := schemaFieldHint{
			ParamType:  normalizeSchemaType(detectTypedCall(expr, "yup", "Yup")),
			SchemaLib:  "yup",
			Confidence: 0.82,
		}
		if strings.Contains(loweredExpr, ".required(") || strings.Contains(loweredExpr, ".required()") {
			hint.HasRequired = true
			hint.Required = true
		} else if strings.Contains(loweredExpr, ".optional(") || strings.Contains(loweredExpr, ".optional()") || strings.Contains(loweredExpr, ".notrequired(") || strings.Contains(loweredExpr, ".notrequired()") {
			hint.HasRequired = true
			hint.Required = false
		}
		hint.Default = extractDefaultValue(expr)
		hint.Enum = extractEnumValues(expr)
		result[strings.ToLower(strings.TrimSpace(name))] = hint
	}
	return result
}

func parseJoiSchemaFields(rawObject string) map[string]schemaFieldHint {
	result := make(map[string]schemaFieldHint)
	for name, expr := range parseTopLevelObjectFields(rawObject) {
		loweredExpr := strings.ToLower(expr)
		hint := schemaFieldHint{
			ParamType:  normalizeSchemaType(detectTypedCall(expr, "joi", "Joi")),
			SchemaLib:  "joi",
			Confidence: 0.82,
		}
		if strings.Contains(loweredExpr, ".required(") || strings.Contains(loweredExpr, ".required()") {
			hint.HasRequired = true
			hint.Required = true
		}
		hint.Default = extractDefaultValue(expr)
		hint.Enum = extractEnumValues(expr)
		result[strings.ToLower(strings.TrimSpace(name))] = hint
	}
	return result
}

func parseTopLevelObjectFields(rawObject string) map[string]string {
	text := strings.TrimSpace(rawObject)
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		text = strings.TrimSpace(text[1 : len(text)-1])
	}
	result := make(map[string]string)
	if text == "" {
		return result
	}
	for _, segment := range splitTopLevel(text, ',') {
		part := strings.TrimSpace(segment)
		if part == "" {
			continue
		}
		name, expr, ok := splitObjectField(part)
		if !ok {
			continue
		}
		result[name] = expr
	}
	return result
}

func splitObjectField(raw string) (string, string, bool) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", "", false
	}
	depthBrace := 0
	depthBracket := 0
	depthParen := 0
	inSingle := false
	inDouble := false
	inTemplate := false
	escaped := false

	for index, r := range text {
		if escaped {
			escaped = false
			continue
		}
		switch r {
		case '\\':
			if inSingle || inDouble || inTemplate {
				escaped = true
			}
		case '\'':
			if !inDouble && !inTemplate {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inTemplate {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inTemplate = !inTemplate
			}
		case '{':
			if !inSingle && !inDouble && !inTemplate {
				depthBrace++
			}
		case '}':
			if !inSingle && !inDouble && !inTemplate && depthBrace > 0 {
				depthBrace--
			}
		case '[':
			if !inSingle && !inDouble && !inTemplate {
				depthBracket++
			}
		case ']':
			if !inSingle && !inDouble && !inTemplate && depthBracket > 0 {
				depthBracket--
			}
		case '(':
			if !inSingle && !inDouble && !inTemplate {
				depthParen++
			}
		case ')':
			if !inSingle && !inDouble && !inTemplate && depthParen > 0 {
				depthParen--
			}
		case ':':
			if inSingle || inDouble || inTemplate || depthBrace > 0 || depthBracket > 0 || depthParen > 0 {
				continue
			}
			name := strings.TrimSpace(strings.Trim(text[:index], `"'`))
			expr := strings.TrimSpace(text[index+1:])
			if name == "" || expr == "" {
				return "", "", false
			}
			return name, expr, true
		}
	}

	return "", "", false
}

func splitTopLevel(raw string, delimiter rune) []string {
	result := make([]string, 0)
	start := 0
	depthBrace := 0
	depthBracket := 0
	depthParen := 0
	inSingle := false
	inDouble := false
	inTemplate := false
	escaped := false

	for index, r := range raw {
		if escaped {
			escaped = false
			continue
		}
		switch r {
		case '\\':
			if inSingle || inDouble || inTemplate {
				escaped = true
			}
		case '\'':
			if !inDouble && !inTemplate {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inTemplate {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inTemplate = !inTemplate
			}
		case '{':
			if !inSingle && !inDouble && !inTemplate {
				depthBrace++
			}
		case '}':
			if !inSingle && !inDouble && !inTemplate && depthBrace > 0 {
				depthBrace--
			}
		case '[':
			if !inSingle && !inDouble && !inTemplate {
				depthBracket++
			}
		case ']':
			if !inSingle && !inDouble && !inTemplate && depthBracket > 0 {
				depthBracket--
			}
		case '(':
			if !inSingle && !inDouble && !inTemplate {
				depthParen++
			}
		case ')':
			if !inSingle && !inDouble && !inTemplate && depthParen > 0 {
				depthParen--
			}
		default:
			if r == delimiter && !inSingle && !inDouble && !inTemplate && depthBrace == 0 && depthBracket == 0 && depthParen == 0 {
				result = append(result, raw[start:index])
				start = index + 1
			}
		}
	}
	result = append(result, raw[start:])
	return result
}

func extractBalancedObject(source string, searchStart int) (string, bool) {
	if searchStart < 0 {
		searchStart = 0
	}
	openIndex := strings.Index(source[searchStart:], "{")
	if openIndex < 0 {
		return "", false
	}
	openIndex += searchStart
	depth := 0
	inSingle := false
	inDouble := false
	inTemplate := false
	escaped := false

	for index := openIndex; index < len(source); index++ {
		ch := source[index]
		if escaped {
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			if inSingle || inDouble || inTemplate {
				escaped = true
			}
		case '\'':
			if !inDouble && !inTemplate {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inTemplate {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inTemplate = !inTemplate
			}
		case '{':
			if !inSingle && !inDouble && !inTemplate {
				depth++
			}
		case '}':
			if !inSingle && !inDouble && !inTemplate {
				depth--
				if depth == 0 {
					return source[openIndex : index+1], true
				}
			}
		}
	}

	return "", false
}

func findSiblingJSONRequiredBlock(jsBody string, propertiesIndex int) (string, bool) {
	requiredMatch := jsonRequiredPattern.FindStringSubmatch(jsBody[propertiesIndex:])
	if len(requiredMatch) < 2 {
		return "", false
	}
	return strings.TrimSpace(requiredMatch[1]), true
}

func detectTypedCall(expr string, prefixes ...string) string {
	loweredExpr := strings.ToLower(expr)
	typeCandidates := []string{"string", "number", "boolean", "array", "object", "file"}
	for _, candidate := range typeCandidates {
		for _, prefix := range prefixes {
			pattern := fmt.Sprintf("%s.%s(", strings.ToLower(strings.TrimSpace(prefix)), candidate)
			if strings.Contains(loweredExpr, pattern) {
				return candidate
			}
		}
	}
	if strings.Contains(loweredExpr, ".enum(") || strings.Contains(loweredExpr, ".oneof(") || strings.Contains(loweredExpr, ".valid(") {
		return "string"
	}
	return ""
}

func extractDefaultValue(expr string) string {
	match := jsonDefaultPattern.FindStringSubmatch(expr)
	if len(match) >= 2 {
		return strings.TrimSpace(strings.Trim(match[1], `"'`))
	}

	loweredExpr := strings.ToLower(expr)
	start := strings.Index(loweredExpr, ".default(")
	if start < 0 {
		return ""
	}
	block, ok := extractBalancedParenContent(expr[start+len(".default"):])
	if !ok {
		return ""
	}
	values := extractLiteralList(block)
	if len(values) > 0 {
		return values[0]
	}
	text := strings.TrimSpace(strings.Trim(block, `"'`))
	if regexp.MustCompile(`^(true|false|-?\d+(?:\.\d+)?)$`).MatchString(text) {
		return text
	}
	return ""
}

func extractEnumValues(expr string) []string {
	match := jsonEnumPattern.FindStringSubmatch(expr)
	if len(match) >= 2 {
		return uniqueSortedStrings(extractLiteralList(match[1]))
	}

	loweredExpr := strings.ToLower(expr)
	for _, marker := range []string{".enum(", ".oneof(", ".valid("} {
		start := strings.Index(loweredExpr, marker)
		if start < 0 {
			continue
		}
		raw := expr[start+len(marker)-1:]
		block, ok := extractBalancedParenContent(raw)
		if !ok {
			continue
		}
		return uniqueSortedStrings(extractLiteralList(block))
	}
	return nil
}

func extractBalancedParenContent(source string) (string, bool) {
	openIndex := strings.Index(source, "(")
	if openIndex < 0 {
		openIndex = 0
	}
	depth := 0
	inSingle := false
	inDouble := false
	inTemplate := false
	escaped := false

	for index := openIndex; index < len(source); index++ {
		ch := source[index]
		if escaped {
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			if inSingle || inDouble || inTemplate {
				escaped = true
			}
		case '\'':
			if !inDouble && !inTemplate {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inTemplate {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inTemplate = !inTemplate
			}
		case '(':
			if !inSingle && !inDouble && !inTemplate {
				depth++
			}
		case ')':
			if !inSingle && !inDouble && !inTemplate {
				depth--
				if depth == 0 {
					return source[openIndex+1 : index], true
				}
			}
		}
	}

	return "", false
}

func extractLiteralList(raw string) []string {
	result := make([]string, 0)
	for _, match := range literalStringPattern.FindAllStringSubmatch(raw, -1) {
		if len(match) < 2 {
			continue
		}
		result = append(result, strings.TrimSpace(match[1]))
	}
	for _, token := range splitTopLevel(raw, ',') {
		value := strings.TrimSpace(strings.Trim(token, `"'`))
		if value == "" {
			continue
		}
		if regexp.MustCompile(`^(true|false|-?\d+(?:\.\d+)?)$`).MatchString(value) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return uniqueSortedStrings(result)
}

func normalizeSchemaType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "str", "string", "text":
		return "string"
	case "number", "int", "integer", "float", "double":
		return "number"
	case "bool", "boolean":
		return "boolean"
	case "object", "record":
		return "object"
	case "array", "list":
		return "array"
	case "file", "blob":
		return "file"
	default:
		return ""
	}
}

func matchFirstGroup(pattern *regexp.Regexp, source string) string {
	if pattern == nil {
		return ""
	}
	match := pattern.FindStringSubmatch(source)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}
