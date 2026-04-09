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
	dynamicJSImportPattern = regexp.MustCompile("(?is)import\\s*\\(\\s*(?:\"([^\"]+\\.js(?:\\?[^\"\\s]*)?)\"|'([^']+\\.js(?:\\?[^'\\s]*)?)'|`([^`]+\\.js(?:\\?[^`\\s]*)?)`|([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*))")
	chunkJSStringPattern   = regexp.MustCompile("(?is)(?:\"([^\"]{1,300}\\.js(?:\\?[^\"\\s]*)?)\"|'([^']{1,300}\\.js(?:\\?[^'\\s]*)?)'|`([^`]{1,300}\\.js(?:\\?[^`\\s]*)?)`)")

	routePathPattern       = regexp.MustCompile("(?is)\\bpath\\s*:\\s*(?:\"([^\"]{1,300})\"|'([^']{1,300})'|`([^`]{1,300})`|([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*))")
	locationHrefPattern    = regexp.MustCompile("(?is)\\blocation\\.href\\s*=\\s*(?:\"([^\"]{1,300})\"|'([^']{1,300})'|`([^`]{1,300})`|([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*))")
	frameworkStatePattern  = regexp.MustCompile("(?is)(?:[\"']?(?:pathname|fullPath|page|route|routePath|redirect(?:Path|Url|URI)?|login(?:Path|Url)?|admin(?:Path|Url)?|entry(?:Path|Url)?)[\"']?)\\s*[:=]\\s*(?:\"([^\"]{1,300})\"|'([^']{1,300})'|`([^`]{1,300})`|([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*))")
	numericPathSegmentExpr = regexp.MustCompile(`^\d+(?:\.\d+)?$`)
	pageNavigationPatterns = []*regexp.Regexp{
		regexp.MustCompile("(?is)\\b(?:router\\.(?:push|replace)|location\\.(?:assign|replace)|window\\.open)\\s*\\(\\s*(?:\"([^\"]{1,300})\"|'([^']{1,300})'|`([^`]{1,300})`|([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*))"),
	}
)

func extractJSImportChunkURLs(jsBody string, jsURL string, variableHints jsVariableHints) []string {
	if strings.TrimSpace(jsBody) == "" || strings.TrimSpace(jsURL) == "" {
		return nil
	}

	results := make([]string, 0)
	for _, match := range dynamicJSImportPattern.FindAllStringSubmatch(jsBody, -1) {
		rawURL := firstNonEmpty(matchValue(match, 1), matchValue(match, 2), matchValue(match, 3), matchValue(match, 4))
		resolvedURL, err := normalizeJSImportURL(jsURL, rawURL, variableHints.StringValues, variableHints.MemberStrings)
		if err == nil && strings.TrimSpace(resolvedURL) != "" {
			results = append(results, resolvedURL)
		}
	}

	for _, match := range chunkJSStringPattern.FindAllStringSubmatch(jsBody, -1) {
		rawURL := firstNonEmpty(matchValue(match, 1), matchValue(match, 2), matchValue(match, 3))
		resolvedURL, err := normalizeJSImportURL(jsURL, rawURL, variableHints.StringValues, variableHints.MemberStrings)
		if err == nil && strings.TrimSpace(resolvedURL) != "" {
			results = append(results, resolvedURL)
		}
	}

	return uniqueSortedStrings(results)
}

func extractJSPageCandidateURLs(jsBody string, jsURL string, variableHints jsVariableHints) []string {
	if strings.TrimSpace(jsBody) == "" || strings.TrimSpace(jsURL) == "" {
		return nil
	}

	results := make([]string, 0)
	for _, match := range routePathPattern.FindAllStringSubmatch(jsBody, -1) {
		rawPath := firstNonEmpty(matchValue(match, 1), matchValue(match, 2), matchValue(match, 3), matchValue(match, 4))
		for _, candidate := range expandRoutePathCandidates(rawPath, variableHints.StringValues, variableHints.MemberStrings) {
			pageURL, err := normalizeStaticPageURL(jsURL, candidate, false, variableHints.StringValues, variableHints.MemberStrings)
			if err == nil && strings.TrimSpace(pageURL) != "" {
				results = append(results, pageURL)
			}
		}
	}

	for _, pattern := range pageNavigationPatterns {
		for _, match := range pattern.FindAllStringSubmatch(jsBody, -1) {
			rawURL := firstNonEmpty(matchValue(match, 1), matchValue(match, 2), matchValue(match, 3), matchValue(match, 4))
			pageURL, err := normalizeStaticPageURL(jsURL, rawURL, true, variableHints.StringValues, variableHints.MemberStrings)
			if err == nil && strings.TrimSpace(pageURL) != "" {
				results = append(results, pageURL)
			}
		}
	}

	for _, match := range locationHrefPattern.FindAllStringSubmatch(jsBody, -1) {
		rawURL := firstNonEmpty(matchValue(match, 1), matchValue(match, 2), matchValue(match, 3), matchValue(match, 4))
		pageURL, err := normalizeStaticPageURL(jsURL, rawURL, true, variableHints.StringValues, variableHints.MemberStrings)
		if err == nil && strings.TrimSpace(pageURL) != "" {
			results = append(results, pageURL)
		}
	}

	for _, match := range frameworkStatePattern.FindAllStringSubmatch(jsBody, -1) {
		rawURL := firstNonEmpty(matchValue(match, 1), matchValue(match, 2), matchValue(match, 3), matchValue(match, 4))
		pageURL, err := normalizeStaticPageURL(jsURL, rawURL, true, variableHints.StringValues, variableHints.MemberStrings)
		if err == nil && strings.TrimSpace(pageURL) != "" {
			results = append(results, pageURL)
		}
	}

	return prioritizePageCandidateURLs(results)
}

func buildJSPageCandidatePathRecords(targetURL string, pageURLs []string) []datatype.ScanRecord {
	targetParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || targetParsed.Host == "" {
		return nil
	}

	seen := make(map[string]struct{})
	results := make([]datatype.ScanRecord, 0)
	for _, pageURL := range pageURLs {
		parsed, parseErr := url.Parse(strings.TrimSpace(pageURL))
		if parseErr != nil || parsed.Host == "" {
			continue
		}
		if !strings.EqualFold(parsed.Hostname(), targetParsed.Hostname()) {
			continue
		}
		if strings.TrimSpace(parsed.RawQuery) != "" {
			continue
		}
		pathToken := normalizePathToken(parsed.Path)
		if fragmentPath := normalizeHashRoutePath(parsed.Fragment); fragmentPath != "" {
			pathToken = normalizePathToken(fragmentPath)
		}
		if pathToken == "" {
			continue
		}
		if _, ok := seen[pathToken]; ok {
			continue
		}
		seen[pathToken] = struct{}{}
		results = append(results, datatype.ScanRecord{
			Id:      "path",
			Content: pathToken,
			Source:  targetURL,
			Tag:     "js_route_candidate",
			Hash:    util.StableHash(fmt.Sprintf("js_route|%s|%s", targetURL, pathToken)),
		})
	}
	return results
}

func normalizeJSImportURL(baseJSURL string, rawURL string, stringValues map[string]string, memberStrings map[string]string) (string, error) {
	expr := strings.TrimSpace(rawURL)
	if expr == "" {
		return "", fmt.Errorf("empty js chunk url")
	}
	if value, ok := resolveStringReferenceWithMembers(expr, stringValues, memberStrings); ok {
		expr = value
	}
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", fmt.Errorf("empty resolved js chunk url")
	}

	baseParsed, err := url.Parse(strings.TrimSpace(baseJSURL))
	if err != nil || baseParsed.Host == "" {
		return "", fmt.Errorf("invalid base js url")
	}

	loweredExpr := strings.ToLower(expr)
	for _, prefix := range []string{"assets/", "static/", "dist/"} {
		if strings.HasPrefix(loweredExpr, prefix) {
			expr = "/" + strings.TrimLeft(expr, "/")
			break
		}
	}

	resolvedURL := normalizeJSURL(expr, baseJSURL)
	if strings.TrimSpace(resolvedURL) == "" {
		return "", fmt.Errorf("invalid resolved js chunk url")
	}
	resolvedParsed, err := url.Parse(resolvedURL)
	if err != nil || resolvedParsed.Host == "" {
		return "", fmt.Errorf("invalid resolved js chunk url")
	}
	if !strings.EqualFold(resolvedParsed.Hostname(), baseParsed.Hostname()) {
		return "", fmt.Errorf("cross host js chunk")
	}
	loweredPath := strings.ToLower(strings.TrimSpace(resolvedParsed.Path))
	if !strings.HasSuffix(loweredPath, ".js") && !strings.HasSuffix(loweredPath, ".mjs") && !strings.HasSuffix(loweredPath, ".cjs") {
		return "", fmt.Errorf("non js chunk path")
	}
	if strings.HasSuffix(loweredPath, ".map") {
		return "", fmt.Errorf("source map path")
	}
	resolvedParsed.Fragment = ""
	return resolvedParsed.String(), nil
}

func normalizeStaticPageURL(baseJSURL string, rawURL string, allowQuery bool, stringValues map[string]string, memberStrings map[string]string) (string, error) {
	expr := strings.TrimSpace(rawURL)
	if expr == "" {
		return "", fmt.Errorf("empty page url")
	}
	if value, ok := resolveStringReferenceWithMembers(expr, stringValues, memberStrings); ok {
		expr = value
	}
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", fmt.Errorf("empty resolved page url")
	}

	loweredExpr := strings.ToLower(expr)
	for _, prefix := range []string{"javascript:", "data:", "mailto:", "tel:"} {
		if strings.HasPrefix(loweredExpr, prefix) {
			return "", fmt.Errorf("unsupported page scheme")
		}
	}

	baseParsed, err := url.Parse(strings.TrimSpace(baseJSURL))
	if err != nil || baseParsed.Host == "" {
		return "", fmt.Errorf("invalid base js url")
	}

	if !strings.Contains(expr, "://") &&
		!strings.HasPrefix(expr, "/") &&
		!strings.HasPrefix(expr, "./") &&
		!strings.HasPrefix(expr, "../") &&
		!strings.HasPrefix(expr, "#") {
		expr = "/" + strings.TrimLeft(expr, "/")
	}

	parsed, err := url.Parse(expr)
	if err != nil {
		return "", err
	}
	resolved := baseParsed.ResolveReference(parsed)
	if resolved == nil || resolved.Host == "" {
		return "", fmt.Errorf("invalid resolved page url")
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("unsupported page scheme")
	}
	if !strings.EqualFold(resolved.Hostname(), baseParsed.Hostname()) {
		return "", fmt.Errorf("cross host page url")
	}

	effectivePath := firstNonEmpty(strings.TrimSpace(resolved.Path), "/")
	if fragmentPath := normalizeHashRoutePath(resolved.Fragment); fragmentPath != "" {
		effectivePath = fragmentPath
	} else {
		resolved.Fragment = ""
	}

	if !isLikelyMeaningfulPagePath(effectivePath) {
		return "", fmt.Errorf("noisy page path")
	}
	if !allowQuery {
		resolved.RawQuery = ""
	}
	return resolved.String(), nil
}

func normalizeHashRoutePath(fragment string) string {
	text := strings.TrimSpace(fragment)
	if text == "" {
		return ""
	}
	if strings.HasPrefix(text, "!/") {
		return "/" + strings.TrimLeft(strings.TrimPrefix(text, "!"), "/")
	}
	if strings.HasPrefix(text, "/") {
		return "/" + strings.TrimLeft(text, "/")
	}
	return ""
}

func expandRoutePathCandidates(rawPath string, stringValues map[string]string, memberStrings map[string]string) []string {
	expr := strings.TrimSpace(rawPath)
	if expr == "" {
		return nil
	}
	if value, ok := resolveStringReferenceWithMembers(expr, stringValues, memberStrings); ok {
		expr = value
	}
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	if strings.Contains(expr, "://") || strings.HasPrefix(expr, "./") || strings.HasPrefix(expr, "../") || strings.HasPrefix(expr, "#") {
		return []string{expr}
	}
	if strings.Contains(expr, "?") && !strings.Contains(expr, ":") {
		return []string{expr}
	}

	pathText := expr
	if !strings.HasPrefix(pathText, "/") {
		pathText = "/" + strings.TrimLeft(pathText, "/")
	}

	segments := strings.Split(pathText, "/")
	resolvedSegments := make([]string, 0, len(segments))
	for _, rawSegment := range segments {
		segment := strings.TrimSpace(rawSegment)
		if segment == "" {
			continue
		}
		if strings.ContainsAny(segment, "{}[]*+") || strings.Contains(segment, "(") || strings.Contains(segment, ")") {
			return nil
		}
		if strings.HasPrefix(segment, ":") {
			if strings.HasSuffix(segment, "?") {
				continue
			}
			return nil
		}
		resolvedSegments = append(resolvedSegments, segment)
	}

	if len(resolvedSegments) == 0 {
		return nil
	}
	return []string{"/" + strings.Join(resolvedSegments, "/")}
}

func isLikelyMeaningfulPagePath(pathText string) bool {
	text := strings.TrimSpace(pathText)
	if text == "" || text == "/" {
		return false
	}
	if strings.ContainsAny(text, "\"'`()[]{}|=*") || strings.Contains(text, "${") {
		return false
	}

	lowered := strings.ToLower(text)
	for _, suffix := range []string{".js", ".mjs", ".css", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".json", ".xml", ".txt", ".pdf"} {
		if strings.HasSuffix(lowered, suffix) {
			return false
		}
	}
	for _, prefix := range []string{"/api", "/graphql", "/rest", "/swagger", "/openapi", "/assets/", "/static/", "/dist/"} {
		if strings.HasPrefix(lowered, prefix) {
			return false
		}
	}

	segments := splitPathSegments(text)
	if len(segments) == 0 {
		return false
	}
	for _, segment := range segments {
		if len(segment) < 2 {
			return false
		}
		if numericPathSegmentExpr.MatchString(segment) {
			return false
		}
	}
	if strings.Contains(lowered, "/login") ||
		strings.Contains(lowered, "/admin") ||
		strings.Contains(lowered, "/auth") ||
		strings.Contains(lowered, "/account") ||
		strings.Contains(lowered, "/portal") ||
		strings.Contains(lowered, "/dashboard") ||
		strings.Contains(lowered, "/home") {
		return true
	}
	return len(segments) >= 1
}

func prioritizePageCandidateURLs(items []string) []string {
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

	sort.SliceStable(result, func(i, j int) bool {
		leftScore := pageCandidatePriority(result[i])
		rightScore := pageCandidatePriority(result[j])
		if leftScore != rightScore {
			return leftScore < rightScore
		}
		return result[i] < result[j]
	})
	return result
}

func pageCandidatePriority(pageURL string) int {
	parsed, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil {
		return 100
	}
	pathText := strings.TrimSpace(parsed.Path)
	if fragmentPath := normalizeHashRoutePath(parsed.Fragment); fragmentPath != "" {
		pathText = fragmentPath
	}
	lowered := strings.ToLower(strings.TrimSpace(pathText))
	switch {
	case strings.Contains(lowered, "login"), strings.Contains(lowered, "signin"), strings.Contains(lowered, "auth"):
		return 0
	case strings.Contains(lowered, "admin"), strings.Contains(lowered, "account"), strings.Contains(lowered, "portal"):
		return 1
	case strings.Contains(lowered, "dashboard"), strings.Contains(lowered, "manage"), strings.Contains(lowered, "home"), strings.Contains(lowered, "index"):
		return 2
	default:
		return 10
	}
}
