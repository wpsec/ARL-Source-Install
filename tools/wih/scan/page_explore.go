package scan

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	datatype "wih/dataType"
)

var (
	anchorHrefPattern = regexp.MustCompile(`(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["']`)
	iframeSrcPattern  = regexp.MustCompile(`(?is)<iframe\b[^>]*src\s*=\s*["']([^"']+)["']`)
)

const staticHTMLExploreMaxPages = 6

type linkedPageSurface struct {
	Records    []datatype.ScanRecord
	Endpoints  []datatype.EndpointRecord
	Parameters []datatype.ParameterRecord
	JSURLs     []string
	PageURLs   []string
}

func scanLinkedHTMLPages(client *http.Client, targetURL string, rootBody string) linkedPageSurface {
	if client == nil || strings.TrimSpace(targetURL) == "" || strings.TrimSpace(rootBody) == "" {
		return linkedPageSurface{}
	}

	pages := crawlStaticHTMLPages(client, targetURL, rootBody)
	if len(pages) == 0 {
		return linkedPageSurface{}
	}

	result := linkedPageSurface{
		Records:    make([]datatype.ScanRecord, 0),
		Endpoints:  make([]datatype.EndpointRecord, 0),
		Parameters: make([]datatype.ParameterRecord, 0),
		JSURLs:     make([]string, 0),
		PageURLs:   make([]string, 0),
	}
	for _, page := range pages {
		result.Records = append(result.Records, filterRecordsByTargetScope(targetURL, rule(page.Body, page.URL, "page"))...)
		endpoints, parameters := extractHTMLFormSurface(page.Body, page.URL)
		result.Endpoints = append(result.Endpoints, endpoints...)
		result.Parameters = append(result.Parameters, parameters...)
		result.JSURLs = append(result.JSURLs, extractJSURLs(page.Body, page.URL)...)
		result.PageURLs = append(result.PageURLs, extractJSPageCandidateURLs(page.Body, page.URL, buildJSVariableHints(page.Body))...)
	}

	result.Records = dedupeRecords(result.Records)
	result.Endpoints = mergeEndpointRecords(result.Endpoints)
	result.Parameters = mergeParameterRecords(result.Parameters)
	result.JSURLs = uniqueSortedText(result.JSURLs)
	result.PageURLs = prioritizePageCandidateURLs(result.PageURLs)
	return result
}

type crawledPage struct {
	URL  string
	Body string
}

func crawlStaticHTMLPages(client *http.Client, targetURL string, rootBody string) []crawledPage {
	targetParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || targetParsed.Host == "" {
		return nil
	}

	queue := extractLinkedPageURLs(rootBody, targetParsed, targetURL)
	if len(queue) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(queue)+1)
	seen[strings.TrimSpace(targetURL)] = struct{}{}
	for _, item := range queue {
		seen[item] = struct{}{}
	}

	result := make([]crawledPage, 0, minInt(len(queue), staticHTMLExploreMaxPages))
	for len(queue) > 0 && len(result) < staticHTMLExploreMaxPages {
		pageURL := queue[0]
		queue = queue[1:]

		body, err := fetchBody(client, pageURL, targetURL)
		if err != nil || strings.TrimSpace(body) == "" {
			continue
		}
		result = append(result, crawledPage{
			URL:  pageURL,
			Body: body,
		})

		for _, nextURL := range extractLinkedPageURLs(body, targetParsed, pageURL) {
			if _, ok := seen[nextURL]; ok {
				continue
			}
			seen[nextURL] = struct{}{}
			queue = append(queue, nextURL)
		}
	}

	return result
}

func extractLinkedPageURLs(pageBody string, targetParsed *url.URL, pageURL string) []string {
	if strings.TrimSpace(pageBody) == "" || targetParsed == nil || targetParsed.Host == "" {
		return nil
	}

	seen := make(map[string]struct{})
	add := func(raw string) {
		normalized := normalizeSameHostPageURL(raw, pageURL, targetParsed)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
	}

	for _, match := range anchorHrefPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(match) < 2 {
			continue
		}
		add(match[1])
	}

	for _, match := range iframeSrcPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(match) < 2 {
			continue
		}
		add(match[1])
	}

	for _, formMatch := range formPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(formMatch) < 2 {
			continue
		}
		formAttrs := parseHTMLAttributes(formMatch[1])
		method := strings.ToUpper(strings.TrimSpace(firstNonEmpty(formAttrs["method"], "GET")))
		if method != "" && method != http.MethodGet {
			continue
		}
		add(formAttrs["action"])
	}

	results := make([]string, 0, len(seen))
	for item := range seen {
		results = append(results, item)
	}
	sort.Strings(results)
	return results
}

func normalizeSameHostPageURL(rawURL string, baseURL string, targetParsed *url.URL) string {
	raw := strings.TrimSpace(rawURL)
	if raw == "" || raw == "#" || strings.HasPrefix(raw, "#") {
		return ""
	}
	lowered := strings.ToLower(raw)
	for _, prefix := range []string{"javascript:", "data:", "mailto:", "tel:"} {
		if strings.HasPrefix(lowered, prefix) {
			return ""
		}
	}

	normalized := normalizeJSURL(raw, baseURL)
	if normalized == "" {
		return ""
	}

	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if !strings.EqualFold(parsed.Host, targetParsed.Host) {
		return ""
	}
	if isStaticHTMLExploreAsset(parsed.Path) {
		return ""
	}
	return parsed.String()
}

func isStaticHTMLExploreAsset(pathText string) bool {
	lowered := strings.ToLower(strings.TrimSpace(pathText))
	if lowered == "" || lowered == "/" {
		return false
	}
	for _, suffix := range []string{
		".js", ".mjs", ".css", ".scss", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
		".vue", ".ts", ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip", ".rar", ".7z",
		".mp3", ".mp4", ".avi", ".mov", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	} {
		if strings.HasSuffix(lowered, suffix) {
			return true
		}
	}
	return false
}

func uniqueSortedText(items []string) []string {
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

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
