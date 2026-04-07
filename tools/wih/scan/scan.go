package scan

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	datatype "wih/dataType"
	"wih/global"
	"wih/util"

	"golang.org/x/net/publicsuffix"
)

var (
	jsSrcPattern             = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']`)
	jsAbsPattern             = regexp.MustCompile(`(?i)https?://[^\s"'<>]+\.js(?:\?[^\s"'<>]*)?`)
	routeMethodSuffixPattern = regexp.MustCompile(`(?i)\|(get|post|put|delete|patch|options|head|connect|trace)$`)
	titlePattern             = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

const (
	// pathProbeMaxCandidates 控制单站点 path 拼接探测的最大候选 URL 数量。
	pathProbeMaxCandidates = 120
	// pathProbeConcurrency 控制 path 探测并发，避免对站点造成突刺压力。
	pathProbeConcurrency = 4
	// pathProbeTimeout 控制 path 探测请求超时，避免慢站点阻塞主流程。
	pathProbeTimeout = 8 * time.Second
	// pathProbeDrainBytes 限制每个探测请求的响应读取字节数，仅用于连接复用排空。
	pathProbeDrainBytes = 2048
	// pathProbeBodyReadBytes 限制每个探测请求用于标题提取的正文读取字节数。
	pathProbeBodyReadBytes = 64 * 1024
)

var (
	pathProbeNoiseSingleSegments = map[string]struct{}{
		"head":   {},
		"body":   {},
		"html":   {},
		"script": {},
		"style":  {},
		"meta":   {},
		"link":   {},
		"title":  {},
	}
	pathProbeStaticSuffixes = []string{
		".js",
		".mjs",
		".css",
		".scss",
		".jpg",
		".jpeg",
		".png",
		".gif",
		".ico",
		".svg",
		".vue",
		".ts",
		".woff",
		".woff2",
		".ttf",
		".map",
	}
)

// pathProbeCandidate 表示一条待探测 URL 候选。
type pathProbeCandidate struct {
	URL    string
	Source string
}

type jsSurfaceScanResult struct {
	Records    []datatype.ScanRecord
	Endpoints  []datatype.EndpointRecord
	Parameters []datatype.ParameterRecord
}

type targetScope struct {
	Host              string
	RegistrableDomain string
}

// Scan 扫描单个站点：页面正文 + JS 资源。
func Scan(targetURL string) *datatype.ScanResult {
	targetURL = normalizeTargetURL(targetURL)
	if targetURL == "" {
		return nil
	}

	client := util.NewClient()
	pageBody, err := fetchBody(client, targetURL, targetURL)
	if err != nil {
		util.ErrPrint(err)
		return nil
	}

	records := filterRecordsByTargetScope(targetURL, rule(pageBody, targetURL, "page"))
	endpoints, parameters := extractHTMLFormSurface(pageBody, targetURL)
	if len(records) >= global.MaxCollect {
		return &datatype.ScanResult{
			Target:     targetURL,
			Records:    records[:global.MaxCollect],
			Endpoints:  endpoints,
			Parameters: parameters,
		}
	}

	jsURLs := extractJSURLs(pageBody, targetURL)
	linkedPageSurface := scanLinkedHTMLPages(client, targetURL, pageBody)
	records = append(records, linkedPageSurface.Records...)
	endpoints = mergeEndpointRecords(append(endpoints, linkedPageSurface.Endpoints...))
	parameters = mergeParameterRecords(append(parameters, linkedPageSurface.Parameters...))
	jsURLs = append(jsURLs, linkedPageSurface.JSURLs...)
	jsURLs = uniqueSortedText(jsURLs)
	if global.MaxJSFiles > 0 && len(jsURLs) > global.MaxJSFiles {
		jsURLs = jsURLs[:global.MaxJSFiles]
	}

	jsSurface := scanJSResources(client, targetURL, jsURLs)
	records = append(records, filterRecordsByTargetScope(targetURL, jsSurface.Records)...)
	records = dedupeRecords(records)
	endpoints = mergeEndpointRecords(append(endpoints, jsSurface.Endpoints...))
	parameters = mergeParameterRecords(append(parameters, jsSurface.Parameters...))

	runtimeSurface := extractRuntimeSurface(targetURL)
	endpoints = mergeEndpointRecords(append(endpoints, runtimeSurface.Endpoints...))
	parameters = mergeParameterRecords(append(parameters, runtimeSurface.Parameters...))

	// 对 path 命中做“根路径 + 当前目录”双策略拼接探测。
	if len(records) < global.MaxCollect {
		pathProbeRecords := probePathRecords(client, targetURL, records)
		records = append(records, pathProbeRecords...)
		records = dedupeRecords(records)
		records = collapseProbedPathRecords(targetURL, records)
	}

	if len(records) > global.MaxCollect {
		records = records[:global.MaxCollect]
	}

	return &datatype.ScanResult{
		Target:     targetURL,
		Records:    records,
		Endpoints:  endpoints,
		Parameters: parameters,
	}
}

// fetchBody 抓取目标内容，并应用响应大小限制。
func fetchBody(client *http.Client, requestURL string, scanTargetURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", err
	}
	util.ApplyRequestHeadersForTarget(req, scanTargetURL)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	reader := io.LimitReader(resp.Body, global.LimitReaderSize)
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

// scanJSResources 并发抓取并扫描 JS 文件。
func scanJSResources(client *http.Client, scanTargetURL string, jsURLs []string) jsSurfaceScanResult {
	if len(jsURLs) == 0 {
		return jsSurfaceScanResult{}
	}

	workerCount := global.ConcurrencyPerSite
	if workerCount < 1 {
		workerCount = 1
	}

	jobs := make(chan string)
	results := make(chan jsSurfaceScanResult, len(jsURLs))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jsURL := range jobs {
				jsBody, err := fetchBody(client, jsURL, scanTargetURL)
				if err != nil {
					util.ErrPrint(err)
					continue
				}
				scanUnits := []jsScanUnit{
					{
						URL:             jsURL,
						Body:            jsBody,
						SourceType:      "static_js",
						ParameterSource: "static_js",
						RuleSourceTag:   "js",
					},
				}
				scanUnits = append(scanUnits, fetchSourceMapScanUnits(client, scanTargetURL, jsURL, jsBody)...)
				scanUnits = dedupeJSScanUnits(scanUnits)

				batchResult := jsSurfaceScanResult{
					Records:    make([]datatype.ScanRecord, 0),
					Endpoints:  make([]datatype.EndpointRecord, 0),
					Parameters: make([]datatype.ParameterRecord, 0),
				}
				for _, unit := range scanUnits {
					endpoints, parameters := extractJSStaticSurfaceWithMeta(unit.Body, unit.URL, unit.SourceType, unit.ParameterSource)
					batchResult.Records = append(batchResult.Records, sanitizeRuleRecords(rule(unit.Body, unit.URL, unit.RuleSourceTag), unit.RuleSourceTag)...)
					batchResult.Endpoints = append(batchResult.Endpoints, endpoints...)
					batchResult.Parameters = append(batchResult.Parameters, parameters...)
				}
				results <- batchResult
			}
		}()
	}

	go func() {
		for _, jsURL := range jsURLs {
			jobs <- jsURL
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	merged := jsSurfaceScanResult{
		Records:    make([]datatype.ScanRecord, 0),
		Endpoints:  make([]datatype.EndpointRecord, 0),
		Parameters: make([]datatype.ParameterRecord, 0),
	}
	for batch := range results {
		if len(batch.Records) == 0 && len(batch.Endpoints) == 0 && len(batch.Parameters) == 0 {
			continue
		}
		merged.Records = append(merged.Records, batch.Records...)
		merged.Endpoints = append(merged.Endpoints, batch.Endpoints...)
		merged.Parameters = append(merged.Parameters, batch.Parameters...)
	}

	if len(merged.Records) > global.MaxCollect {
		merged.Records = merged.Records[:global.MaxCollect]
	}
	merged.Records = dedupeRecords(merged.Records)
	merged.Endpoints = mergeEndpointRecords(merged.Endpoints)
	merged.Parameters = mergeParameterRecords(merged.Parameters)
	return merged
}

// probePathRecords 对 path 记录做智能拼接探测并返回新增 URL 记录。
func probePathRecords(client *http.Client, targetURL string, records []datatype.ScanRecord) []datatype.ScanRecord {
	candidates := buildPathProbeCandidates(targetURL, records)
	if len(candidates) == 0 {
		return nil
	}

	probeClient := *client
	if probeClient.Timeout <= 0 || probeClient.Timeout > pathProbeTimeout {
		probeClient.Timeout = pathProbeTimeout
	}

	workerCount := pathProbeConcurrency
	if workerCount < 1 {
		workerCount = 1
	}
	if len(candidates) < workerCount {
		workerCount = len(candidates)
	}

	jobs := make(chan pathProbeCandidate)
	results := make(chan datatype.ScanRecord, len(candidates))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				record := probeSinglePathCandidate(&probeClient, targetURL, candidate)
				if record == nil {
					continue
				}
				results <- *record
			}
		}()
	}

	go func() {
		for _, candidate := range candidates {
			jobs <- candidate
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	merged := make([]datatype.ScanRecord, 0, len(candidates))
	for record := range results {
		merged = append(merged, record)
	}
	return merged
}

// probeSinglePathCandidate 探测单个 path 拼接 URL，命中后返回 path_url 记录。
func probeSinglePathCandidate(client *http.Client, scanTargetURL string, candidate pathProbeCandidate) *datatype.ScanRecord {
	req, err := http.NewRequest(http.MethodGet, candidate.URL, nil)
	if err != nil {
		return nil
	}
	util.ApplyRequestHeadersForTarget(req, scanTargetURL)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, pathProbeBodyReadBytes))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, pathProbeDrainBytes))

	if !isPathProbeStatusUseful(resp.StatusCode) {
		return nil
	}

	tagParts := []string{fmt.Sprintf("path_probe status=%d", resp.StatusCode)}
	if titleText := extractHTMLTitle(bodyBytes); titleText != "" {
		tagParts = append(tagParts, "title="+titleText)
	}
	sizeValue := resp.ContentLength
	if sizeValue < 0 {
		sizeValue = int64(len(bodyBytes))
	}
	if sizeValue >= 0 {
		tagParts = append(tagParts, fmt.Sprintf("size=%d", sizeValue))
	}

	hashText := "path_url|" + candidate.URL
	return &datatype.ScanRecord{
		Id:      "path_url",
		Content: candidate.URL,
		Source:  candidate.Source,
		Tag:     strings.Join(tagParts, " "),
		Hash:    util.StableHash(hashText),
	}
}

// isPathProbeStatusUseful 判断探测结果是否可认为“路径存在或有价值”。
func isPathProbeStatusUseful(statusCode int) bool {
	if statusCode >= 200 && statusCode < 400 {
		return true
	}
	switch statusCode {
	case 401, 403, 405:
		return true
	default:
		return false
	}
}

// buildPathProbeCandidates 从 path 记录构造探测候选 URL：
// 1) 根路径拼接（host + /path）
// 2) 当前目录拼接（source 所在目录 + path）
func buildPathProbeCandidates(targetURL string, records []datatype.ScanRecord) []pathProbeCandidate {
	targetParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || targetParsed.Host == "" {
		return nil
	}

	seen := make(map[string]pathProbeCandidate)
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.Id), "path") {
			continue
		}

		pathToken := normalizePathToken(record.Content)
		if pathToken == "" {
			continue
		}

		candidateURLs := buildCandidateURLsByPath(
			targetParsed,
			strings.TrimSpace(record.Source),
			pathToken,
		)
		for _, candidateURL := range candidateURLs {
			if _, ok := seen[candidateURL]; ok {
				continue
			}
			seen[candidateURL] = pathProbeCandidate{
				URL:    candidateURL,
				Source: strings.TrimSpace(record.Source),
			}
			if len(seen) >= pathProbeMaxCandidates {
				return sortedPathProbeCandidates(seen)
			}
		}
	}

	return sortedPathProbeCandidates(seen)
}

func collapseProbedPathRecords(targetURL string, records []datatype.ScanRecord) []datatype.ScanRecord {
	if len(records) == 0 {
		return nil
	}
	targetParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || targetParsed.Host == "" {
		return records
	}

	probedURLSet := make(map[string]struct{})
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.Id), "path_url") {
			continue
		}
		probedURLSet[strings.TrimSpace(record.Content)] = struct{}{}
	}
	if len(probedURLSet) == 0 {
		return records
	}

	result := make([]datatype.ScanRecord, 0, len(records))
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.Id), "path") {
			result = append(result, record)
			continue
		}
		pathToken := normalizePathToken(record.Content)
		if pathToken == "" {
			result = append(result, record)
			continue
		}
		candidates := buildCandidateURLsByPath(targetParsed, strings.TrimSpace(record.Source), pathToken)
		matched := false
		for _, candidateURL := range candidates {
			if _, ok := probedURLSet[candidateURL]; ok {
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		result = append(result, record)
	}
	return result
}

func sanitizeRuleRecords(records []datatype.ScanRecord, sourceTag string) []datatype.ScanRecord {
	if len(records) == 0 {
		return nil
	}

	result := make([]datatype.ScanRecord, 0, len(records))
	for _, record := range records {
		if shouldDropRuleRecord(record, sourceTag) {
			continue
		}
		result = append(result, record)
	}
	return result
}

func shouldDropRuleRecord(record datatype.ScanRecord, sourceTag string) bool {
	idText := strings.ToLower(strings.TrimSpace(record.Id))
	contentText := strings.TrimSpace(record.Content)
	if contentText == "" {
		return true
	}

	if strings.EqualFold(sourceTag, "js") || strings.EqualFold(sourceTag, "js_source_map") {
		switch idText {
		case "ip", "internal_ip":
			return true
		case "path":
			return !isLikelyMeaningfulJSPath(contentText)
		case "domain":
			return !isLikelyMeaningfulJSDomain(contentText)
		case "domain_url", "ip_url", "url_as_value":
			return !isLikelyMeaningfulJSURL(contentText)
		case "debug_logic_parameters", "dos_parameters", "location_header":
			return true
		case "password":
			return isPlaceholderPassword(contentText)
		}
	}

	if idText == "location_header" {
		return !strings.Contains(strings.ToLower(contentText), "http") && !strings.Contains(contentText, "/")
	}

	return false
}

func isJSLikeSource(source string) bool {
	sourceText := strings.ToLower(strings.TrimSpace(source))
	if sourceText == "" {
		return false
	}
	if strings.Contains(sourceText, "/__wih_sourcemap__/") {
		return true
	}
	for _, suffix := range []string{".js", ".mjs", ".cjs", ".map", ".ts", ".tsx", ".jsx"} {
		if strings.Contains(sourceText, suffix) {
			return true
		}
	}
	return false
}

func isLikelyMeaningfulJSPath(pathText string) bool {
	text := strings.TrimSpace(pathText)
	if !strings.HasPrefix(text, "/") {
		return false
	}
	if strings.ContainsAny(text, "\"'`()[]{}|=*") {
		return false
	}
	lowered := strings.ToLower(text)
	for _, token := range []string{
		".test", ".exec", ".value", ".name", ".scroll", ".prototype", "this.", "window.", "document.",
		"runtime-core", "runtime-dom", "reactivity", "shared", "function", "const", "let", "var",
	} {
		if strings.Contains(lowered, token) {
			return false
		}
	}
	segments := splitPathSegments(text)
	if len(segments) == 0 {
		return false
	}
	if containsEndpointKeyword(text) {
		return true
	}
	for _, segment := range segments {
		if len(segment) < 2 {
			return false
		}
		if regexp.MustCompile(`^\d+(?:\.\d+)?$`).MatchString(segment) {
			return false
		}
	}
	return len(segments) >= 2
}

func isLikelyMeaningfulJSDomain(domainText string) bool {
	raw := strings.TrimSpace(domainText)
	if raw == "" {
		return false
	}
	if raw != strings.ToLower(raw) {
		return false
	}
	labels := strings.Split(raw, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels[:len(labels)-1] {
		if strings.TrimSpace(label) == "" {
			return false
		}
	}
	if len(labels) == 2 && len(labels[0]) < 3 {
		return false
	}
	for _, token := range []string{"appcontext", "prototype", "runtime", "scroll", "window", "document", "record", "value"} {
		if strings.Contains(raw, token) {
			return false
		}
	}
	return true
}

func isLikelyMeaningfulJSURL(rawURL string) bool {
	text := strings.TrimSpace(rawURL)
	if text == "" {
		return false
	}
	if strings.ContainsAny(text, "{}$`") || strings.Contains(text, "${") || strings.Contains(text, "{{") {
		return false
	}
	parsed, err := url.Parse(text)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	return true
}

func filterRecordsByTargetScope(targetURL string, records []datatype.ScanRecord) []datatype.ScanRecord {
	if len(records) == 0 {
		return nil
	}

	scope := buildTargetScope(targetURL)
	if scope.Host == "" {
		return records
	}

	result := make([]datatype.ScanRecord, 0, len(records))
	for _, record := range records {
		if shouldDropOutOfScopeRecord(record, scope) {
			continue
		}
		result = append(result, record)
	}
	return result
}

func buildTargetScope(targetURL string) targetScope {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return targetScope{}
	}

	host := normalizeHostToken(parsed.Hostname())
	if host == "" {
		return targetScope{}
	}

	scope := targetScope{Host: host}
	if net.ParseIP(host) == nil {
		scope.RegistrableDomain = effectiveRegistrableDomain(host)
	}
	return scope
}

func shouldDropOutOfScopeRecord(record datatype.ScanRecord, scope targetScope) bool {
	idText := strings.ToLower(strings.TrimSpace(record.Id))
	contentText := strings.TrimSpace(record.Content)
	if contentText == "" {
		return false
	}

	switch idText {
	case "domain":
		return !isHostInTargetScope(contentText, scope)
	case "domain_url":
		parsed, err := url.Parse(contentText)
		if err != nil {
			return true
		}
		return !isHostInTargetScope(parsed.Hostname(), scope)
	case "email":
		atIndex := strings.LastIndex(contentText, "@")
		if atIndex <= 0 || atIndex >= len(contentText)-1 {
			return true
		}
		return !isHostInTargetScope(contentText[atIndex+1:], scope)
	default:
		return false
	}
}

func isHostInTargetScope(rawHost string, scope targetScope) bool {
	host := normalizeHostToken(rawHost)
	if host == "" || scope.Host == "" {
		return false
	}
	if host == scope.Host {
		return true
	}

	hostIP := net.ParseIP(host)
	scopeIP := net.ParseIP(scope.Host)
	if hostIP != nil || scopeIP != nil {
		return host == scope.Host
	}

	hostRegistrable := effectiveRegistrableDomain(host)
	if hostRegistrable == "" || scope.RegistrableDomain == "" {
		return host == scope.Host || strings.HasSuffix(host, "."+scope.Host) || strings.HasSuffix(scope.Host, "."+host)
	}
	return hostRegistrable == scope.RegistrableDomain
}

func normalizeHostToken(rawHost string) string {
	host := strings.ToLower(strings.TrimSpace(rawHost))
	host = strings.Trim(host, ".")
	return host
}

func effectiveRegistrableDomain(host string) string {
	normalized := normalizeHostToken(host)
	if normalized == "" {
		return ""
	}
	value, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		return normalized
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func extractHTMLTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	match := titlePattern.FindStringSubmatch(string(body))
	if len(match) < 2 {
		return ""
	}
	titleText := strings.TrimSpace(stripHTMLTags(match[1]))
	titleText = regexp.MustCompile(`\s+`).ReplaceAllString(titleText, " ")
	if len(titleText) > 120 {
		titleText = titleText[:120]
	}
	return strings.TrimSpace(titleText)
}

func isPlaceholderPassword(content string) bool {
	lowered := strings.ToLower(strings.TrimSpace(content))
	return strings.Contains(lowered, `password="password"`) || strings.Contains(lowered, `password='password'`)
}

func splitPathSegments(pathText string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(pathText), "/"), "/")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return result
}

func containsEndpointKeyword(pathText string) bool {
	lowered := strings.ToLower(strings.TrimSpace(pathText))
	for _, token := range []string{
		"/api", "/auth", "/login", "/logout", "/graphql", "/oauth", "/token", "/user", "/account",
		"/search", "/query", "/upload", "/download", "/file", "/service", "/admin", "/rest",
		"/openapi", "/swagger", "/captcha", "/verify",
	} {
		if strings.Contains(lowered, token) {
			return true
		}
	}
	return false
}

// normalizePathToken 规范化 path 记录内容，仅保留可拼接路径片段。
func normalizePathToken(rawPath string) string {
	pathText := strings.TrimSpace(rawPath)
	if !strings.HasPrefix(pathText, "/") {
		return ""
	}

	// path 规则仅用于路径探测，剔除 query/fragment 干扰。
	pathText = strings.SplitN(pathText, "?", 2)[0]
	pathText = strings.SplitN(pathText, "#", 2)[0]
	pathText = routeMethodSuffixPattern.ReplaceAllString(pathText, "")
	pathText = strings.TrimSpace(pathText)
	if pathText == "" || pathText == "/" {
		return ""
	}

	if strings.Contains(pathText, " ") {
		return ""
	}
	if hasPathTemplateMarker(pathText) {
		return ""
	}

	pathText = path.Clean(pathText)
	if !strings.HasPrefix(pathText, "/") {
		pathText = "/" + pathText
	}
	if pathText == "" || pathText == "/" || pathText == "/." {
		return ""
	}
	if isPathProbeStaticResource(pathText) {
		return ""
	}
	if isNoiseSingleSegmentPath(pathText) {
		return ""
	}

	return pathText
}

func hasPathTemplateMarker(pathText string) bool {
	text := strings.TrimSpace(pathText)
	if text == "" {
		return false
	}

	if strings.ContainsAny(text, "{}<>[]|") || strings.Contains(text, "${") {
		return true
	}

	for _, segment := range strings.Split(text, "/") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if strings.HasPrefix(segment, ":") {
			return true
		}
		if strings.Contains(segment, "*") {
			return true
		}
	}

	return false
}

func isNoiseSingleSegmentPath(pathText string) bool {
	text := strings.Trim(strings.TrimSpace(pathText), "/")
	if text == "" {
		return false
	}
	if strings.Contains(text, "/") || strings.Contains(text, ".") {
		return false
	}

	_, ok := pathProbeNoiseSingleSegments[strings.ToLower(text)]
	return ok
}

func isPathProbeStaticResource(pathText string) bool {
	lowerPath := strings.ToLower(strings.TrimSpace(pathText))
	if lowerPath == "" {
		return false
	}
	for _, suffix := range pathProbeStaticSuffixes {
		if strings.HasSuffix(lowerPath, suffix) {
			return true
		}
	}
	return false
}

// buildCandidateURLsByPath 按“根路径 + 当前目录”构建候选 URL。
func buildCandidateURLsByPath(targetParsed *url.URL, sourceURL string, pathToken string) []string {
	if targetParsed == nil || targetParsed.Host == "" {
		return nil
	}
	relPath := strings.TrimLeft(pathToken, "/")
	if relPath == "" {
		return nil
	}

	baseURLSet := make(map[string]struct{})
	rootBase := fmt.Sprintf("%s://%s/", targetParsed.Scheme, targetParsed.Host)
	baseURLSet[rootBase] = struct{}{}

	sourceParsed, err := url.Parse(sourceURL)
	if err == nil && strings.EqualFold(sourceParsed.Host, targetParsed.Host) {
		sourceScheme := sourceParsed.Scheme
		if sourceScheme == "" {
			sourceScheme = targetParsed.Scheme
		}

		sourcePath := sourceParsed.Path
		if sourcePath == "" {
			sourcePath = "/"
		}
		dirPath := sourcePath
		if !strings.HasSuffix(dirPath, "/") {
			dirPath = path.Dir(dirPath)
		}
		if !strings.HasPrefix(dirPath, "/") {
			dirPath = "/" + dirPath
		}
		if !strings.HasSuffix(dirPath, "/") {
			dirPath += "/"
		}
		contextBase := fmt.Sprintf("%s://%s%s", sourceScheme, sourceParsed.Host, dirPath)
		baseURLSet[contextBase] = struct{}{}
	}

	candidateSet := make(map[string]struct{})
	for baseText := range baseURLSet {
		baseParsed, baseErr := url.Parse(baseText)
		if baseErr != nil || baseParsed.Host == "" {
			continue
		}
		resolved := baseParsed.ResolveReference(&url.URL{Path: relPath})
		if resolved == nil || !strings.EqualFold(resolved.Host, targetParsed.Host) {
			continue
		}
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		resolved.Fragment = ""
		candidateSet[resolved.String()] = struct{}{}
	}

	candidates := make([]string, 0, len(candidateSet))
	for item := range candidateSet {
		candidates = append(candidates, item)
	}
	sort.Strings(candidates)
	return candidates
}

// sortedPathProbeCandidates 输出稳定有序的候选列表，便于测试与排障。
func sortedPathProbeCandidates(input map[string]pathProbeCandidate) []pathProbeCandidate {
	if len(input) == 0 {
		return nil
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make([]pathProbeCandidate, 0, len(keys))
	for _, key := range keys {
		result = append(result, input[key])
	}
	return result
}

// normalizeTargetURL 规范化扫描目标。
func normalizeTargetURL(raw string) string {
	target := strings.TrimSpace(raw)
	if target == "" {
		return ""
	}

	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return target
	}
	return "http://" + target
}

// extractJSURLs 从页面提取并归一化 JS URL。
func extractJSURLs(pageBody string, pageURL string) []string {
	results := make([]string, 0)
	seen := make(map[string]struct{})

	add := func(raw string) {
		normalized := normalizeJSURL(raw, pageURL)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		results = append(results, normalized)
	}

	for _, match := range jsSrcPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(match) < 2 {
			continue
		}
		add(match[1])
	}

	for _, match := range jsAbsPattern.FindAllString(pageBody, -1) {
		add(match)
	}

	return results
}

// normalizeJSURL 将相对路径转换为可访问的绝对 URL。
func normalizeJSURL(rawURL string, baseURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "data:") {
		return ""
	}

	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	if strings.HasPrefix(rawURL, "//") {
		rawURL = baseParsed.Scheme + ":" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	resolved := baseParsed.ResolveReference(parsed)
	if resolved == nil || resolved.Host == "" {
		return ""
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	resolved.Fragment = ""
	return resolved.String()
}

// dedupeRecords 依据 hash 去重。
func dedupeRecords(records []datatype.ScanRecord) []datatype.ScanRecord {
	if len(records) <= 1 {
		return records
	}
	result := make([]datatype.ScanRecord, 0, len(records))
	seen := make(map[uint64]struct{})
	for _, record := range records {
		if _, ok := seen[record.Hash]; ok {
			continue
		}
		seen[record.Hash] = struct{}{}
		result = append(result, record)
	}
	return result
}
