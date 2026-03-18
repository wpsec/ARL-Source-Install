package scan

import (
	"fmt"
	"io"
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
)

var (
	jsSrcPattern = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']`)
	jsAbsPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+\.js(?:\?[^\s"'<>]*)?`)
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
)

// pathProbeCandidate 表示一条待探测 URL 候选。
type pathProbeCandidate struct {
	URL    string
	Source string
}

// Scan 扫描单个站点：页面正文 + JS 资源。
func Scan(targetURL string) *datatype.ScanResult {
	targetURL = normalizeTargetURL(targetURL)
	if targetURL == "" {
		return nil
	}

	client := util.NewClient()
	pageBody, err := fetchBody(client, targetURL)
	if err != nil {
		util.ErrPrint(err)
		return nil
	}

	records := rule(pageBody, targetURL, "page")
	if len(records) >= global.MaxCollect {
		return &datatype.ScanResult{Target: targetURL, Records: records[:global.MaxCollect]}
	}

	jsURLs := extractJSURLs(pageBody, targetURL)
	if global.MaxJSFiles > 0 && len(jsURLs) > global.MaxJSFiles {
		jsURLs = jsURLs[:global.MaxJSFiles]
	}

	jsRecords := scanJSResources(client, jsURLs)
	records = append(records, jsRecords...)
	records = dedupeRecords(records)

	// 对 path 命中做“根路径 + 当前目录”双策略拼接探测。
	if len(records) < global.MaxCollect {
		pathProbeRecords := probePathRecords(client, targetURL, records)
		records = append(records, pathProbeRecords...)
		records = dedupeRecords(records)
	}

	if len(records) > global.MaxCollect {
		records = records[:global.MaxCollect]
	}

	return &datatype.ScanResult{Target: targetURL, Records: records}
}

// fetchBody 抓取目标内容，并应用响应大小限制。
func fetchBody(client *http.Client, target string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	util.ApplyRequestHeaders(req)

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
func scanJSResources(client *http.Client, jsURLs []string) []datatype.ScanRecord {
	if len(jsURLs) == 0 {
		return nil
	}

	workerCount := global.ConcurrencyPerSite
	if workerCount < 1 {
		workerCount = 1
	}

	jobs := make(chan string)
	results := make(chan []datatype.ScanRecord, len(jsURLs))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jsURL := range jobs {
				jsBody, err := fetchBody(client, jsURL)
				if err != nil {
					util.ErrPrint(err)
					continue
				}
				results <- rule(jsBody, jsURL, "js")
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

	merged := make([]datatype.ScanRecord, 0)
	for batch := range results {
		if len(batch) == 0 {
			continue
		}
		merged = append(merged, batch...)
	}

	if len(merged) > global.MaxCollect {
		return merged[:global.MaxCollect]
	}
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
				record := probeSinglePathCandidate(&probeClient, candidate)
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
func probeSinglePathCandidate(client *http.Client, candidate pathProbeCandidate) *datatype.ScanRecord {
	req, err := http.NewRequest(http.MethodGet, candidate.URL, nil)
	if err != nil {
		return nil
	}
	util.ApplyRequestHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, pathProbeDrainBytes))

	if !isPathProbeStatusUseful(resp.StatusCode) {
		return nil
	}

	hashText := "path_url|" + candidate.URL
	return &datatype.ScanRecord{
		Id:      "path_url",
		Content: candidate.URL,
		Source:  candidate.Source,
		Tag:     fmt.Sprintf("path_probe status=%d", resp.StatusCode),
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

// normalizePathToken 规范化 path 记录内容，仅保留可拼接路径片段。
func normalizePathToken(rawPath string) string {
	pathText := strings.TrimSpace(rawPath)
	if !strings.HasPrefix(pathText, "/") {
		return ""
	}

	// path 规则仅用于路径探测，剔除 query/fragment 干扰。
	pathText = strings.SplitN(pathText, "?", 2)[0]
	pathText = strings.SplitN(pathText, "#", 2)[0]
	pathText = strings.TrimSpace(pathText)
	if pathText == "" || pathText == "/" {
		return ""
	}
	return pathText
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
