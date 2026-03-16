package scan

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	datatype "wih/dataType"
	"wih/global"
	"wih/util"
)

var (
	jsSrcPattern = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']`)
	jsAbsPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+\.js(?:\?[^\s"'<>]*)?`)
)

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
