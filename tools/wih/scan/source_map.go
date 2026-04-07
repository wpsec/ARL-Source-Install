package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	sourceMapCommentPattern = regexp.MustCompile("(?im)(?://[#@]\\s*sourceMappingURL=([^\\s\"'`]+)|/\\*[#@]\\s*sourceMappingURL=([^*\\s]+)\\s*\\*/)")
)

const sourceMapFetchSourceLimit = 6

type jsScanUnit struct {
	URL             string
	Body            string
	SourceType      string
	ParameterSource string
	RuleSourceTag   string
}

type sourceMapDocument struct {
	Version        int      `json:"version"`
	File           string   `json:"file"`
	SourceRoot     string   `json:"sourceRoot"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

func extractSourceMapReference(jsBody string) string {
	matches := sourceMapCommentPattern.FindAllStringSubmatch(jsBody, -1)
	if len(matches) == 0 {
		return ""
	}
	last := matches[len(matches)-1]
	return strings.TrimSpace(firstNonEmpty(matchValue(last, 1), matchValue(last, 2)))
}

func resolveSourceMapURL(baseJSURL string, reference string) (string, error) {
	refText := strings.TrimSpace(reference)
	if refText == "" {
		return "", fmt.Errorf("empty source map reference")
	}
	if strings.HasPrefix(strings.ToLower(refText), "data:") {
		return "", fmt.Errorf("inline source map is not supported")
	}

	baseParsed, err := url.Parse(strings.TrimSpace(baseJSURL))
	if err != nil || baseParsed.Host == "" {
		return "", fmt.Errorf("invalid base js url")
	}
	targetParsed, err := url.Parse(refText)
	if err != nil {
		return "", err
	}
	resolved := baseParsed.ResolveReference(targetParsed)
	if resolved == nil || resolved.Host == "" {
		return "", fmt.Errorf("invalid resolved source map url")
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("unsupported source map scheme")
	}
	if !strings.EqualFold(resolved.Hostname(), baseParsed.Hostname()) {
		return "", fmt.Errorf("cross host source map")
	}
	resolved.Fragment = ""
	return resolved.String(), nil
}

func guessSourceMapURL(jsURL string) (string, error) {
	jsParsed, err := url.Parse(strings.TrimSpace(jsURL))
	if err != nil || jsParsed.Host == "" {
		return "", fmt.Errorf("invalid js url")
	}
	if jsParsed.Path == "" {
		return "", fmt.Errorf("empty js path")
	}
	if strings.HasSuffix(strings.ToLower(jsParsed.Path), ".map") {
		return jsParsed.String(), nil
	}
	jsParsed.Path = jsParsed.Path + ".map"
	jsParsed.Fragment = ""
	return jsParsed.String(), nil
}

func fetchSourceMapScanUnits(client *http.Client, scanTargetURL string, jsURL string, jsBody string) []jsScanUnit {
	candidateURLs := buildSourceMapCandidateURLs(jsURL, jsBody)
	if len(candidateURLs) == 0 {
		return nil
	}

	seenMapURLs := make(map[string]struct{})
	for _, mapURL := range candidateURLs {
		mapText := strings.TrimSpace(mapURL)
		if mapText == "" {
			continue
		}
		if _, ok := seenMapURLs[mapText]; ok {
			continue
		}
		seenMapURLs[mapText] = struct{}{}

		mapBody, err := fetchBody(client, mapText, scanTargetURL)
		if err != nil || strings.TrimSpace(mapBody) == "" {
			continue
		}

		units := collectSourceMapScanUnits(client, scanTargetURL, mapText, mapBody)
		if len(units) > 0 {
			return dedupeJSScanUnits(units)
		}
	}

	return nil
}

func buildSourceMapCandidateURLs(jsURL string, jsBody string) []string {
	candidates := make([]string, 0, 2)
	if reference := extractSourceMapReference(jsBody); reference != "" {
		if resolvedURL, err := resolveSourceMapURL(jsURL, reference); err == nil {
			candidates = append(candidates, resolvedURL)
		}
	}
	if guessedURL, err := guessSourceMapURL(jsURL); err == nil {
		candidates = append(candidates, guessedURL)
	}
	return uniqueSortedStrings(candidates)
}

func collectSourceMapScanUnits(client *http.Client, scanTargetURL string, mapURL string, mapBody string) []jsScanUnit {
	document := sourceMapDocument{}
	if err := json.Unmarshal([]byte(mapBody), &document); err != nil {
		return nil
	}

	units := make([]jsScanUnit, 0)
	seen := make(map[string]struct{})

	sourceCount := len(document.Sources)
	if len(document.SourcesContent) > 0 {
		limit := sourceCount
		if len(document.SourcesContent) < limit {
			limit = len(document.SourcesContent)
		}
		for index := 0; index < limit; index++ {
			bodyText := strings.TrimSpace(document.SourcesContent[index])
			if bodyText == "" {
				continue
			}
			sourceURL := buildSourceMapSourceURL(mapURL, document.SourceRoot, document.Sources[index])
			if sourceURL == "" {
				continue
			}
			key := sourceURL + "|" + bodyText
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			units = append(units, jsScanUnit{
				URL:             sourceURL,
				Body:            bodyText,
				SourceType:      "source_map_js",
				ParameterSource: "source_map_js",
				RuleSourceTag:   "js_source_map",
			})
		}
		if len(units) > 0 {
			return units
		}
	}

	fetchCount := 0
	if client == nil {
		return units
	}
	for _, rawSource := range document.Sources {
		if fetchCount >= sourceMapFetchSourceLimit {
			break
		}
		sourceURL := buildSourceMapSourceURL(mapURL, document.SourceRoot, rawSource)
		if sourceURL == "" {
			continue
		}
		sourceBody, err := fetchBody(client, sourceURL, scanTargetURL)
		if err != nil || strings.TrimSpace(sourceBody) == "" {
			continue
		}
		key := sourceURL + "|" + sourceBody
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		units = append(units, jsScanUnit{
			URL:             sourceURL,
			Body:            sourceBody,
			SourceType:      "source_map_js",
			ParameterSource: "source_map_js",
			RuleSourceTag:   "js_source_map",
		})
		fetchCount++
	}

	return units
}

func buildSourceMapSourceURL(mapURL string, sourceRoot string, rawSource string) string {
	sourceText := strings.TrimSpace(rawSource)
	if sourceText == "" {
		return ""
	}
	if !isUsefulSourceMapSourcePath(sourceText) {
		return ""
	}

	mapParsed, err := url.Parse(strings.TrimSpace(mapURL))
	if err != nil || mapParsed.Host == "" {
		return ""
	}

	if strings.HasPrefix(strings.ToLower(sourceText), "http://") || strings.HasPrefix(strings.ToLower(sourceText), "https://") {
		targetParsed, targetErr := url.Parse(sourceText)
		if targetErr != nil || targetParsed.Host == "" {
			return ""
		}
		if !strings.EqualFold(targetParsed.Hostname(), mapParsed.Hostname()) {
			return ""
		}
		targetParsed.Fragment = ""
		return targetParsed.String()
	}

	if strings.Contains(sourceText, "://") || strings.HasPrefix(sourceText, "node:") {
		return buildVirtualSourceMapURL(mapParsed, sourceText)
	}

	baseRef := *mapParsed
	baseRef.RawQuery = ""
	baseRef.Fragment = ""

	rootText := strings.TrimSpace(sourceRoot)
	if rootText != "" {
		rootParsed, rootErr := url.Parse(rootText)
		if rootErr == nil {
			baseRef = *baseRef.ResolveReference(rootParsed)
		}
	}

	sourceParsed, err := url.Parse(sourceText)
	if err != nil {
		return buildVirtualSourceMapURL(mapParsed, sourceText)
	}
	resolved := baseRef.ResolveReference(sourceParsed)
	if resolved == nil || resolved.Host == "" {
		return buildVirtualSourceMapURL(mapParsed, sourceText)
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return buildVirtualSourceMapURL(mapParsed, sourceText)
	}
	if !strings.EqualFold(resolved.Hostname(), mapParsed.Hostname()) {
		return ""
	}
	resolved.Fragment = ""
	return resolved.String()
}

func buildVirtualSourceMapURL(mapParsed *url.URL, rawSource string) string {
	if mapParsed == nil || mapParsed.Host == "" {
		return ""
	}
	virtualPath := strings.Trim(strings.TrimSpace(rawSource), "/")
	if virtualPath == "" {
		virtualPath = "source.js"
	}
	virtualPath = strings.ReplaceAll(virtualPath, "\\", "/")
	virtualPath = path.Clean("/__wih_sourcemap__/" + virtualPath)

	virtualURL := *mapParsed
	virtualURL.Path = virtualPath
	virtualURL.RawQuery = ""
	virtualURL.Fragment = ""
	return virtualURL.String()
}

func isUsefulSourceMapSourcePath(rawSource string) bool {
	text := strings.ToLower(strings.TrimSpace(rawSource))
	if text == "" {
		return false
	}
	if strings.Contains(text, "node_modules/") || strings.Contains(text, "/node_modules/") {
		return false
	}
	if strings.Contains(text, "webpack/bootstrap") || strings.Contains(text, "webpack/runtime") {
		return false
	}
	suffixes := []string{
		".js",
		".mjs",
		".cjs",
		".jsx",
		".ts",
		".tsx",
		".vue",
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(text, suffix) {
			return true
		}
	}
	return false
}

func dedupeJSScanUnits(units []jsScanUnit) []jsScanUnit {
	if len(units) <= 1 {
		return units
	}
	result := make([]jsScanUnit, 0, len(units))
	seen := make(map[string]struct{})
	for _, unit := range units {
		urlText := strings.TrimSpace(unit.URL)
		bodyText := strings.TrimSpace(unit.Body)
		if urlText == "" || bodyText == "" {
			continue
		}
		key := fmt.Sprintf("%s|%s", urlText, bodyText)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, unit)
	}
	return result
}
