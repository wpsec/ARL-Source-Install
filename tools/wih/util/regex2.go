package util

import (
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

var regexCache sync.Map

// Regex2 使用 regexp2 做全局匹配并返回所有命中内容。
// 为降低重复编译开销，内部带有正则编译缓存。
func Regex2(body string, pattern string) ([]string, error) {
	re, err := getOrCompileRegex(pattern)
	if err != nil {
		return nil, err
	}
	return findAllMatches(re, body, 0)
}

// Regex2Limit 与 Regex2 一致，但限制最大命中数量（0 表示不限制）。
func Regex2Limit(body string, pattern string, limit int) ([]string, error) {
	re, err := getOrCompileRegex(pattern)
	if err != nil {
		return nil, err
	}
	return findAllMatches(re, body, limit)
}

func getOrCompileRegex(pattern string) (*regexp2.Regexp, error) {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp2.Regexp), nil
	}

	re, err := regexp2.Compile(pattern, 0)
	if err != nil {
		return nil, err
	}
	// 防止复杂正则导致长时间回溯阻塞。
	re.MatchTimeout = 2 * time.Second
	regexCache.Store(pattern, re)
	return re, nil
}

func findAllMatches(re *regexp2.Regexp, text string, limit int) ([]string, error) {
	results := make([]string, 0)
	match, err := re.FindStringMatch(text)
	if err != nil {
		return nil, err
	}

	for match != nil {
		results = append(results, match.String())
		if limit > 0 && len(results) >= limit {
			break
		}
		match, err = re.FindNextMatch(match)
		if err != nil {
			return results, err
		}
	}
	return results, nil
}
