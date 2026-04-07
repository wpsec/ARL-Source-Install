package util

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const fallbackOutputRootDir = "output"

var defaultOutputRootDir = fallbackOutputRootDir
var outputGroupNameRE = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
var defaultOutputRunTimestamp = time.Now().Format("20060102_150405")

// SetDefaultOutputRootDir 设置相对输出文件的根目录。
func SetDefaultOutputRootDir(rootDir string) {
	path := strings.TrimSpace(rootDir)
	if path == "" || path == "-" {
		defaultOutputRootDir = fallbackOutputRootDir
		return
	}
	defaultOutputRootDir = filepath.Clean(path)
}

// ResolveOutputPath 将相对文件名归一到 <output-root>/<scope>/ 目录下。
func ResolveOutputPath(writePath string) string {
	return ResolveOutputPathForTarget("", writePath)
}

// ResolveOutputPathForTarget 将相对文件名归一到 <output-root>/<hostname_timestamp>/ 目录下。
func ResolveOutputPathForTarget(targetURL string, writePath string) string {
	path := strings.TrimSpace(writePath)
	if path == "" || path == "-" {
		return path
	}

	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) {
		return cleanPath
	}

	dir := filepath.Dir(cleanPath)
	if dir != "." && dir != "" {
		return cleanPath
	}

	baseName := filepath.Base(cleanPath)
	scopeName := outputScopeName(targetURL, baseName)
	return filepath.Join(defaultOutputRootDir, scopeName, baseName)
}

// ResolveOutputPathInScope 将相对文件名放到主输出同级目录下。
func ResolveOutputPathInScope(scopePath string, targetURL string, writePath string) string {
	path := strings.TrimSpace(writePath)
	if path == "" || path == "-" {
		return path
	}

	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) {
		return cleanPath
	}

	dir := filepath.Dir(cleanPath)
	if dir != "." && dir != "" {
		return cleanPath
	}

	scopeDir := outputScopeDir(scopePath)
	if scopeDir == "" {
		return ResolveOutputPathForTarget(targetURL, cleanPath)
	}
	return filepath.Join(scopeDir, filepath.Base(cleanPath))
}

func outputScopeDir(scopePath string) string {
	path := strings.TrimSpace(scopePath)
	if path == "" || path == "-" {
		return ""
	}

	dir := filepath.Dir(filepath.Clean(path))
	if dir == "." || dir == "" {
		return ""
	}
	return dir
}

func outputScopeName(targetURL string, fallbackName string) string {
	name := hostnameFromTarget(targetURL)
	if name == "" {
		name = strings.TrimSpace(fallbackName)
	}

	base := ""
	if hostnameFromTarget(targetURL) != "" {
		base = sanitizeOutputPathName(name, false)
	} else {
		base = sanitizeOutputPathName(name, true)
	}
	if base == "" {
		seed := strings.TrimSpace(targetURL)
		if seed == "" {
			seed = strings.TrimSpace(fallbackName)
		}
		if seed == "" {
			seed = "output"
		}
		base = fmt.Sprintf("output_%d", StableHash(seed))
	}
	return base + "_" + defaultOutputRunTimestamp
}

func hostnameFromTarget(targetURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Hostname())
}

func sanitizeOutputPathName(raw string, stripExt bool) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		return ""
	}

	base := name
	if stripExt {
		ext := filepath.Ext(name)
		base = strings.TrimSuffix(name, ext)
	}
	base = outputGroupNameRE.ReplaceAllString(base, "_")
	base = strings.Trim(base, "._-")
	if len(base) > 80 {
		base = base[:80]
	}
	return base
}

// ResolveTaskAggregatePath 生成单次任务的汇总输出路径。
func ResolveTaskAggregatePath(writePath string) string {
	path := strings.TrimSpace(writePath)
	useDefaultName := false
	if path == "" || path == "-" {
		path = "aggregate.csv"
		useDefaultName = true
	}

	cleanPath := filepath.Clean(path)
	baseName := filepath.Base(cleanPath)
	ext := filepath.Ext(baseName)
	base := strings.TrimSuffix(baseName, ext)
	if strings.TrimSpace(base) == "" {
		base = "aggregate"
	}
	aggregateName := ""
	if useDefaultName {
		aggregateName = "aggregate.csv"
	} else {
		aggregateName = base + "_aggregate"
		if ext == "" {
			aggregateName += ".csv"
		} else {
			aggregateName += ext
		}
	}

	taskDirName := "task_" + defaultOutputRunTimestamp
	if filepath.IsAbs(cleanPath) {
		return filepath.Join(filepath.Dir(cleanPath), taskDirName, aggregateName)
	}

	dir := filepath.Dir(cleanPath)
	if dir != "." && dir != "" {
		return filepath.Join(dir, taskDirName, aggregateName)
	}
	return filepath.Join(defaultOutputRootDir, taskDirName, aggregateName)
}

// ResolveTaskAggregateCSVPath 生成单次任务的汇总 CSV 路径。
func ResolveTaskAggregateCSVPath(writePath string) string {
	path := ResolveTaskAggregatePath(writePath)
	ext := filepath.Ext(path)
	if ext == "" {
		return path + ".csv"
	}
	return strings.TrimSuffix(path, ext) + ".csv"
}
