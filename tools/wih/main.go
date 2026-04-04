package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	datatype "wih/dataType"
	"wih/factory"
	"wih/global"
	"wih/options"
	"wih/scan"
	"wih/util"

	"github.com/gookit/color"
)

var (
	outputLock sync.Mutex
	akskLock   sync.Mutex
	fileNameRE = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
)

// main 为 wih 入口。
func main() {
	option := options.Options()
	if option == nil {
		return
	}

	if option.ShowVersion {
		fmt.Printf("version: %s\n", global.Version)
		return
	}

	if option.GenerateRule {
		if err := util.GenerateRuleTemplate(option.OutputFilePath); err != nil {
			fmt.Println(err)
		}
		return
	}

	printBanner()
	scan.RuleLoad()

	targets := factory.Factory(option)
	if len(targets) == 0 {
		fmt.Println("未找到可扫描目标")
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, option.Concurrency)
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scan.Scan(targetURL)
			if result == nil {
				return
			}

			realOutputPath := option.OutputFilePath
			if option.AutoSaveName {
				realOutputPath = buildAutoSavePath(targetURL, option.OutputJSON)
			}
			endpointOutputPath, parameterOutputPath := util.ResolveStructuredOutputPaths(
				realOutputPath,
				option.EndpointOutputPath,
				option.ParameterOutputPath,
			)

			outputLock.Lock()
			util.FormatOutput(result, option.OutputJSON)
			util.FormatOutputWrite(result, realOutputPath, option.OutputJSON)
			if !option.DisableStructuredOutput {
				util.WriteStructuredOutputFiles(result, endpointOutputPath, parameterOutputPath)
			}
			outputLock.Unlock()

			if !option.DisableAKSKOutput {
				saveAKSK(result, option.AKSKOutputPath, option.AutoSaveName)
			}
		}(target)
	}
	wg.Wait()
}

// printBanner 根据日志级别输出启动横幅。
func printBanner() {
	if global.LogLevel == "zero" {
		return
	}
	if global.DisableColor {
		fmt.Printf(global.LOGO, global.Version)
		return
	}
	color.C256(45).Printf(global.LOGO, global.Version)
}

// saveAKSK 将可能的 AK/SK 结果单独落盘。
func saveAKSK(result *datatype.ScanResult, outputPath string, autoSaveName bool) {
	if result == nil || len(result.Records) == 0 {
		return
	}

	path := strings.TrimSpace(outputPath)
	if path == "" || path == "-" {
		path = "ak_leak.txt"
	}
	if autoSaveName {
		base := buildAutoSavePath(result.Target, false)
		path = strings.TrimSuffix(base, filepath.Ext(base)) + "_ak_leak.txt"
	}

	var builder strings.Builder
	for _, record := range result.Records {
		if !isAKSKRecord(record) {
			continue
		}
		builder.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\n", result.Target, record.Id, record.Content, record.Source))
	}
	if builder.Len() == 0 {
		return
	}

	akskLock.Lock()
	util.WriteFile(path, builder.String())
	akskLock.Unlock()
}

// isAKSKRecord 判断记录是否属于 AK/SK 凭证类结果。
func isAKSKRecord(record datatype.ScanRecord) bool {
	id := strings.ToLower(record.Id)
	if strings.Contains(id, "_ak_id") || strings.Contains(id, "secret") || strings.Contains(id, "token") || strings.Contains(id, "api_key") || strings.Contains(id, "apikey") {
		return true
	}

	content := strings.ToUpper(record.Content)
	if strings.Contains(content, "LTAI") || strings.Contains(content, "AKIA") || strings.Contains(content, "AKID") || strings.Contains(content, "JDC_") {
		return true
	}
	return false
}

// buildAutoSavePath 根据目标和输出模式生成文件名。
func buildAutoSavePath(targetURL string, outputJSON bool) string {
	ext := ".txt"
	if outputJSON {
		ext = ".json"
	} else {
		switch global.OutputMode {
		case "csv":
			ext = ".csv"
		case "html":
			ext = ".html"
		case "md":
			ext = ".md"
		}
	}

	base := sanitizeFilename(targetURL)
	if parsed, err := url.Parse(targetURL); err == nil && parsed.Hostname() != "" {
		base = sanitizeFilename(parsed.Hostname())
	}
	if base == "" {
		base = fmt.Sprintf("target_%d", util.StableHash(targetURL))
	}
	return filepath.Clean(base + ext)
}

// sanitizeFilename 将字符串转换为安全文件名。
func sanitizeFilename(raw string) string {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return ""
	}
	cleaned = fileNameRE.ReplaceAllString(cleaned, "_")
	cleaned = strings.Trim(cleaned, "._-")
	if len(cleaned) > 80 {
		cleaned = cleaned[:80]
	}
	return cleaned
}
