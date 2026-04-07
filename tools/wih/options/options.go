package options

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	datatype "wih/dataType"
	"wih/global"
	"wih/util"

	"github.com/projectdiscovery/goflags"
)

// Options 解析命令行参数并同步全局运行配置。
func Options() *datatype.Option {
	util.EnsureRuleTemplate()

	option := &datatype.Option{
		RuleConfigPath:      "config/rules.yml",
		OutputDir:           "output",
		OutputFilePath:      "-",
		EndpointOutputPath:  "",
		ParameterOutputPath: "",
		LogLevel:            "info",
		LogFile:             "-",
		Concurrency:         2,
		ConcurrencyPerSite:  3,
		MaxCollect:          600,
		LimitReaderSize:     10 * 1024 * 1024,
		RuntimeEnable:       true,
		RuntimeDriver:       "playwright",
		RuntimeCommand:      "",
		RuntimeTimeoutSec:   20,
		RuntimeMaxPages:     8,
		RuntimeMaxActions:   20,
		RuntimeMaxRequests:  120,
		AKSKOutputPath:      "ak_leak.txt",
		OutputText:          true,
	}

	var timeoutRaw = "180"
	var dialTimeoutRaw = "5"
	var headerSingle string

	flagset := goflags.NewFlagSet()
	flagset.CaseSensitive = false

	flagset.CreateGroup("input", "输入参数",
		flagset.StringVarP(&option.Target, "target", "t", "", "目标URL或者文件"),
		flagset.StringVarP(&option.URL, "url", "u", "", "兼容参数：单个目标 URL"),
		flagset.StringVarP(&option.FilePath, "file-path", "", "", "兼容参数：目标文件路径"),
		flagset.StringVarP(&option.JsonFilePath, "json-path", "", "", "兼容参数：从 JSON 提取 source 字段"),
	)

	flagset.CreateGroup("output", "输出参数",
		flagset.StringVarP(&option.OutputDir, "output-dir", "", "output", "结果输出根目录（相对文件名默认写入 <output-dir>/<域名_时间戳>/）"),
		flagset.StringVarP(&option.OutputFilePath, "output", "o", "-", "结果输出文件名或路径(- 为标准输出；相对文件名默认写入 <output-dir>/<域名_时间戳>/；--csv 未指定时默认 result.csv，并自动写成 xlsx 工作簿)"),
		flagset.StringVarP(&option.EndpointOutputPath, "endpoint-output", "", "", "结构化接口结果输出文件（相对文件名默认写入主输出目录）"),
		flagset.StringVarP(&option.ParameterOutputPath, "parameter-output", "", "", "结构化参数结果输出文件（相对文件名默认写入主输出目录）"),
		flagset.BoolVarP(&option.OutputJSON, "output-json", "J", false, "JSON 格式输出"),
		flagset.BoolVarP(&option.OutputCSV, "csv", "", false, "CSV 格式输出"),
		flagset.BoolVarP(&option.OutputHTML, "html", "", false, "HTML 格式输出"),
		flagset.BoolVarP(&option.OutputMD, "md", "", false, "Markdown 格式输出"),
		flagset.BoolVarP(&option.OutputText, "text", "T", false, "文本格式输出"),
		flagset.BoolVarP(&option.DisableStructuredOutput, "disable-structured-output", "", false, "禁止 endpoint/parameter 独立输出"),
		flagset.IntVarP(&option.OutputSize, "size", "", 0, "设置表格分页大小"),
		flagset.BoolVarP(&option.AutoSaveName, "auto-save-name", "a", false, "根据站点自动生成保存的文件名"),
		flagset.StringVarP(&option.AKSKOutputPath, "ak-sk-output", "", "ak_leak.txt", "AK/SK 单独保存的文件名（相对文件名默认写入主输出目录）"),
		flagset.BoolVarP(&option.DisableAKSKOutput, "disable-ak-sk-output", "", false, "禁止 AK/SK 单独保存"),
	)

	flagset.CreateGroup("runtime", "运行参数",
		flagset.IntVarP(&option.Concurrency, "concurrency", "c", 2, "并发数(针对站点)"),
		flagset.IntVarP(&option.ConcurrencyPerSite, "concurrency-per-site", "P", 3, "每个站点的并发数"),
		flagset.IntVarP(&option.MaxCollect, "max-collect", "M", 600, "用于表示所有收集类型的最大收集数量, 对于每个站点"),
		flagset.IntVarP(&option.LimitReaderSize, "limit-reader-size", "", 10*1024*1024, "Maximum response size (in bytes)"),
		flagset.BoolVarP(&option.RuntimeEnable, "runtime-enable", "", true, "启用运行时参数采集（默认启用 Playwright）"),
		flagset.StringVarP(&option.RuntimeDriver, "runtime-driver", "", "playwright", "运行时采集驱动(playwright/external/noop)"),
		flagset.StringVarP(&option.RuntimeCommand, "runtime-command", "", "", "运行时采集命令；external 为完整命令，playwright 可覆盖默认 node 调用"),
		flagset.IntVarP(&option.RuntimeTimeoutSec, "runtime-timeout", "", 20, "运行时采集超时(秒)"),
		flagset.IntVarP(&option.RuntimeMaxPages, "runtime-max-pages", "", 8, "运行时探索最大页面数"),
		flagset.IntVarP(&option.RuntimeMaxActions, "runtime-max-actions", "", 20, "运行时探索最大交互动作数"),
		flagset.IntVarP(&option.RuntimeMaxRequests, "runtime-max-requests", "", 120, "运行时采集最大请求数"),
		flagset.StringVarP(&timeoutRaw, "timeout", "", "180", "Response timeout (s)"),
		flagset.StringVarP(&dialTimeoutRaw, "dial-timeout", "", "5", "Dial timeout (s)"),
		flagset.StringVarP(&option.Proxy, "proxy", "x", "", "HTTP proxy (e.g. http://localhost:8080)"),
		flagset.BoolVarP(&option.FollowRedirect, "follow-redirect", "f", false, "跟随重定向"),
		flagset.StringVarP(&option.RuleConfigPath, "rule-config", "r", "config/rules.yml", "规则配置文件"),
		flagset.StringVarP(&option.LogLevel, "log-level", "v", "info", "Log level (zero,debug,info,success,error)"),
		flagset.StringVarP(&option.LogFile, "log-file", "", "-", "Path to log file"),
		flagset.StringVarP(&headerSingle, "header", "H", "", "Custom header (e.g. 'X-My-Header: value')"),
		flagset.BoolVarP(&option.DisableColor, "disable-color", "", false, "disable log color"),
		flagset.BoolVarP(&option.DisableCheckAKSK, "disable-check-ak-sk", "", false, "禁止检查 AK/SK 有效性"),
		flagset.BoolVarP(&option.DisableCheckAKSKAlt, "dc", "", false, "禁止检查 AK/SK 有效性"),
	)

	flagset.CreateGroup("other", "其它参数",
		flagset.BoolVarP(&option.GenerateRule, "generate-rule", "G", false, "生成规则"),
		flagset.BoolVarP(&option.ShowVersion, "version", "", false, "显示版本"),
	)

	_ = flagset.Parse()
	outputFlagProvided := hasOutputFlag(os.Args[1:])

	if headerSingle != "" {
		option.HeaderRaw = append(option.HeaderRaw, headerSingle)
	}
	option.HeaderRaw = append(option.HeaderRaw, collectHeaderFlags(os.Args[1:])...)
	option.HeaderRaw = uniqueTrimmed(option.HeaderRaw)

	if option.Target != "" {
		target := strings.TrimSpace(option.Target)
		if looksLikeURL(target) {
			option.URL = target
		} else if util.FileExists(target) {
			option.FilePath = target
		} else {
			option.URL = target
		}
	}

	if option.Concurrency < 1 {
		option.Concurrency = 1
	}
	if option.ConcurrencyPerSite < 1 {
		option.ConcurrencyPerSite = 1
	}
	if option.MaxCollect < 1 {
		option.MaxCollect = 1
	}
	if option.LimitReaderSize < 1024 {
		option.LimitReaderSize = 1024
	}
	if option.RuntimeMaxPages < 1 {
		option.RuntimeMaxPages = 1
	}
	if option.RuntimeTimeoutSec < 1 {
		option.RuntimeTimeoutSec = 1
	}
	if option.RuntimeMaxActions < 1 {
		option.RuntimeMaxActions = 1
	}
	if option.RuntimeMaxRequests < 1 {
		option.RuntimeMaxRequests = 1
	}

	timeoutSec, err := parsePositiveFloat(timeoutRaw)
	if err != nil {
		fmt.Printf("timeout 参数错误: %v\n", err)
		return nil
	}
	dialTimeoutSec, err := parsePositiveFloat(dialTimeoutRaw)
	if err != nil {
		fmt.Printf("dial-timeout 参数错误: %v\n", err)
		return nil
	}
	option.OutputDir = normalizeOutputDir(option.OutputDir)
	if outputMode(option) == "csv" && !outputFlagProvided {
		option.OutputFilePath = "result.csv"
	}
	option.TimeOutSec = timeoutSec
	option.DialTimeOutSec = dialTimeoutSec

	if !(option.ShowVersion || option.GenerateRule) && option.URL == "" && option.FilePath == "" && option.JsonFilePath == "" {
		fmt.Println("请使用 -t 指定目标URL或目标文件")
		return nil
	}

	global.RulePath = strings.TrimSpace(option.RuleConfigPath)
	global.TimeOut = time.Duration(option.TimeOutSec * float64(time.Second))
	global.DialTimeOut = time.Duration(option.DialTimeOutSec * float64(time.Second))
	global.LimitReaderSize = int64(option.LimitReaderSize)
	global.MaxCollect = option.MaxCollect
	global.ConcurrencyPerSite = option.ConcurrencyPerSite
	global.RuntimeEnable = option.RuntimeEnable
	global.RuntimeDriver = strings.ToLower(strings.TrimSpace(option.RuntimeDriver))
	if global.RuntimeDriver == "" {
		global.RuntimeDriver = "playwright"
	}
	global.RuntimeCommand = strings.TrimSpace(option.RuntimeCommand)
	global.RuntimeTimeout = time.Duration(option.RuntimeTimeoutSec) * time.Second
	global.RuntimeMaxPages = option.RuntimeMaxPages
	global.RuntimeMaxActions = option.RuntimeMaxActions
	global.RuntimeMaxRequests = option.RuntimeMaxRequests
	global.FollowRedirect = option.FollowRedirect
	global.LogLevel = normalizeLogLevel(option.LogLevel)
	global.LogFile = strings.TrimSpace(option.LogFile)
	global.Debug = strings.EqualFold(global.LogLevel, "debug")
	global.DisableColor = option.DisableColor
	global.Headers = option.HeaderRaw
	global.OutputMode = outputMode(option)
	util.SetDefaultOutputRootDir(option.OutputDir)

	if err = global.RebuildTransport(option.Proxy); err != nil {
		fmt.Printf("proxy 参数错误: %v\n", err)
		return nil
	}

	return option
}

// outputMode 根据输出参数返回最终输出模式。
func outputMode(option *datatype.Option) string {
	if option.OutputJSON {
		return "json"
	}
	if option.OutputCSV {
		return "csv"
	}
	if option.OutputHTML {
		return "html"
	}
	if option.OutputMD {
		return "md"
	}
	return "text"
}

func normalizeOutputDir(path string) string {
	text := strings.TrimSpace(path)
	if text == "" || text == "-" {
		return "output"
	}
	return filepath.Clean(text)
}

// parsePositiveFloat 解析正浮点数。
func parsePositiveFloat(raw string) (float64, error) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, fmt.Errorf("必须大于 0")
	}
	return value, nil
}

// looksLikeURL 判断输入是否为 URL。
func looksLikeURL(target string) bool {
	low := strings.ToLower(strings.TrimSpace(target))
	return strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")
}

// normalizeLogLevel 规范化日志级别。
func normalizeLogLevel(level string) string {
	low := strings.ToLower(strings.TrimSpace(level))
	switch low {
	case "zero", "debug", "info", "success", "error":
		return low
	default:
		return "info"
	}
}

// uniqueTrimmed 对字符串切片做去空、去重。
func uniqueTrimmed(items []string) []string {
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{})
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
	return result
}

func hasOutputFlag(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case arg == "-o" || arg == "--output":
			return true
		case strings.HasPrefix(arg, "-o="):
			return true
		case strings.HasPrefix(arg, "--output="):
			return true
		}
	}
	return false
}

// collectHeaderFlags 兼容重复传入 -H/--header。
func collectHeaderFlags(args []string) []string {
	results := make([]string, 0)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-H" || arg == "--header":
			if i+1 < len(args) {
				results = append(results, args[i+1])
				i++
			}
		case strings.HasPrefix(arg, "-H="):
			results = append(results, strings.TrimPrefix(arg, "-H="))
		case strings.HasPrefix(arg, "--header="):
			results = append(results, strings.TrimPrefix(arg, "--header="))
		}
	}
	return results
}
