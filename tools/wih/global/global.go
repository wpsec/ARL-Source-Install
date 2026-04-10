package global

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	datatype "wih/dataType"
)

// DefaultUserAgent 为扫描请求默认 UA。
const DefaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

// 全局运行配置与共享状态。
var (
	// Version 为 wih 当前版本号。
	Version = "1.2.1"

	// RulePath 为规则配置路径。
	RulePath = "config/rules.yml"

	// TimeOut 为请求总超时。
	TimeOut = 180 * time.Second
	// DialTimeOut 为连接建立超时。
	DialTimeOut = 5 * time.Second

	// LimitReaderSize 为单个响应体最大读取字节数。
	LimitReaderSize int64 = 10 * 1024 * 1024
	// MaxCollect 为单站点最大收集数量。
	MaxCollect = 600
	// MaxJSFiles 为单站点最多提取并抓取的 JS 数量。
	MaxJSFiles = 30
	// ConcurrencyPerSite 为单站点 JS 抓取并发。
	ConcurrencyPerSite = 3
	// RuntimeEnable 控制是否启用运行时参数采集骨架。
	RuntimeEnable = true
	// RuntimeDriver 控制运行时采集驱动类型。
	RuntimeDriver = "playwright"
	// RuntimeCommand 为 external 驱动执行命令。
	RuntimeCommand = ""
	// RuntimeTimeout 控制运行时采集超时。
	RuntimeTimeout = 60 * time.Second
	// RuntimeMaxPages 控制运行时探索页面预算。
	RuntimeMaxPages = 12
	// RuntimeMaxActions 控制运行时交互预算。
	RuntimeMaxActions = 32
	// RuntimeMaxRequests 控制运行时请求采集预算。
	RuntimeMaxRequests = 180

	// FollowRedirect 控制是否跟随重定向。
	FollowRedirect = false
	// Headers 为用户自定义请求头。
	Headers = make([]string, 0)
	// ProxyURL 为当前生效的代理地址。
	ProxyURL = ""

	// LogLevel 支持：zero/debug/info/success/error。
	LogLevel = "info"
	// LogFile 为日志落盘路径，"-" 表示不落盘。
	LogFile = "-"
	// Debug 控制调试日志输出。
	Debug = false
	// DisableColor 控制终端彩色输出。
	DisableColor = false

	// OutputMode 支持：json/text/csv/html/md。
	OutputMode = "text"

	// RuleWIH 为加载后的规则配置。
	RuleWIH *datatype.WIH

	transportLock sync.Mutex
	// Tr 为全局复用 HTTP Transport。
	Tr = newTransport("")
)

// RebuildTransport 按当前全局配置重建 Transport。
func RebuildTransport(proxyRaw string) error {
	transportLock.Lock()
	defer transportLock.Unlock()

	proxyRaw = strings.TrimSpace(proxyRaw)
	ProxyURL = proxyRaw
	if proxyRaw == "" {
		Tr = newTransport("")
		return nil
	}

	proxyURL, err := url.Parse(proxyRaw)
	if err != nil {
		return err
	}
	Tr = newTransport(proxyURL.String())
	return nil
}

// newTransport 创建高复用低开销的 HTTP Transport。
func newTransport(proxyRaw string) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   DialTimeOut,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DialContext:           dialer.DialContext,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw != "" {
		if proxyURL, err := url.Parse(proxyRaw); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return transport
}
