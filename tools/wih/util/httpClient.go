package util

import (
	"net/http"
	"strings"
	"wih/global"
)

// NewClient 创建统一 HTTP 客户端。
func NewClient() *http.Client {
	client := &http.Client{
		Transport: global.Tr,
		Timeout:   global.TimeOut,
	}

	if !global.FollowRedirect {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// ApplyRequestHeaders 将全局配置头写入请求对象。
func ApplyRequestHeaders(req *http.Request) {
	if req == nil {
		return
	}

	req.Header.Set("User-Agent", global.DefaultUserAgent)
	for _, raw := range global.Headers {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		req.Header.Set(key, value)
	}
}
