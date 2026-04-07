package util

import (
	"net/http"
	"testing"
	"wih/global"
)

func TestApplyRequestHeadersForTargetIncludesWIHTarget(t *testing.T) {
	previousHeaders := global.Headers
	global.Headers = []string{"X-Custom-Header: demo"}
	defer func() { global.Headers = previousHeaders }()

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}

	ApplyRequestHeadersForTarget(req, "https://scan.example.com")

	if got := req.Header.Get("User-Agent"); got != global.DefaultUserAgent {
		t.Fatalf("unexpected user-agent: %s", got)
	}
	if got := req.Header.Get("X-Custom-Header"); got != "demo" {
		t.Fatalf("unexpected custom header: %s", got)
	}
	if got := req.Header.Get("X-WIH-Target"); got != "https://scan.example.com" {
		t.Fatalf("unexpected X-WIH-Target header: %s", got)
	}
}

func TestApplyRequestHeadersForTargetSkipsEmptyWIHTarget(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}

	ApplyRequestHeadersForTarget(req, "")

	if got := req.Header.Get("X-WIH-Target"); got != "" {
		t.Fatalf("unexpected X-WIH-Target header: %s", got)
	}
}
