package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strings"

	datatype "wih/dataType"
	"wih/global"
	"wih/util"
)

// runtimeSurfaceResult 表示运行时参数采集结果。
type runtimeSurfaceResult struct {
	Endpoints  []datatype.EndpointRecord
	Parameters []datatype.ParameterRecord
}

type runtimeSurfaceRequest struct {
	TargetURL      string            `json:"target_url"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty"`
	MaxPages       int               `json:"max_pages"`
	MaxActions     int               `json:"max_actions"`
	MaxRequests    int               `json:"max_requests"`
	FollowRedirect bool              `json:"follow_redirect"`
	TimeoutSec     int               `json:"timeout_sec"`
}

type runtimeSurfaceResponse struct {
	Endpoints  []datatype.EndpointRecord  `json:"endpoints"`
	Parameters []datatype.ParameterRecord `json:"parameters"`
}

// extractRuntimeSurface 为运行时 Hook MVP 提供统一接入口。
//
// 当前支持两种模式：
// - noop: 默认空实现，保持独立工具稳定
// - external: 调用外部命令，通过 stdin/stdout 交换 JSON
func extractRuntimeSurface(targetURL string) runtimeSurfaceResult {
	if !global.RuntimeEnable {
		return runtimeSurfaceResult{}
	}

	switch strings.ToLower(strings.TrimSpace(global.RuntimeDriver)) {
	case "", "noop":
		return runtimeSurfaceResult{}
	case "external":
		return extractRuntimeSurfaceByExternalDriver(targetURL)
	default:
		return runtimeSurfaceResult{}
	}
}

func extractRuntimeSurfaceByExternalDriver(targetURL string) runtimeSurfaceResult {
	commandText := strings.TrimSpace(global.RuntimeCommand)
	if commandText == "" {
		return runtimeSurfaceResult{}
	}

	timeoutSec := int(global.RuntimeTimeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 20
	}

	requestPayload := runtimeSurfaceRequest{
		TargetURL: targetURL,
		DefaultHeaders: map[string]string{
			"User-Agent": global.DefaultUserAgent,
			"Accept":     "application/json, text/plain, */*",
		},
		MaxPages:       global.RuntimeMaxPages,
		MaxActions:     global.RuntimeMaxActions,
		MaxRequests:    global.RuntimeMaxRequests,
		FollowRedirect: global.FollowRedirect,
		TimeoutSec:     timeoutSec,
	}

	requestBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return runtimeSurfaceResult{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), global.RuntimeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", commandText)
	cmd.Stdin = bytes.NewReader(requestBytes)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return runtimeSurfaceResult{}
	}

	return parseRuntimeSurfaceResponse(stdout.Bytes(), targetURL)
}

func parseRuntimeSurfaceResponse(raw []byte, targetURL string) runtimeSurfaceResult {
	if len(bytes.TrimSpace(raw)) == 0 {
		return runtimeSurfaceResult{}
	}

	resp := runtimeSurfaceResponse{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return runtimeSurfaceResult{}
	}

	targetParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || targetParsed.Host == "" {
		return runtimeSurfaceResult{}
	}
	targetHost := strings.ToLower(strings.TrimSpace(targetParsed.Hostname()))

	endpoints := make([]datatype.EndpointRecord, 0, len(resp.Endpoints))
	parameters := make([]datatype.ParameterRecord, 0, len(resp.Parameters))
	allowedEndpointIDs := make(map[string]struct{})

	for _, endpoint := range resp.Endpoints {
		normalizedEndpoint, ok := normalizeRuntimeEndpoint(endpoint, targetURL, targetHost)
		if !ok {
			continue
		}
		allowedEndpointIDs[normalizedEndpoint.EndpointID] = struct{}{}
		endpoints = append(endpoints, normalizedEndpoint)
	}

	for _, parameter := range resp.Parameters {
		if _, ok := allowedEndpointIDs[strings.TrimSpace(parameter.EndpointID)]; !ok {
			continue
		}
		parameters = append(parameters, enrichParameterMetadata(parameter))
	}

	return runtimeSurfaceResult{
		Endpoints:  mergeEndpointRecords(endpoints),
		Parameters: mergeParameterRecords(parameters),
	}
}

func normalizeRuntimeEndpoint(endpoint datatype.EndpointRecord, targetURL string, targetHost string) (datatype.EndpointRecord, bool) {
	urlText := strings.TrimSpace(endpoint.URL)
	if urlText == "" {
		return datatype.EndpointRecord{}, false
	}
	parsed, err := url.Parse(urlText)
	if err != nil || parsed.Host == "" {
		return datatype.EndpointRecord{}, false
	}
	if strings.ToLower(strings.TrimSpace(parsed.Hostname())) != targetHost {
		return datatype.EndpointRecord{}, false
	}

	methodText := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	if methodText == "" {
		methodText = "GET"
	}

	normalized := endpoint
	if strings.TrimSpace(normalized.EndpointID) == "" {
		normalized.EndpointID = fmt.Sprintf("%d", util.StableHash(strings.Join([]string{
			targetURL,
			methodText,
			parsed.String(),
		}, "|")))
	}
	normalized.URL = parsed.String()
	normalized.Path = firstNonEmpty(strings.TrimSpace(parsed.Path), "/")
	normalized.Method = methodText
	normalized.Protocol = firstNonEmpty(strings.TrimSpace(parsed.Scheme), "https")
	normalized.SourceTypes = uniqueSortedStrings(append(normalized.SourceTypes, "runtime_hook"))
	if strings.TrimSpace(normalized.TriggerContext.Event) == "" {
		normalized.TriggerContext.Event = "runtime_hook"
	}
	if normalized.Confidence <= 0 {
		normalized.Confidence = 0.93
	}
	return normalized, true
}
