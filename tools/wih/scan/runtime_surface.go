package scan

import (
	datatype "wih/dataType"
	"wih/global"
)

// runtimeSurfaceResult 表示运行时参数采集结果。
type runtimeSurfaceResult struct {
	Endpoints  []datatype.EndpointRecord
	Parameters []datatype.ParameterRecord
}

// extractRuntimeSurface 为运行时 Hook MVP 预留统一接入口。
//
// 当前阶段先打通：
// - CLI 参数
// - 全局预算配置
// - 扫描主链路中的调用点
// - 结构化结果合流接口
//
// 这样后续真正接入浏览器运行时实现时，不需要再改一遍主链路和输出模型。
func extractRuntimeSurface(targetURL string) runtimeSurfaceResult {
	if !global.RuntimeEnable {
		return runtimeSurfaceResult{}
	}

	_ = targetURL
	_ = global.RuntimeMaxPages
	_ = global.RuntimeMaxActions
	_ = global.RuntimeMaxRequests

	return runtimeSurfaceResult{}
}
