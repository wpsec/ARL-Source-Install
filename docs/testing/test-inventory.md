# 自动化测试覆盖清单

本清单由 `python3 scripts/generate_test_inventory.py` 生成。API 行来自 Flask 已注册 Namespace 和 `@ns.route`；页面行来自前端模块注册表。

## 盘点基线

- Python 测试文件：194 个。
- Flask 已注册 Namespace：39 个；HTTP 操作：189 个。
- 前端测试文件：30 个；可见业务页面：37 个。
- 每个 API 操作都有路由注册及对应基础响应契约：受保护操作检查缺少 Token 的统一响应包络，公开登录/登出分别检查失败与成功响应；高风险业务行为由域级测试补充。

## API 操作

| 方法 | 路径 | Namespace | 资源 | 认证 | API 基础契约 | 源码 |
|---|---|---|---|---|---|---|
| GET | `/api/api_console/ai_config/` | `api_console` | `ApiConsoleAiConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5051` |
| POST | `/api/api_console/ai_config/` | `api_console` | `ApiConsoleAiConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5051` |
| POST | `/api/api_console/ai_config/reveal/` | `api_console` | `ApiConsoleAiConfigReveal` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5129` |
| POST | `/api/api_console/ai_config/sop/upload/` | `api_console` | `ApiConsoleAiConfigSopUpload` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5214` |
| POST | `/api/api_console/ai_config/test/` | `api_console` | `ApiConsoleAiConfigTest` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5180` |
| POST | `/api/api_console/ai_denoise/analyze/` | `api_console` | `ApiConsoleAiDenoiseAnalyze` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5564` |
| GET | `/api/api_console/ai_usage/logs/` | `api_console` | `ApiConsoleAiUsageLogs` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5490` |
| GET | `/api/api_console/ai_usage/stats/` | `api_console` | `ApiConsoleAiUsageStats` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5340` |
| GET | `/api/api_console/config/` | `api_console` | `ApiConsoleConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:4725` |
| POST | `/api/api_console/config/` | `api_console` | `ApiConsoleConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:4725` |
| GET | `/api/api_console/scan_config/` | `api_console` | `ApiConsoleScanConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5654` |
| POST | `/api/api_console/scan_config/` | `api_console` | `ApiConsoleScanConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5654` |
| POST | `/api/api_console/scan_config/afrog_poc/update/` | `api_console` | `ApiConsoleAfrogPocUpdate` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5772` |
| POST | `/api/api_console/scan_config/domain_dict/upload/` | `api_console` | `ApiConsoleDomainDictUpload` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5809` |
| POST | `/api/api_console/scan_config/file_leak_dict/upload/` | `api_console` | `ApiConsoleFileLeakDictUpload` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5864` |
| POST | `/api/api_console/scan_config/nuclei_poc/update/` | `api_console` | `ApiConsoleNucleiPocUpdate` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5735` |
| POST | `/api/api_console/sensitive_verify/` | `api_console` | `ApiConsoleSensitiveVerify` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:5622` |
| GET | `/api/api_console/service_api/` | `api_console` | `ApiConsoleServiceApi` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:4797` |
| POST | `/api/api_console/service_api/` | `api_console` | `ApiConsoleServiceApi` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:4797` |
| POST | `/api/api_console/service_api/reveal/` | `api_console` | `ApiConsoleServiceApiReveal` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:4871` |
| POST | `/api/api_console/service_api/test/` | `api_console` | `ApiConsoleServiceApiTest` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:4920` |
| POST | `/api/api_console/service_api/test_batch/` | `api_console` | `ApiConsoleServiceApiBatchTest` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/api_console.py:4970` |
| GET | `/api/asset_domain/` | `asset_domain` | `ARLAssetDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetDomain.py:54` |
| POST | `/api/asset_domain/` | `asset_domain` | `ARLAssetDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetDomain.py:54` |
| POST | `/api/asset_domain/delete/` | `asset_domain` | `DeleteARLAssetDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetDomain.py:235` |
| GET | `/api/asset_domain/export/` | `asset_domain` | `ARLAssetDomainExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetDomain.py:269` |
| GET | `/api/asset_ip/` | `asset_ip` | `ARLAssetIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetIP.py:50` |
| POST | `/api/asset_ip/delete/` | `asset_ip` | `DeleteARLAssetIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetIP.py:208` |
| GET | `/api/asset_ip/export/` | `asset_ip` | `ARLAssetIPExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetIP.py:115` |
| GET | `/api/asset_ip/export_domain/` | `asset_ip` | `ARLIPExportDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetIP.py:173` |
| GET | `/api/asset_ip/export_ip/` | `asset_ip` | `ARLIPExportIp` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetIP.py:144` |
| GET | `/api/asset_scope/` | `asset_scope` | `ARLAssetScope` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetScope.py:93` |
| POST | `/api/asset_scope/` | `asset_scope` | `ARLAssetScope` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetScope.py:93` |
| POST | `/api/asset_scope/add/` | `asset_scope` | `AddARLAssetScope` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetScope.py:328` |
| DELETE | `/api/asset_scope/delete/` | `asset_scope` | `DeleteARLAssetScope` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetScope.py:208` |
| POST | `/api/asset_scope/delete/` | `asset_scope` | `DeleteARLAssetScope` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetScope.py:208` |
| GET | `/api/asset_scope/export/` | `asset_scope` | `ARLAssetScopeExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetScope.py:478` |
| POST | `/api/asset_scope/update/` | `asset_scope` | `UpdateARLAssetScope` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetScope.py:424` |
| GET | `/api/asset_site/` | `asset_site` | `ARLAssetSite` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetSite.py:66` |
| POST | `/api/asset_site/` | `asset_site` | `ARLAssetSite` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetSite.py:66` |
| POST | `/api/asset_site/add_tag/` | `asset_site` | `AddAssetSiteTagARL` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetSite.py:395` |
| POST | `/api/asset_site/delete/` | `asset_site` | `DeleteARLAssetSite` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetSite.py:292` |
| POST | `/api/asset_site/delete_tag/` | `asset_site` | `DeleteAssetSiteTagARL` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetSite.py:463` |
| GET | `/api/asset_site/export/` | `asset_site` | `ARLSiteExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetSite.py:212` |
| GET | `/api/asset_site/save_result_set/` | `asset_site` | `ARLSaveResultSet` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetSite.py:330` |
| GET | `/api/asset_wih/` | `asset_wih` | `ARLAssetWebInfoHunter` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetWih.py:49` |
| GET | `/api/asset_wih/export/` | `asset_wih` | `ARLAssetWIHExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/assetWih.py:106` |
| POST | `/api/batch_export/asset_domain/` | `batch_export` | `BatchExportAssetIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:300` |
| POST | `/api/batch_export/asset_ip/` | `batch_export` | `BatchExportAssetIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:269` |
| POST | `/api/batch_export/asset_site/` | `batch_export` | `BatchExportAssetIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:331` |
| POST | `/api/batch_export/asset_wih/` | `batch_export` | `BatchExportAssetWIH` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:362` |
| POST | `/api/batch_export/cip/` | `batch_export` | `BatchExportCIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:231` |
| POST | `/api/batch_export/domain/` | `batch_export` | `BatchExportDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:65` |
| POST | `/api/batch_export/fileleak/` | `batch_export` | `BatchExportFileLeak` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:158` |
| POST | `/api/batch_export/ip/` | `batch_export` | `BatchExportIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:96` |
| POST | `/api/batch_export/ip_port/` | `batch_export` | `BatchExportIpPort` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:184` |
| POST | `/api/batch_export/site/` | `batch_export` | `BatchExportSite` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:35` |
| POST | `/api/batch_export/url/` | `batch_export` | `BatchExportURL` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/batchExport.py:127` |
| GET | `/api/cert/` | `cert` | `ARLCert` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/cert.py:86` |
| POST | `/api/cert/delete/` | `cert` | `DeleteARLCert` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/cert.py:228` |
| GET | `/api/cip/` | `cip` | `ARLCIPList` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/cip.py:34` |
| GET | `/api/cip/export/` | `cip` | `ARLCIPExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/cip.py:79` |
| GET | `/api/console/dashboard` | `console` | `ARLConsoleDashboard` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/console.py:1001` |
| GET | `/api/console/info` | `console` | `ARLConsole` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/console.py:986` |
| GET | `/api/console/queue_metrics` | `console` | `ARLConsoleQueueMetrics` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/console.py:1081` |
| GET | `/api/console/recent_logs` | `console` | `ARLConsoleRecentLogs` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/console.py:1090` |
| GET | `/api/console/system_monitor/` | `console` | `ARLConsoleSystemMonitor` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/console.py:1110` |
| GET | `/api/dingtalk_api/config/` | `dingtalk_api` | `DingtalkApiConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:420` |
| POST | `/api/dingtalk_api/config/` | `dingtalk_api` | `DingtalkApiConfig` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:420` |
| POST | `/api/dingtalk_api/create_workbook/` | `dingtalk_api` | `DingtalkApiCreateWorkbook` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:587` |
| POST | `/api/dingtalk_api/nodes/` | `dingtalk_api` | `DingtalkApiNodes` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:567` |
| POST | `/api/dingtalk_api/reveal/` | `dingtalk_api` | `DingtalkApiReveal` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:487` |
| POST | `/api/dingtalk_api/sheets/` | `dingtalk_api` | `DingtalkApiWorkbookSheets` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:610` |
| POST | `/api/dingtalk_api/test/` | `dingtalk_api` | `DingtalkApiTest` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:531` |
| POST | `/api/dingtalk_api/workspaces/` | `dingtalk_api` | `DingtalkApiWorkspaces` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:550` |
| POST | `/api/dingtalk_api/write_markdown/` | `dingtalk_api` | `DingtalkApiWriteWorkbookMarkdown` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/dingtalk_api.py:631` |
| GET | `/api/domain/` | `domain` | `ARLDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/domain.py:55` |
| POST | `/api/domain/delete/` | `domain` | `DeleteARLDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/domain.py:125` |
| GET | `/api/domain/export/` | `domain` | `ARLDomainExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/domain.py:90` |
| GET | `/api/export/<string:task_id>` | `export` | `ARLExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/export.py:1731` |
| POST | `/api/export/batch` | `export` | `ARLBatchExcel` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/export.py:1786` |
| POST | `/api/export/job` | `export` | `ARLExportJobCreate` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/export.py:1859` |
| GET | `/api/export/job/<string:job_id>` | `export` | `ARLExportJobStatus` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/export.py:1896` |
| GET | `/api/export/job/<string:job_id>/download` | `export` | `ARLExportJobDownload` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/export.py:1932` |
| GET | `/api/fileleak/` | `fileleak` | `ARLFileLeak` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fileleak.py:51` |
| POST | `/api/fileleak/delete/` | `fileleak` | `DeleteARLFileleak` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fileleak.py:142` |
| GET | `/api/fileleak/export/` | `fileleak` | `ARLFileLeakExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fileleak.py:110` |
| GET | `/api/fingerprint/` | `fingerprint` | `ARLFingerprint` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fingerprint.py:62` |
| POST | `/api/fingerprint/` | `fingerprint` | `ARLFingerprint` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fingerprint.py:62` |
| POST | `/api/fingerprint/delete/` | `fingerprint` | `DeleteARLFinger` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fingerprint.py:117` |
| GET | `/api/fingerprint/export/` | `fingerprint` | `ExportARLFinger` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fingerprint.py:136` |
| POST | `/api/fingerprint/upload/` | `fingerprint` | `UploadARLFinger` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/fingerprint.py:170` |
| GET | `/api/github_monitor_result/` | `github_monitor_result` | `ARLGithubMonitorResult` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_monitor_result.py:42` |
| GET | `/api/github_result/` | `github_result` | `ARLGithubResult` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_result.py:47` |
| GET | `/api/github_scheduler/` | `github_scheduler` | `ARLGithubScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_scheduler.py:61` |
| POST | `/api/github_scheduler/` | `github_scheduler` | `ARLGithubScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_scheduler.py:61` |
| POST | `/api/github_scheduler/delete/` | `github_scheduler` | `DeleteGithubScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_scheduler.py:181` |
| POST | `/api/github_scheduler/recover/` | `github_scheduler` | `RecoverGithubScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_scheduler.py:276` |
| POST | `/api/github_scheduler/stop/` | `github_scheduler` | `StopGithubScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_scheduler.py:308` |
| POST | `/api/github_scheduler/update/` | `github_scheduler` | `UpdateGithubScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_scheduler.py:217` |
| GET | `/api/github_task/` | `github_task` | `ARLGithubTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_task.py:55` |
| POST | `/api/github_task/` | `github_task` | `ARLGithubTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_task.py:55` |
| POST | `/api/github_task/delete/` | `github_task` | `DeleteARLGithubTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_task.py:153` |
| POST | `/api/github_task/stop/` | `github_task` | `StopARLGithubTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/github_task.py:185` |
| GET | `/api/icp/about` | `icp` | `IcpAbout` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:405` |
| GET | `/api/icp/batch` | `icp` | `IcpBatchCreate` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:194` |
| POST | `/api/icp/batch` | `icp` | `IcpBatchCreate` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:194` |
| DELETE | `/api/icp/batch/<string:task_id>` | `icp` | `IcpBatchDetail` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:233` |
| GET | `/api/icp/batch/<string:task_id>` | `icp` | `IcpBatchDetail` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:233` |
| POST | `/api/icp/batch/<string:task_id>/cancel` | `icp` | `IcpBatchCancel` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:264` |
| GET | `/api/icp/export` | `icp` | `IcpExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:380` |
| GET | `/api/icp/history` | `icp` | `IcpHistoryList` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:285` |
| DELETE | `/api/icp/history/<string:history_id>` | `icp` | `IcpHistoryDetail` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:307` |
| GET | `/api/icp/history/<string:history_id>` | `icp` | `IcpHistoryDetail` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:307` |
| POST | `/api/icp/history/clear` | `icp` | `IcpHistoryClear` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:338` |
| GET | `/api/icp/logs` | `icp` | `IcpLogs` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:349` |
| POST | `/api/icp/logs/clear` | `icp` | `IcpLogsClear` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:369` |
| GET | `/api/icp/meta` | `icp` | `IcpMeta` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:85` |
| POST | `/api/icp/query` | `icp` | `IcpQueryCreate` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:100` |
| GET | `/api/icp/query/<string:task_id>` | `icp` | `IcpQueryStatus` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:129` |
| POST | `/api/icp/query/<string:task_id>/cancel` | `icp` | `IcpQueryCancel` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:173` |
| GET | `/api/icp/query/<string:task_id>/results` | `icp` | `IcpQueryResults` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/icp_query.py:143` |
| GET | `/api/image/<string:task_id>/<string:file_name>` | `image` | `ARLImage` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/image.py:84` |
| POST | `/api/image/internal/upload` | `image` | `ARLImageInternalUpload` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/image.py:155` |
| GET | `/api/ip/` | `ip` | `ARLIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/ip.py:65` |
| POST | `/api/ip/delete/` | `ip` | `DeleteARLIP` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/ip.py:198` |
| GET | `/api/ip/export/` | `ip` | `ARLIPExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/ip.py:104` |
| GET | `/api/ip/export_domain/` | `ip` | `ARLIPExportDomain` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/ip.py:135` |
| GET | `/api/ip/export_ip/` | `ip` | `ARLIPExportIp` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/ip.py:162` |
| GET | `/api/npoc_service/` | `npoc_service` | `NpocService` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/npoc_service.py:43` |
| GET | `/api/nuclei_result/` | `nuclei_result` | `ARLUrl` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/nuclei_result.py:548` |
| POST | `/api/nuclei_result/delete/` | `nuclei_result` | `DeleteNucleiResult` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/nuclei_result.py:626` |
| GET | `/api/poc/` | `poc` | `ARLPoC` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/poc.py:92` |
| POST | `/api/poc/delete/` | `poc` | `ARLPoCDelete` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/poc.py:320` |
| GET | `/api/poc/names/` | `poc` | `ARLPoCNames` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/poc.py:152` |
| POST | `/api/poc/sync/` | `poc` | `ARLPoCSync` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/poc.py:199` |
| GET | `/api/poc/sync/<string:job_id>/` | `poc` | `ARLPoCSyncStatus` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/poc.py:297` |
| GET | `/api/policy/` | `policy` | `ARLPolicy` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/policy.py:40` |
| POST | `/api/policy/add/` | `policy` | `AddARLPolicy` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/policy.py:202` |
| POST | `/api/policy/delete/` | `policy` | `DeletePolicy` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/policy.py:451` |
| POST | `/api/policy/edit/` | `policy` | `EditPolicy` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/policy.py:501` |
| GET | `/api/scheduler/` | `scheduler` | `ARLScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:51` |
| POST | `/api/scheduler/add/` | `scheduler` | `AddARLScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:114` |
| POST | `/api/scheduler/add/site_monitor/` | `scheduler` | `AddSiteScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:566` |
| POST | `/api/scheduler/add/wih_monitor/` | `scheduler` | `AddWihScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:637` |
| POST | `/api/scheduler/delete/` | `scheduler` | `DeleteARLScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:263` |
| POST | `/api/scheduler/recover/` | `scheduler` | `RecoverARLScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:342` |
| POST | `/api/scheduler/recover/batch` | `scheduler` | `BatchRecoverARLScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:399` |
| POST | `/api/scheduler/stop/` | `scheduler` | `StopARLScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:453` |
| POST | `/api/scheduler/stop/batch` | `scheduler` | `BatchStopARLScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/scheduler.py:510` |
| GET | `/api/service/` | `service` | `ARLService` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/service.py:230` |
| GET | `/api/site/` | `site` | `ARLSite` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/site.py:122` |
| POST | `/api/site/add_tag/` | `site` | `AddSiteTagARL` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/site.py:267` |
| POST | `/api/site/delete/` | `site` | `DeleteARLSite` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/site.py:388` |
| POST | `/api/site/delete_tag/` | `site` | `DeleteSiteTagARL` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/site.py:328` |
| GET | `/api/site/export/` | `site` | `ARLSiteExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/site.py:174` |
| GET | `/api/site/save_result_set/` | `site` | `ARLSaveResultSet` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/site.py:202` |
| GET | `/api/stat_finger/` | `stat_finger` | `ARLStatFingerprint` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/stat_finger.py:39` |
| GET | `/api/task/` | `task` | `ARLTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:175` |
| POST | `/api/task/` | `task` | `ARLTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:175` |
| POST | `/api/task/batch_stop/` | `task` | `BatchStopTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:359` |
| POST | `/api/task/delete/` | `task` | `DeleteTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:497` |
| POST | `/api/task/policy/` | `task` | `TaskByPolicy` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:719` |
| POST | `/api/task/restart/` | `task` | `TaskRestart` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:846` |
| POST | `/api/task/stop/` | `task` | `StopTaskCompat` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:396` |
| GET | `/api/task/stop/<string:task_id>` | `task` | `StopTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:424` |
| POST | `/api/task/sync/` | `task` | `SyncTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:558` |
| GET | `/api/task/sync_scope/` | `task` | `Target2Scope` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task.py:652` |
| POST | `/api/task_fofa/submit` | `task_fofa` | `AddMeasureTask` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/taskFofa.py:108` |
| POST | `/api/task_fofa/test` | `task_fofa` | `TaskMeasureTest` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/taskFofa.py:80` |
| GET | `/api/task_schedule/` | `task_schedule` | `ARLTaskScheduleResult` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task_schedule.py:95` |
| POST | `/api/task_schedule/` | `task_schedule` | `ARLTaskScheduleResult` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task_schedule.py:95` |
| POST | `/api/task_schedule/delete/` | `task_schedule` | `DeleteARLTaskScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task_schedule.py:243` |
| POST | `/api/task_schedule/recover/` | `task_schedule` | `RecoverARLTaskScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task_schedule.py:321` |
| POST | `/api/task_schedule/stop/` | `task_schedule` | `StopARLTaskScheduler` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/task_schedule.py:273` |
| GET | `/api/url/` | `url` | `ARLUrl` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/url.py:38` |
| GET | `/api/url/export/` | `url` | `ARLUrlExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/url.py:86` |
| POST | `/api/user/change_pass` | `user` | `ChangePassARL` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/user.py:114` |
| POST | `/api/user/login` | `user` | `LoginARL` | 公开（显式 allowlist） | 注册 + 错误登录响应 | `ARL/app/routes/user.py:34` |
| GET | `/api/user/logout` | `user` | `LogoutARL` | 公开（显式 allowlist） | 注册 + 登出成功响应包络 | `ARL/app/routes/user.py:78` |
| GET | `/api/vuln/` | `vuln` | `ARLUrl` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/vuln.py:43` |
| POST | `/api/vuln/delete/` | `vuln` | `DeleteARLVuln` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/vuln.py:106` |
| GET | `/api/waf_host/` | `waf_host` | `ARLWafHost` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/waf_host.py:120` |
| GET | `/api/wih/` | `wih` | `ARLWebInfoHunter` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/wih.py:58` |
| GET | `/api/wih/export/` | `wih` | `ARLWihExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/wih.py:186` |
| GET | `/api/wih/stat/` | `wih` | `ARLWebInfoHunterStat` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/wih.py:115` |
| GET | `/api/wih_endpoint/` | `wih_endpoint` | `ARLWihEndpoint` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/wih_endpoint.py:34` |
| POST | `/api/wih_endpoint/delete/` | `wih_endpoint` | `DeleteARLWihEndpoint` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/wih_endpoint.py:66` |
| GET | `/api/wih_endpoint/export/` | `wih_endpoint` | `ARLWihEndpointExport` | Token | 注册 + 缺 Token 响应包络 | `ARL/app/routes/wih_endpoint.py:47` |

## 前端业务页面

| 页面 ID | 名称 | 直接访问路径 | 基础覆盖 |
|---|---|---|---|
| `dashboard` | 我的仪表盘 | `/dashboard` | Vitest 路由注册；Playwright 页面 smoke |
| `system_monitor` | 系统监控 | `/modules/system-monitor` | Vitest 路由注册；Playwright 页面 smoke |
| `icp_query` | ICP 查询 | `/modules/icp-query` | Vitest 路由注册；Playwright 页面 smoke |
| `task` | 任务管理 | `/modules/task` | Vitest 路由注册；Playwright 页面 smoke |
| `task_schedule` | 计划任务 | `/modules/task-schedule` | Vitest 路由注册；Playwright 页面 smoke |
| `scheduler` | 资产监控 | `/modules/scheduler` | Vitest 路由注册；Playwright 页面 smoke |
| `policy` | 策略配置 | `/modules/policy` | Vitest 路由注册；Playwright 页面 smoke |
| `asset_scope` | 资产分组 | `/modules/asset-scope` | Vitest 路由注册；Playwright 页面 smoke |
| `asset_domain` | 资产域名 | `/modules/asset-domain` | Vitest 路由注册；Playwright 页面 smoke |
| `asset_site` | 资产站点 | `/modules/asset-site` | Vitest 路由注册；Playwright 页面 smoke |
| `asset_ip` | 资产IP | `/modules/asset-ip` | Vitest 路由注册；Playwright 页面 smoke |
| `asset_wih` | 资产WIH | `/modules/asset-wih` | Vitest 路由注册；Playwright 页面 smoke |
| `site` | 站点 | `/modules/site` | Vitest 路由注册；Playwright 页面 smoke |
| `domain` | 子域名 | `/modules/domain` | Vitest 路由注册；Playwright 页面 smoke |
| `ip` | IP | `/modules/ip` | Vitest 路由注册；Playwright 页面 smoke |
| `url` | URL信息 | `/modules/url` | Vitest 路由注册；Playwright 页面 smoke |
| `cert` | SSL证书 | `/modules/cert` | Vitest 路由注册；Playwright 页面 smoke |
| `service` | 服务 | `/modules/service` | Vitest 路由注册；Playwright 页面 smoke |
| `npoc_service` | C段 | `/modules/npoc-service` | Vitest 路由注册；Playwright 页面 smoke |
| `cip` | C段 | `/modules/cip` | Vitest 路由注册；Playwright 页面 smoke |
| `vuln` | 风险 | `/modules/vuln` | Vitest 路由注册；Playwright 页面 smoke |
| `nuclei_result` | PoC风险 | `/modules/nuclei-result` | Vitest 路由注册；Playwright 页面 smoke |
| `fileleak` | 目录扫描 | `/modules/fileleak` | Vitest 路由注册；Playwright 页面 smoke |
| `wih` | WIH | `/modules/wih` | Vitest 路由注册；Playwright 页面 smoke |
| `wih_endpoint` | WIH接口提取 | `/modules/wih-endpoint` | Vitest 路由注册；Playwright 页面 smoke |
| `waf_host` | WAF识别 | `/modules/waf-host` | Vitest 路由注册；Playwright 页面 smoke |
| `poc` | PoC管理 | `/modules/poc` | Vitest 路由注册；Playwright 页面 smoke |
| `fingerprint` | 指纹规则 | `/modules/fingerprint` | Vitest 路由注册；Playwright 页面 smoke |
| `github_task` | GitHub任务 | `/modules/github-task` | Vitest 路由注册；Playwright 页面 smoke |
| `github_result` | GitHub结果 | `/modules/github-result` | Vitest 路由注册；Playwright 页面 smoke |
| `github_scheduler` | GitHub监控 | `/modules/github-scheduler` | Vitest 路由注册；Playwright 页面 smoke |
| `github_monitor_result` | GitHub监控结果 | `/modules/github-monitor-result` | Vitest 路由注册；Playwright 页面 smoke |
| `task_fofa` | 测绘任务 | `/modules/task-fofa` | Vitest 路由注册；Playwright 页面 smoke |
| `dingtalk_api` | 钉钉集成 | `/modules/dingtalk-api` | Vitest 路由注册；Playwright 页面 smoke |
| `api_console` | API管理 | `/modules/api-console` | Vitest 路由注册；Playwright 页面 smoke |
| `config_console` | 配置管理 | `/modules/config-console` | Vitest 路由注册；Playwright 页面 smoke |
| `ai_console` | AI管理 | `/modules/ai-console` | Vitest 路由注册；Playwright 页面 smoke |

## 高风险业务域覆盖映射

此表列出业务域的主要单测/API 合同测试。它说明测试范围，不代表列出的每个用例都会访问生产 provider；真实扫描、真实 provider 和生产数据均不在自动化测试范围。

| 业务域 | 主要测试文件 | 覆盖边界 |
|---|---|---|
| 任务与用户权限 | `test_high_risk_api_contracts.py`, `test_task_repository.py`, `test_task_pipeline.py`, `test_task_terminal_status_mapping.py`, `test_semantics_and_recovery.py`, `test_legacy_owner_migration.py` | 任务创建/所有者归属、IDOR、状态恢复、历史所有者兼容；系统测试另验证 worker 与 API 的真实隔离闭环。 |
| 资产与范围 | `test_high_risk_api_contracts.py`, `test_asset_scope.py`, `test_asset_site_update.py`, `test_asset_site_monitor.py`, `test_asset_wih_monitor.py`, `test_asset_wih_task.py` | 范围输入校验、删除目标、资产同步及监控逻辑；provider 和扫描命令使用 mock/fixture。 |
| 风险与验证 | `test_high_risk_api_contracts.py`, `test_risk_cruising.py`, `test_nuclei_result_verify.py`, `test_controlled_verification_policy.py` | 风险记录删除边界、风险巡检、验证策略和结果处理。 |
| 策略与计划任务 | `test_high_risk_api_contracts.py`, `test_policy_edit.py`, `test_scheduler.py`, `test_task_schedule_query_args.py`, `test_wih_adaptive_scheduler.py` | 策略字段收敛、计划任务输入/持久化 ID、查询过滤与调度逻辑。 |
| 导出 | `test_high_risk_api_contracts.py`, `test_batch_export.py`, `test_export_repository.py`, `test_waf_export.py` | 跨用户任务导出拒绝、批量导出、仓储分页和结果组装。 |
| ICP | `test_icp_query_routes.py`, `test_icp_query.py`, `test_icp_fixtures.py`, `test_icp_config_templates.py` | 路由认证/错误脱敏、输入校验、固定 provider 响应、任务生命周期、取消/导出及历史清理；不访问真实 provider。 |
| 配置与集成 | `test_high_risk_api_contracts.py`, `test_config_domain_service.py`, `test_config_file_store.py`, `test_scan_config_service.py`, `test_service_api_config_service.py`, `test_ai_config_service.py`, `test_dingtalk_api_sensitive.py` | 配置校验、原子持久化、脱敏字段保护及敏感值 reveal 边界；外部服务调用使用 mock。 |
| GitHub 任务 | `test_high_risk_api_contracts.py`, `test_github_task.py`, `test_github_search.py`, `test_github_cron.py` | 输入校验、固定队列适配、搜索和周期任务逻辑；不访问 GitHub。 |
| 系统监控 | `test_system_monitor_processes.py`, `test_console_dashboard_trend.py`, `test_api_route_contract_inventory.py` | 容器进程快照、过期数据聚合、趋势逻辑及接口认证；不读取宿主机生产状态。 |

## 端到端工作流

| 工作流 | 覆盖方式 |
|---|---|
| 登录、深层链接返回、导航、刷新、浏览器历史 | Playwright 固定 API fixture |
| 任务名筛选、同名任务查看、Task ID 与详情 tab 绑定 | Vitest 组件测试与 Playwright 固定 fixture |
| 真实 API 创建任务、隔离 worker 执行、任务列表/详情/异常对话框查看 | Playwright 通过本地端口代理到隔离 Compose API；固定 Celery 测试任务 |
| 查询/分页/筛选 URL 恢复、主题、窄屏无溢出 | Vitest 路由测试与 Playwright 固定 fixture |
| API 路由注册及受保护接口缺少 Token 的响应 | Flask 测试客户端逐操作检查 |
| 高风险任务/用户/资产/风险/策略/计划任务/导出/配置/GitHub API 的输入、权限和副作用合同 | `test_high_risk_api_contracts.py`，扫描队列与外部 provider 使用 mock |
| RabbitMQ 投递/重试/撤销/重试耗尽、worker 重启、Mongo 状态落库、Redis 数据隔离 | 隔离 Compose 系统测试 |
| 外部 provider / 扫描器真实网络行为 | 默认排除；通过固定响应测试 ARL 适配层 |
