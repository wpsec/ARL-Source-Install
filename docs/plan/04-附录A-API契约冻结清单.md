# 04 附录A · API 契约冻结清单（Step 1 取证，UI 重构期间只读）

- 生成命令：`python3 scripts/freeze-api-contract.py`（本文件即脚本输出，禁止手改；代码变更后重跑刷新）
- 基线 rev：`3540385c`，生成时间：2026-09-04 17:58:50
- 规模：154 端点 / 38 命名空间；UI 消费端点 135 条；modules 配置 37 页


## 冻结规则

1. 本清单是 UI 重构（Phase 0-4）期间的行为基准：重构只允许改渲染与请求组织方式，**端点路径、方法、请求参数、响应字段、状态枚举、导出下载行为不得变化**。
2. 列表接口标准信封（`ARLResource.build_data` → `collection_query_service.build_collection_data`）：
   `{ page, size, total, items, query, code: 200 }`；缓存受 `API_LIST_CACHE_EXPIRE` 控制，`_refresh=1` 强制穿透。
3. 认证：请求头 `Token: <token>`（flask_restx ApiKeyAuth），失败 401。
4. 任务状态枚举：`waiting/running/done/stop/error`；任务类型：`domain/ip/risk_cruising/fofa/asset_site_add` 等。
5. 若后端契约确需变更，必须先改本清单来源（代码）并重跑脚本，再改 UI——顺序不可反。

## UI 消费的端点全表（requestApi/listPath/exportPath/action.path 去重）

说明：`/api` 前缀由前端 `API_BASE` 统一拼接；`<img>` 直连资源（截图 `/image/{task_id}/{path}`）不经 requestApi，但同样属冻结面。

| 端点 |
|---|
| `/api_console/ai_config/` |
| `/api_console/ai_config/reveal/` |
| `/api_console/ai_config/sop/upload/` |
| `/api_console/ai_config/test/` |
| `/api_console/ai_denoise/analyze/` |
| `/api_console/ai_usage/logs/` |
| `/api_console/ai_usage/stats/` |
| `/api_console/scan_config/` |
| `/api_console/scan_config/domain_dict/upload/` |
| `/api_console/scan_config/file_leak_dict/upload/` |
| `/api_console/service_api/` |
| `/api_console/service_api/reveal/` |
| `/api_console/service_api/test/` |
| `/api_console/service_api/test_batch/` |
| `/asset_domain/` |
| `/asset_domain/delete/` |
| `/asset_domain/export/` |
| `/asset_ip/` |
| `/asset_ip/delete/` |
| `/asset_ip/export/` |
| `/asset_scope/` |
| `/asset_scope/add/` |
| `/asset_scope/delete/` |
| `/asset_scope/export/` |
| `/asset_scope/update/` |
| `/asset_site/` |
| `/asset_site/delete/` |
| `/asset_site/export/` |
| `/asset_site/save_result_set/` |
| `/asset_wih/` |
| `/asset_wih/export/` |
| `/batch_export/cip/` |
| `/batch_export/domain/` |
| `/batch_export/fileleak/` |
| `/batch_export/ip/` |
| `/batch_export/ip_port/` |
| `/batch_export/site/` |
| `/batch_export/url/` |
| `/cert/` |
| `/cert/delete/` |
| `/cip/` |
| `/cip/export/` |
| `/console/dashboard` |
| `/console/info` |
| `/console/recent_logs` |
| `/console/system_monitor/` |
| `/dingtalk_api/config/` |
| `/dingtalk_api/create_workbook/` |
| `/dingtalk_api/nodes/` |
| `/dingtalk_api/reveal/` |
| `/dingtalk_api/sheets/` |
| `/dingtalk_api/test/` |
| `/dingtalk_api/workspaces/` |
| `/dingtalk_api/write_markdown/` |
| `/domain/` |
| `/domain/delete/` |
| `/domain/export/` |
| `/export/batch` |
| `/export/job` |
| `/export/job/${jobId}` |
| `/export/job/${jobId}/download` |
| `/export/job/{var}` |
| `/export/job/{var}/download` |
| `/export/{task_id}` |
| `/fileleak/` |
| `/fileleak/delete/` |
| `/fileleak/export/` |
| `/fingerprint/` |
| `/fingerprint/delete/` |
| `/fingerprint/export/` |
| `/fingerprint/upload/` |
| `/github_monitor_result/` |
| `/github_result/` |
| `/github_scheduler/` |
| `/github_scheduler/delete/` |
| `/github_scheduler/recover/` |
| `/github_scheduler/stop/` |
| `/github_scheduler/update/` |
| `/github_task/` |
| `/github_task/delete/` |
| `/github_task/stop/` |
| `/ip/` |
| `/ip/delete/` |
| `/ip/export/` |
| `/ip/export_domain/` |
| `/ip/export_ip/` |
| `/npoc_service/` |
| `/nuclei_result/` |
| `/nuclei_result/delete/` |
| `/poc/` |
| `/poc/delete/` |
| `/poc/sync/` |
| `/policy/` |
| `/policy/add/` |
| `/policy/delete/` |
| `/policy/edit/` |
| `/scheduler/` |
| `/scheduler/add/` |
| `/scheduler/add/site_monitor/` |
| `/scheduler/add/wih_monitor/` |
| `/scheduler/delete/` |
| `/scheduler/recover/batch` |
| `/scheduler/stop/batch` |
| `/service/` |
| `/site/` |
| `/site/delete/` |
| `/site/export/` |
| `/site/save_result_set/` |
| `/stat_finger/` |
| `/task/` |
| `/task/batch_stop/` |
| `/task/delete/` |
| `/task/policy/` |
| `/task/restart/` |
| `/task/sync/` |
| `/task/sync_scope/` |
| `/task_fofa/submit` |
| `/task_fofa/test` |
| `/task_schedule/` |
| `/task_schedule/delete/` |
| `/task_schedule/recover/` |
| `/task_schedule/stop/` |
| `/url/` |
| `/url/export/` |
| `/user/change_pass` |
| `/user/login` |
| `/user/logout` |
| `/vuln/` |
| `/vuln/delete/` |
| `/waf_host/` |
| `/wih/` |
| `/wih/export/` |
| `/wih_endpoint/` |
| `/wih_endpoint/delete/` |
| `/wih_endpoint/export/` |

## modules 配置：字段与动作消费契约

| 模块 | 名称 | listPath | 行键 | 消费列 |
|---|---|---|---|---|
| `dashboard` | 我的仪表盘 | `-` | `_id` | - |
| `system_monitor` | 系统监控 | `-` | `_id` | - |
| `task` | 任务管理 | `/task/` | `_id` | name, target, statistic_summary, progress, options_summary, status, start_time, end_time, _id |
| `task_schedule` | 计划任务 | `/task_schedule/` | `_id` | name, target, schedule_type, status, policy_name, time_config, last_run_date, next_run_date, run_number |
| `scheduler` | 资产监控 | `/scheduler/` | `_id` | name, domain, scope_id, interval, last_run_date, next_run_date, run_number |
| `policy` | 策略配置 | `/policy/` | `_id` | name, desc, update_date |
| `asset_scope` | 资产分组 | `/asset_scope/` | `_id` | name, scope, _id |
| `asset_domain` | 资产域名 | `/asset_domain/` | `_id` | domain, type, record, ips, source |
| `asset_site` | 资产站点 | `/asset_site/` | `_id` | site, title, headers, finger |
| `asset_ip` | 资产IP | `/asset_ip/` | `_id` | ip, os_info.name, port_info.port_id, domain, cdn_name |
| `asset_wih` | 资产WIH | `/asset_wih/` | `_id` | - |
| `site` | 站点 | `/site/` | `_id` | site, title, headers, finger, screenshot, ai_analysis |
| `domain` | 子域名 | `/domain/` | `_id` | domain, type, record, ips, source |
| `ip` | IP | `/ip/` | `_id` | ip, os_info.name, port_info.port_id, domain, cdn_name, geo_summary, asn_summary |
| `url` | URL信息 | `/url/` | `_id` | url, title, status_code, content_length, source, ai_analysis |
| `cert` | SSL证书 | `/cert/` | `_id` | host, cert_summary, ai_analysis |
| `service` | 服务 | `/service/` | `_id` | service_name, ip_port, service_info.product |
| `npoc_service` | C段 | `/npoc_service/` | `_id` | scheme, host, port, target |
| `cip` | C段 | `/cip/` | `_id` | cidr_ip, ip_count, domain_count |
| `stat_finger` | 指纹统计 | `/stat_finger/` | `_id` | name, cnt |
| `vuln` | 风险 | `/vuln/` | `_id` | vul_name, plg_type, app_name, target, credential, save_date, ai_analysis, detail_action |
| `nuclei_result` | PoC风险 | `/nuclei_result/` | `_id` | scanner_type, rule_id, target, vuln_name, vuln_severity, save_date, verify_data, ai_analysis, detail_action |
| `fileleak` | 目录扫描 | `/fileleak/` | `_id` | url, title, status_code, content_length, source, ai_analysis |
| `wih` | WIH | `/wih/` | `_id` | record_type, content, source, site |
| `wih_endpoint` | WIH接口提取 | `/wih_endpoint/` | `_id` | target, url, method, status_code, response_size, ai_analysis, detail_action |
| `waf_host` | WAF识别 | `/waf_host/` | `_id` | ip, domain, port, waf_name, hit_rule |
| `poc` | PoC管理 | `/poc/` | `_id` | plugin_name, plugin_type, category, app_name, vul_name, scheme, update_date |
| `fingerprint` | 指纹规则 | `/fingerprint/` | `_id` | name, human_rule, update_date |
| `github_task` | GitHub任务 | `/github_task/` | `_id` | name, keyword, result_count, status, start_time, end_time, _id |
| `github_result` | GitHub结果 | `/github_result/` | `_id` | repo_full_name, path, human_content, commit_date, keyword |
| `github_scheduler` | GitHub监控 | `/github_scheduler/` | `_id` | name, keyword, cron, status, run_number, last_run_date, next_run_date |
| `github_monitor_result` | GitHub监控结果 | `/github_monitor_result/` | `_id` | repo_full_name, path, human_content, commit_date, keyword |
| `task_fofa` | 测绘任务 | `-` | `_id` | - |
| `dingtalk_api` | 钉钉集成 | `-` | `_id` | - |
| `api_console` | API管理 | `-` | `_id` | - |
| `config_console` | 配置管理 | `-` | `_id` | - |
| `ai_console` | AI管理 | `-` | `_id` | - |

### 动作（action id → method + path）

| 模块 | 动作 | 方法 | 路径 |
|---|---|---|---|
| `task` | `create_task` | POST | `/task/` |
| `task` | `fofa_submit` | POST | `/task_fofa/submit` |
| `task` | `task_stop_batch` | POST | `/task/batch_stop/` |
| `task` | `task_restart_batch` | POST | `/task/restart/` |
| `task` | `task_delete_batch` | POST | `/task/delete/` |
| `task` | `task_policy_submit` | POST | `/task/policy/` |
| `task` | `task_sync` | POST | `/task/sync/` |
| `task` | `task_sync_scope_lookup` | GET | `/task/sync_scope/` |
| `task` | `task_batch_export_site` | POST | `/batch_export/site/` |
| `task` | `task_batch_export_domain` | POST | `/batch_export/domain/` |
| `task` | `task_batch_export_ip` | POST | `/batch_export/ip/` |
| `task` | `task_batch_export_url` | POST | `/batch_export/url/` |
| `task` | `task_batch_export_fileleak` | POST | `/batch_export/fileleak/` |
| `task` | `task_batch_export_port` | POST | `/batch_export/ip_port/` |
| `task` | `task_batch_export_cip` | POST | `/batch_export/cip/` |
| `task` | `task_batch_excel_report` | POST | `/export/batch` |
| `task` | `task_download_single_report` | GET | `/export/{task_id}` |
| `task_schedule` | `task_schedule_add` | POST | `/task_schedule/` |
| `task_schedule` | `task_schedule_stop` | POST | `/task_schedule/stop/` |
| `task_schedule` | `task_schedule_recover` | POST | `/task_schedule/recover/` |
| `task_schedule` | `task_schedule_delete` | POST | `/task_schedule/delete/` |
| `scheduler` | `scheduler_delete` | POST | `/scheduler/delete/` |
| `scheduler` | `scheduler_stop` | POST | `/scheduler/stop/batch` |
| `scheduler` | `scheduler_recover` | POST | `/scheduler/recover/batch` |
| `policy` | `policy_add` | POST | `/policy/add/` |
| `policy` | `policy_edit` | POST | `/policy/edit/` |
| `policy` | `policy_delete` | POST | `/policy/delete/` |
| `asset_scope` | `asset_scope_add` | POST | `/asset_scope/` |
| `asset_scope` | `asset_scope_delete` | POST | `/asset_scope/delete/` |
| `asset_scope` | `asset_scope_add_scope` | POST | `/asset_scope/add/` |
| `asset_scope` | `asset_scope_update` | POST | `/asset_scope/update/` |
| `asset_scope` | `asset_scope_add_scheduler` | POST | `/scheduler/add/` |
| `asset_scope` | `asset_scope_add_site_monitor` | POST | `/scheduler/add/site_monitor/` |
| `asset_scope` | `asset_scope_add_wih_monitor` | POST | `/scheduler/add/wih_monitor/` |
| `asset_domain` | `asset_domain_delete` | POST | `/asset_domain/delete/` |
| `asset_site` | `asset_site_delete` | POST | `/asset_site/delete/` |
| `asset_site` | `asset_site_save_result_set` | GET | `/asset_site/save_result_set/` |
| `asset_ip` | `asset_ip_delete` | POST | `/asset_ip/delete/` |
| `site` | `site_delete` | POST | `/site/delete/` |
| `site` | `site_save_result_set` | GET | `/site/save_result_set/` |
| `domain` | `domain_delete` | POST | `/domain/delete/` |
| `ip` | `ip_export_ip` | GET | `/ip/export_ip/` |
| `ip` | `ip_export_domain` | GET | `/ip/export_domain/` |
| `ip` | `ip_delete` | POST | `/ip/delete/` |
| `cert` | `cert_delete` | POST | `/cert/delete/` |
| `vuln` | `vuln_delete` | POST | `/vuln/delete/` |
| `nuclei_result` | `nuclei_result_delete` | POST | `/nuclei_result/delete/` |
| `fileleak` | `fileleak_delete` | POST | `/fileleak/delete/` |
| `wih_endpoint` | `wih_endpoint_delete` | POST | `/wih_endpoint/delete/` |
| `poc` | `poc_sync` | GET | `/poc/sync/` |
| `poc` | `poc_clear` | GET | `/poc/delete/` |
| `fingerprint` | `fingerprint_add` | POST | `/fingerprint/` |
| `fingerprint` | `fingerprint_delete` | POST | `/fingerprint/delete/` |
| `fingerprint` | `fingerprint_export` | GET | `/fingerprint/export/` |
| `fingerprint` | `fingerprint_upload` | POST | `/fingerprint/upload/` |
| `github_task` | `github_task_add` | POST | `/github_task/` |
| `github_task` | `github_task_stop` | POST | `/github_task/stop/` |
| `github_task` | `github_task_delete` | POST | `/github_task/delete/` |
| `github_scheduler` | `github_scheduler_add` | POST | `/github_scheduler/` |
| `github_scheduler` | `github_scheduler_update` | POST | `/github_scheduler/update/` |
| `github_scheduler` | `github_scheduler_stop` | POST | `/github_scheduler/stop/` |
| `github_scheduler` | `github_scheduler_recover` | POST | `/github_scheduler/recover/` |
| `github_scheduler` | `github_scheduler_delete` | POST | `/github_scheduler/delete/` |
| `task_fofa` | `fofa_test` | POST | `/task_fofa/test` |
| `task_fofa` | `fofa_submit_center` | POST | `/task_fofa/submit` |
| `dingtalk_api` | `dingtalk_config` | GET | `/dingtalk_api/config/` |
| `dingtalk_api` | `dingtalk_test` | POST | `/dingtalk_api/test/` |
| `dingtalk_api` | `dingtalk_workspaces` | POST | `/dingtalk_api/workspaces/` |
| `dingtalk_api` | `dingtalk_nodes` | POST | `/dingtalk_api/nodes/` |
| `dingtalk_api` | `dingtalk_create_workbook` | POST | `/dingtalk_api/create_workbook/` |
| `dingtalk_api` | `dingtalk_sheets` | POST | `/dingtalk_api/sheets/` |
| `dingtalk_api` | `dingtalk_write_markdown` | POST | `/dingtalk_api/write_markdown/` |

## 后端端点全表（AST 提取自 ARL/app/routes/）


### /api/api_console  （`api_console.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /ai_config/ | GET,POST | `save_ai_config_fields` | AI 管理配置读取与保存接口。 |
| /ai_config/reveal/ | POST | `verify_sensitive_fields` | AI 管理敏感字段显示接口（需二次身份验证）。 |
| /ai_config/sop/upload/ | POST | `-` | AI SOP 上传接口（仅支持 YAML）。 |
| /ai_config/test/ | POST | `test_ai_config_fields` | AI 管理连通性测试接口（基于当前表单值，不落盘）。 |
| /ai_denoise/analyze/ | POST | `analyze_ai_denoise_fields` | AI 去噪分析接口（详情仅展示已分析结果，不再触发实时 AI 调用）。 |
| /ai_usage/logs/ | GET | `-` | AI 对话日志查询接口。 |
| /ai_usage/stats/ | GET | `-` | AI Token 用量统计接口。 |
| /config/ | GET,POST | `save_config_fields` | 配置读取与保存接口 |
| /scan_config/ | GET,POST | `save_scan_config_fields` | 扫描配置读取与保存接口 |
| /scan_config/afrog_poc/update/ | POST | `-` | afrog-pocs 仓库更新接口（git clone/pull）。 |
| /scan_config/domain_dict/upload/ | POST | `-` | 域名爆破字典上传接口 |
| /scan_config/file_leak_dict/upload/ | POST | `-` | 敏感文件泄漏字典上传接口 |
| /scan_config/nuclei_poc/update/ | POST | `-` | nuclei-templates 仓库更新接口（git clone/pull）。 |
| /sensitive_verify/ | POST | `verify_sensitive_fields` | 敏感信息显示前的二次身份验证接口。 |
| /service_api/ | GET,POST | `save_service_api_fields` | 三方 API 配置读取与保存接口 |
| /service_api/reveal/ | POST | `verify_sensitive_fields` | 二次验证后返回敏感字段明文，仅用于“显示 key”场景。 |
| /service_api/test/ | POST | `test_service_api_fields` | 三方 API 单项测试接口（基于当前表单值实时测试，不落盘）。 |
| /service_api/test_batch/ | POST | `test_service_api_batch_fields` | 三方 API 批量测试接口，仅验证已填写凭据的 provider。 |

### /api/asset_domain  （`assetDomain.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` | 资产域名管理接口 |
| /delete/ | POST | `delete_domain_fields` | 删除资产域名接口 |
| /export/ | GET | `parser` | 资产域名导出接口 |

### /api/asset_ip  （`assetIP.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 资产IP查询接口 |
| /delete/ | POST | `delete_ip_fields` | 删除资产IP接口 |
| /export/ | GET | `parser` | 资产IP详细信息导出接口 |
| /export_domain/ | GET | `parser` | 域名单独导出接口 |
| /export_ip/ | GET | `parser` | IP地址单独导出接口 |

### /api/asset_scope  （`assetScope.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` | 资产范围管理接口 |
| /add/ | POST | `add_scope_fields` | 添加资产范围接口 |
| /delete/ | GET,POST | `parser` | 资产范围删除接口 |
| /export/ | GET | `parser` | 资产分组导出接口 |
| /update/ | POST | `update_scope_fields` | 编辑已有资产范围接口 |

### /api/asset_site  （`assetSite.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` | 资产站点管理接口 |
| /add_tag/ | POST | `add_asset_site_tag_fields` | 添加站点标签接口 |
| /delete/ | POST | `delete_asset_site_fields` | 删除资产站点接口 |
| /delete_tag/ | POST | `delete_asset_site_tag_fields` | 删除站点标签接口 |
| /export/ | GET | `parser` | 资产站点导出接口 |
| /save_result_set/ | GET | `parser` | 保存站点查询结果集接口 |

### /api/asset_wih  （`assetWih.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 资产WIH查询接口 |
| /export/ | GET | `parser` | 资产WIH导出接口 |

### /api/batch_export  （`batchExport.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /asset_ip/ | /asset_domain/ | /asset_site/ | POST | `scope_batch_export_fields` | 批量导出资产组IP接口 |
| /asset_ip/ | /asset_domain/ | /asset_site/ | POST | `scope_batch_export_fields` | 批量导出资产组域名接口 |
| /asset_ip/ | /asset_domain/ | /asset_site/ | POST | `scope_batch_export_fields` | 批量导出资产组站点接口 |
| /asset_wih/ | POST | `scope_batch_export_fields` | 批量导出资产组WIH接口 |
| /cip/ | POST | `batch_export_fields` | 批量导出C段接口 |
| /domain/ | POST | `batch_export_fields` | 批量导出域名接口 |
| /fileleak/ | POST | `batch_export_fields` | 批量导出文件泄露接口 |
| /ip/ | POST | `batch_export_fields` | 批量导出IP接口 |
| /ip_port/ | POST | `batch_export_fields` | 批量导出IP端口接口 |
| /site/ | POST | `batch_export_fields` | 批量导出站点接口 |
| /url/ | POST | `batch_export_fields` | 批量导出URL接口 |

### /api/cert  （`cert.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | SSL 证书信息查询接口 |
| /delete/ | POST | `delete_cert_fields` | SSL 证书信息删除接口 |

### /api/cip  （`cip.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | C段IP统计查询接口 |
| /export/ | GET | `parser` |  |

### /api/console  （`console.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /dashboard | GET | `-` | 仪表盘聚合数据接口 |
| /info | GET | `-` | 系统信息查询接口 |
| /recent_logs | GET | `-` | 仪表盘实时扫描日志接口 |
| /system_monitor/ | GET | `-` | 系统监控接口 |

### /api/dingtalk_api  （`dingtalk_api.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /config/ | GET,POST | `save_dingtalk_config_fields` | 获取/保存钉钉集成配置 |
| /create_workbook/ | POST | `create_workbook_fields` | 手动创建知识库表格（WORKBOOK） |
| /nodes/ | POST | `list_nodes_fields` | 获取知识库目录节点列表 |
| /reveal/ | POST | `verify_sensitive_fields` | 二次验证后返回钉钉集成敏感字段明文，仅用于显式查看场景。 |
| /sheets/ | POST | `list_sheets_fields` | 获取 workbook 下工作表列表 |
| /test/ | POST | `test_dingtalk_fields` | 测试钉钉开放平台连通性 |
| /workspaces/ | POST | `list_workspaces_fields` | 获取知识库空间列表 |
| /write_markdown/ | POST | `write_markdown_fields` | 将 markdown 文本写入 workbook |

### /api/domain  （`domain.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 域名信息查询接口 |
| /delete/ | POST | `delete_domain_fields` | 域名信息删除接口 |
| /export/ | GET | `parser` | 域名数据导出接口 |

### /api/export  （`export.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /<string:task_id> | GET | `-` | 任务报告导出接口 |
| /batch | POST | `-` | 批量合并导出接口 - 支持POST请求接收多个任务ID |
| /job | POST | `-` | 异步报告导出任务创建接口 |
| /job/<string:job_id> | GET | `-` | 异步报告导出任务状态接口 |
| /job/<string:job_id>/download | GET | `-` | 异步报告导出任务下载接口 |

### /api/fileleak  （`fileleak.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 文件泄露查询接口 |
| /delete/ | POST | `delete_fileleak_fields` | 删除文件泄露信息接口 |
| /export/ | GET | `parser` | 文件泄露导出接口 |

### /api/fingerprint  （`fingerprint.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` |  |
| /delete/ | POST | `delete_finger_fields` |  |
| /export/ | GET | `-` |  |
| /upload/ | POST | `file_upload` |  |

### /api/github_monitor_result  （`github_monitor_result.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | GitHub监控结果查询接口 |

### /api/github_result  （`github_result.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | GitHub泄露结果查询接口 |

### /api/github_scheduler  （`github_scheduler.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` | GitHub监控调度查询接口 |
| /delete/ | POST | `delete_github_scheduler_fields` |  |
| /recover/ | POST | `recover_github_scheduler_fields` |  |
| /stop/ | POST | `stop_github_scheduler_fields` |  |
| /update/ | POST | `update_github_scheduler_fields` |  |

### /api/github_task  （`github_task.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` |  |
| /delete/ | POST | `delete_github_task_fields` |  |
| /stop/ | POST | `stop_github_task_fields` |  |

### /api/image  （`image.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /<string:task_id>/<string:file_name> | GET | `-` | 站点截图访问接口 |
| /internal/upload | POST | `-` | worker 截图回传接口（仅内部调用） |

### /api/ip  （`ip.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | IP 信息查询接口 |
| /delete/ | POST | `delete_ip_fields` | IP 信息删除接口 |
| /export/ | GET | `parser` | IP:端口导出接口 |
| /export_domain/ | GET | `parser` | 从 IP 记录中导出域名接口 |
| /export_ip/ | GET | `parser` | 纯 IP 导出接口 |

### /api/npoc_service  （`npoc_service.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | NPoC服务识别查询接口 |

### /api/nuclei_result  （`nuclei_result.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | PoC 扫描结果查询接口 |
| /delete/ | POST | `delete_nuclei_result_fields` | 删除 PoC 扫描结果接口 |

### /api/poc  （`poc.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | PoC查询接口 |
| /delete/ | GET | `-` | PoC清空接口 |
| /sync/ | GET | `-` | PoC同步接口 |

### /api/policy  （`policy.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 策略信息查询接口 |
| /add/ | POST | `add_policy_fields` | 策略添加接口 |
| /delete/ | POST | `delete_policy_fields` | 策略删除接口 |
| /edit/ | POST | `edit_policy_fields` | 策略编辑接口 |

### /api/scheduler  （`scheduler.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 监控任务查询接口 |
| /add/ | POST | `add_scheduler_fields` | 添加监控任务接口 |
| /add/site_monitor/ | POST | `add_scheduler_site_fields` | 添加站点更新监控接口 |
| /add/wih_monitor/ | POST | `add_scheduler_wih_fields` | 添加WIH更新监控接口 |
| /delete/ | POST | `delete_scheduler_fields` | 删除监控任务接口 |
| /recover/ | POST | `recover_scheduler_fields` | 恢复单个监控任务接口（将被批量接口替代） |
| /recover/batch | POST | `batch_recover_scheduler_fields` | 批量恢复监控任务接口 |
| /stop/ | POST | `stop_scheduler_fields` | 停止单个监控任务接口（将被批量接口替代） |
| /stop/batch | POST | `batch_stop_scheduler_fields` | 批量停止监控任务接口 |

### /api/service  （`service.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 服务信息查询接口 |

### /api/site  （`site.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 站点信息查询接口 |
| /add_tag/ | POST | `add_site_tag_fields` | 站点添加标签接口 |
| /delete/ | POST | `delete_site_fields` | 站点批量删除接口 |
| /delete_tag/ | POST | `delete_site_tag_fields` | 删除站点标签接口 |
| /export/ | GET | `parser` | 站点信息导出接口 |
| /save_result_set/ | GET | `parser` | 保存站点结果集接口 |

### /api/stat_finger  （`stat_finger.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 指纹统计查询接口 |

### /api/task  （`task.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` | 任务管理主接口 |
| /batch_stop/ | POST | `batch_stop_fields` | 批量停止任务接口 |
| /delete/ | POST | `delete_task_fields` | 任务删除接口 |
| /policy/ | POST | `task_by_policy_fields` | 通过策略创建任务接口 |
| /restart/ | POST | `restart_task_fields` | 任务重启接口 |
| /stop/ | POST | `batch_stop_fields` | 旧版兼容：批量停止任务接口（POST /task/stop/） |
| /stop/<string:task_id> | GET | `-` | 单个任务停止接口 |
| /sync/ | POST | `sync_task_fields` | 任务结果同步接口 |
| /sync_scope/ | GET | `parser` | 目标到资产范围映射接口 |

### /api/task_fofa  （`taskFofa.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /submit | POST | `add_measure_fields` | 提交测绘任务接口 |
| /test | POST | `test_measure_fields` | 测绘语法测试接口 |

### /api/task_schedule  （`task_schedule.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET,POST | `parser` |  |
| /delete/ | POST | `delete_task_schedule_fields` |  |
| /recover/ | POST | `recover_task_schedule_fields` |  |
| /stop/ | POST | `stop_task_schedule_fields` |  |

### /api/url  （`url.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | URL信息查询接口 |
| /export/ | GET | `parser` | URL信息导出接口 |

### /api/user  （`user.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| /change_pass | POST | `change_pass_fields` | 修改密码接口 |
| /login | POST | `login_fields` | 用户登录接口 |
| /logout | GET | `-` | 用户登出接口 |

### /api/vuln  （`vuln.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | 漏洞查询接口 |
| /delete/ | POST | `delete_vuln_fields` | 删除漏洞信息接口 |

### /api/waf_host  （`waf_host.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | WAF 跳过主机查询接口 |

### /api/wih  （`wih.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | WIH查询接口 |
| /export/ | GET | `parser` | WIH导出接口 |
| /stat/ | GET | `parser` | WIH聚合统计接口（finger -> 数量） |

### /api/wih_endpoint  （`wih_endpoint.py`）

| 路由 | 方法 | 参数模型 | 摘要 |
|---|---|---|---|
| / | GET | `parser` | WIH 接口提取结果查询接口 |
| /delete/ | POST | `delete_wih_endpoint_fields` | 删除 WIH 接口提取结果接口 |
| /export/ | GET | `parser` | WIH 接口提取结果导出接口 |
