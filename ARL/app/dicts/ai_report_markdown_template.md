# ARL AI分析报告

> 模板版本：`v2.1`
> 生成时间：`{{generated_at}}`
> 扫描开始时间：`{{scan_start}}`
> 扫描截止时间：`{{scan_end}}`
> 报告类型：`AI分析报告固定模板 V2`
> 生成方式：`离线结构化汇总（仅读取扫描与AI去噪落库结果，不触发实时模型调用）`
> 任务ID：`{{task_id_list}}`

## 一、任务概览

| 任务名 | 目标 | 任务状态 |
| --- | --- | --- |
| {{task_name_1}} | {{target_1}} | {{task_status_1}} |
| {{task_name_2}} | {{target_2}} | {{task_status_2}} |

## 二、扫描目标清单

| 任务名 | 扫描目标 |
| --- | --- |
| {{scan_task_name_1}} | {{scan_target_1}} |
| {{scan_task_name_2}} | {{scan_target_2}} |
| {{scan_task_name_3}} | {{scan_target_3}} |

## 三、任务资产产出统计

| 任务名 | 任务目标 | 站点 | 子域名 | IP | URL | 风险 |
| --- | --- | --- | --- | --- | --- | --- |
| {{asset_task_name_1}} | {{asset_task_target_1}} | {{asset_site_cnt_1}} | {{asset_domain_cnt_1}} | {{asset_ip_cnt_1}} | {{asset_url_cnt_1}} | {{asset_vuln_cnt_1}} |
| {{asset_task_name_2}} | {{asset_task_target_2}} | {{asset_site_cnt_2}} | {{asset_domain_cnt_2}} | {{asset_ip_cnt_2}} | {{asset_url_cnt_2}} | {{asset_vuln_cnt_2}} |

## 四、资产样本（节选）

### 站点资产（总数 {{site_total}}，展示 {{site_sample_cnt}}）
1. {{site_sample_1}}
2. {{site_sample_2}}
3. {{site_sample_3}}

### 子域名资产（总数 {{domain_total}}，展示 {{domain_sample_cnt}}）
1. {{domain_sample_1}}
2. {{domain_sample_2}}
3. {{domain_sample_3}}

### IP资产（总数 {{ip_total}}，展示 {{ip_sample_cnt}}）
1. {{ip_sample_1}}
2. {{ip_sample_2}}
3. {{ip_sample_3}}

### URL资产（总数 {{url_total}}，展示 {{url_sample_cnt}}）
1. {{url_sample_1}}
2. {{url_sample_2}}
3. {{url_sample_3}}

## 五、执行摘要

- 总体结论：`{{overall_conclusion}}`
- 风险态势：`{{risk_posture}}`
- 主要暴露面：`{{main_attack_surface}}`
- 首要处置建议：`{{top_action}}`

## 六、资产总览

| 指标 | 数量 |
| --- | --- |
| 站点 | {{site_cnt}} |
| 子域名 | {{domain_cnt}} |
| IP | {{ip_cnt}} |
| URL信息 | {{url_cnt}} |
| 风险总数 | {{vuln_cnt}} |
| PoC风险 | {{poc_cnt}} |
| WAF识别 | {{waf_cnt}} |
| WIH记录 | {{wih_cnt}} |

## 七、风险等级分布

| 严重级别 | 数量 |
| --- | --- |
| 严重 | {{sev_critical_cnt}} |
| 高危 | {{sev_high_cnt}} |
| 中危 | {{sev_medium_cnt}} |
| 低危 | {{sev_low_cnt}} |
| 信息 | {{sev_info_cnt}} |

## 八、AI去噪概览

- AI去噪配置开关：`{{ai_denoise_switch}}`
- AI去噪落库记录：`{{ai_denoise_total}}`
- 已完成分析（AI/规则）：`{{ai_denoise_analyzed}}`
- 高价值目标（危险/可疑）：`{{ai_high_value_cnt}}`
- 疑似误报候选：`{{ai_suspected_fp_cnt}}`
- 分析来源分布：`AI {{ai_source_ai_cnt}} / 规则 {{ai_source_rule_cnt}} / 未分析 {{ai_source_disabled_cnt}}`
- 结果级别分布：`危险 {{ai_level_danger_cnt}} / 可疑 {{ai_level_suspicious_cnt}} / 正常 {{ai_level_safe_cnt}} / 未分析 {{ai_level_disabled_cnt}}`

| 模块 | 记录数 | 危险 | 可疑 | 正常 | AI模型 | 规则 | 未分析 | 疑似误报 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| {{ai_module_1}} | {{ai_total_1}} | {{ai_danger_1}} | {{ai_suspicious_1}} | {{ai_safe_1}} | {{ai_src_ai_1}} | {{ai_src_rule_1}} | {{ai_src_disabled_1}} | {{ai_fp_1}} |
| {{ai_module_2}} | {{ai_total_2}} | {{ai_danger_2}} | {{ai_suspicious_2}} | {{ai_safe_2}} | {{ai_src_ai_2}} | {{ai_src_rule_2}} | {{ai_src_disabled_2}} | {{ai_fp_2}} |

## 九、AI高价值目标（危险/可疑）

| 模块 | 目标 | 结论 | 来源 | 风险等级 | 可信度 | 分析时间 | 摘要 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| {{high_module_1}} | {{high_target_1}} | {{high_level_1}} | {{high_source_1}} | {{high_risk_1}} | {{high_trust_1}} | {{high_time_1}} | {{high_summary_1}} |
| {{high_module_2}} | {{high_target_2}} | {{high_level_2}} | {{high_source_2}} | {{high_risk_2}} | {{high_trust_2}} | {{high_time_2}} | {{high_summary_2}} |

## 十、AI疑似误报候选

| 模块 | 目标 | 结论 | 来源 | 风险等级 | 分析时间 | 依据摘要 |
| --- | --- | --- | --- | --- | --- | --- |
| {{ai_fp_module_1}} | {{ai_fp_target_1}} | {{ai_fp_level_1}} | {{ai_fp_source_1}} | {{ai_fp_risk_1}} | {{ai_fp_time_1}} | {{ai_fp_reason_1}} |
| {{ai_fp_module_2}} | {{ai_fp_target_2}} | {{ai_fp_level_2}} | {{ai_fp_source_2}} | {{ai_fp_risk_2}} | {{ai_fp_time_2}} | {{ai_fp_reason_2}} |

## 十一、重点风险聚类

| 来源 | 风险名称 | 最高等级 | 数量 | 典型目标 |
| --- | --- | --- | --- | --- |
| {{source_1}} | {{vuln_name_1}} | {{severity_1}} | {{count_1}} | {{target_sample_1}} |
| {{source_2}} | {{vuln_name_2}} | {{severity_2}} | {{count_2}} | {{target_sample_2}} |

## 十二、规则误报疑似项

1. [{{fp_source_1}}] {{fp_vuln_name_1}} | 目标：`{{fp_target_1}}` | 疑似原因：{{fp_reason_1}}
2. [{{fp_source_2}}] {{fp_vuln_name_2}} | 目标：`{{fp_target_2}}` | 疑似原因：{{fp_reason_2}}

## 十三、优先处置计划

### 24小时内（高优先级）
1. 处置 `critical/high` 风险且存在外网直接可达的入口。
2. 对认证缺失、弱口令、敏感管理入口进行临时收敛（ACL/白名单/下线）。
3. 对疑似泄漏的密钥、令牌执行轮换并审计调用日志。

### 72小时内（中优先级）
1. 对同类重复风险按“单漏洞多目标”批量修复，统一整改基线。
2. 校验 TLS/证书策略，关闭弱协议与弱套件。
3. 梳理高频风险来源插件，确认规则适配性并降低误报噪声。

### 7天内（治理项）
1. 建立资产分层分级整改清单，明确责任人与 SLA。
2. 建立持续复测机制，纳入周期任务并跟踪趋势。
3. 输出误报规则优化建议，反哺检测策略。

## 十四、复测清单

- 复测范围：`{{retest_scope}}`
- 复测时间窗口：`{{retest_window}}`
- 复测负责人：`{{retest_owner}}`
- 复测结果记录：`{{retest_result_summary}}`

| 复测项 | 目标 | 预期结果 | 实际结果 |
| --- | --- | --- | --- |
| {{retest_item_1}} | {{retest_target_1}} | {{retest_expected_1}} | {{retest_actual_1}} |
| {{retest_item_2}} | {{retest_target_2}} | {{retest_expected_2}} | {{retest_actual_2}} |

## 十五、审计轨迹

- 扫描任务标识：`{{task_id_list}}`
- 数据时间范围：`{{scan_start}} ~ {{scan_end}}`
- 导出时间：`{{generated_at}}`
- 备注：`{{audit_note}}`

## 十六、说明

- 本报告为 `AI分析报告固定模板 V2`，内容基于当前任务扫描结果与 AI 去噪落库结果进行结构化整理。
- 模板默认不调用在线模型，仅用于导出交付与复盘留档。
- 若需“自然语言深度总结”，可在后续版本接入在线模型增强模块。
