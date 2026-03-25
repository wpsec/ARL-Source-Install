# ARL AI报告（Markdown）

> 模板版本：`v1.1`
> 生成时间：`{{generated_at}}`
> 扫描开始时间：`{{scan_start}}`
> 扫描截止时间：`{{scan_end}}`
> 报告类型：`AI报告（Markdown）固定模板`
> 生成方式：`离线结构化汇总（不触发在线模型实时推理）`
> 任务ID：`{{task_id_list}}`

## 一、任务概览

| 任务名 | 目标 | 任务状态 |
| --- | --- | --- |
| {{task_name_1}} | {{target_1}} | {{task_status_1}} |
| {{task_name_2}} | {{target_2}} | {{task_status_2}} |

## 二、执行摘要

- 总体结论：`{{overall_conclusion}}`
- 风险态势：`{{risk_posture}}`
- 主要暴露面：`{{main_attack_surface}}`
- 首要处置建议：`{{top_action}}`

## 三、资产总览

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

## 四、风险等级分布

| 严重级别 | 数量 |
| --- | --- |
| 严重 | {{sev_critical_cnt}} |
| 高危 | {{sev_high_cnt}} |
| 中危 | {{sev_medium_cnt}} |
| 低危 | {{sev_low_cnt}} |

## 五、重点风险聚类

| 来源 | 风险名称 | 最高等级 | 数量 | 典型目标 |
| --- | --- | --- | --- | --- |
| {{source_1}} | {{vuln_name_1}} | {{severity_1}} | {{count_1}} | {{target_sample_1}} |
| {{source_2}} | {{vuln_name_2}} | {{severity_2}} | {{count_2}} | {{target_sample_2}} |

## 六、PoC风险摘要

| 规则ID | 风险名称 | 目标 | 严重级别 | 复现要点 |
| --- | --- | --- | --- | --- |
| {{poc_rule_id_1}} | {{poc_name_1}} | {{poc_target_1}} | {{poc_severity_1}} | {{poc_verify_hint_1}} |
| {{poc_rule_id_2}} | {{poc_name_2}} | {{poc_target_2}} | {{poc_severity_2}} | {{poc_verify_hint_2}} |

## 七、误报疑似项

1. [{{fp_source_1}}] {{fp_vuln_name_1}} | 目标：`{{fp_target_1}}` | 疑似原因：{{fp_reason_1}}
2. [{{fp_source_2}}] {{fp_vuln_name_2}} | 目标：`{{fp_target_2}}` | 疑似原因：{{fp_reason_2}}

## 八、优先处置计划

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

## 九、复测清单

- 复测范围：`{{retest_scope}}`
- 复测时间窗口：`{{retest_window}}`
- 复测负责人：`{{retest_owner}}`
- 复测结果记录：`{{retest_result_summary}}`

| 复测项 | 目标 | 预期结果 | 实际结果 |
| --- | --- | --- | --- |
| {{retest_item_1}} | {{retest_target_1}} | {{retest_expected_1}} | {{retest_actual_1}} |
| {{retest_item_2}} | {{retest_target_2}} | {{retest_expected_2}} | {{retest_actual_2}} |

## 十、审计轨迹

- 扫描任务标识：`{{task_id_list}}`
- 数据时间范围：`{{scan_start}} ~ {{scan_end}}`
- 导出时间：`{{generated_at}}`
- 备注：`{{audit_note}}`

## 十一、说明

- 本报告为 `AI报告（Markdown）固定模板`，内容基于当前任务扫描结果进行结构化整理。
- 模板默认不调用在线模型，仅用于导出交付与复盘留档。
- 若需“自然语言深度总结”，可在后续版本接入在线模型增强模块。
