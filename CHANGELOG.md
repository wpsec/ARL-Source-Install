# 更新日志

本文件记录 `newUI` 分支的重要变更。  
每次更新版本号时，请同步补充一条记录（日期、版本、核心变更）。

## v3.0.15 - 2026-03-11

- 新建任务新增 `domain_dict` 字段：支持任务级域名字典选择，不选时沿用配置管理默认字典
- `/task/` 接口新增 `domain_dict` 参数校验，避免提交不存在的字典路径
- 域名任务执行流程增强：优先读取任务级字典，缺失时回退 `domain_brute_type` 对应默认字典
- README 字典持久化说明补充“任务级字典选择”使用方式

## v3.0.14 - 2026-03-11

- 新增宿主机持久化字典目录：`ARL/docker/dicts/domain`、`ARL/docker/dicts/file_leak`
- `docker-compose` 为 `web/worker` 增加字典目录挂载与 `ARL_DOMAIN_DICT_CUSTOM_DIR` / `ARL_DOMAIN_DICT_UPLOAD_DIR`
- 配置管理扫描项增强：自动收集内置/自定义/上传目录中的域名字典
- 扫描配置增强：读取与保存时自动兼容旧字典路径，并对所选字典文件做存在性校验

## v3.0.13 - 2026-03-11

- 字典目录重构：新增 `ARL/app/dicts/domain` 与 `ARL/app/dicts/file_leak`
- 域名字典迁移：`domain_2w.txt`、`domain_dict_test.txt`、`altdnsdict.txt`
- 敏感目录字典迁移：`file_top_2000.txt`、`file_top_200.txt`、`file_test.txt`
- 新增旧路径兼容逻辑：历史配置仍可自动映射到新目录，避免升级后配置失效

## v3.0.12 - 2026-03-11

- 统一删除确认交互：全系统删除按钮改为统一的前端确认弹窗
- 优化错误/提示消息展示：过滤接口返回中的 `<script>` 与 HTML 标签，避免原样显示
- 更新前端构建产物并同步到 `ARL/docker/frontend`

## v3.0.10 - 2026-03-11

- SSL证书采集能力增强：支持协议、加密套件与加密强度采集
- 任务详情与资产搜索中的 `SSL证书/CERT` 增强展示协议与套件摘要
- 导出报告新增 `SSL证书` 工作表，并纳入钉钉知识库写入顺序
- 钉钉集成新增 `SSL证书扫描通知` 配置，支持证书临期告警通知
