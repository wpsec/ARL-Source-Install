# 计划 5：指纹体系统一与服务识别重构

## Review 修正复核报告

- 复核日期：2026-09-04
- 复核范围：计划 5 第 2 阶段修正及其前置提交
- 复核方式：只读代码检查、生成器 dry-run、定向单元测试
- 复核结论：第 2 阶段前置产物基本达标；第 3 阶段已有未跟踪的 Registry 草稿，但尚未接入运行时，不能宣称整套指纹体系统一已完成。

## 一、复核提交

本轮复核确认以下提交已存在于当前分支：

| Commit | 内容 | 结论 |
|---|---|---|
| `9cb309e5` | Kscan local 增量审计与 golden 双文件对比 | 已落库 |
| `d48541ba` | 修复多操作数表达式求值缺陷 | 已修复并有回归测试 |
| `4176aa5b` | 下沉 `app/fp_common.py`，解耦生成器依赖 | 已修复 |
| `378619e8` | 统一指纹生成器、schema、压缩产物和原子写盘 | 已实现，待运行时消费 |
| `a3978b6d` | 计划状态和遗留决策收口 | 已落档 |

## 二、已修复事项

1. `evaluate_expression` 多操作数 `||` 规则不再隐式返回 `None`。
2. 生成器改为依赖 `app.fp_common`，不再因 `app.services` 包级导入而强制依赖 NPoC 的 `xing`。
3. 泛化条件改为分支级拒绝，避免把 `A && login` 错误降成 `A`。
4. 括号表达式和不支持字段保守拒绝，不猜测布尔语义。
5. 名称合并不再删除标点，`A-B` 与 `AB` 不会被错误合并。
6. 分支级 `sources` 已保留。
7. 服务 seed 已补充 `tcp/udp`、NPoC/Nmap 优先级和 `keep_evidence` 契约，并明确标记为 `seed_v0`。
8. 生成结果增加 schema 校验、输入文件 hash、gzip 分发形态、临时文件和失败回滚。
9. 默认 `tools/finger.json` 路径已与 `/code` 构建目录一致。

## 三、验证结果

当前验证结果：

- 统一指纹生成器 dry-run：站点规则 22260 条，服务 seed 33 条。
- 分支级拒绝 212 条，整条规则拒绝 153 条。
- 同名多源合并冲突 18074 条，分支来源保留。
- 当前输入样本的 no-anchor 分支为 0，运行时 no-anchor 桶尚未形成真实覆盖测试。
- `test_unified_fingerprints_build` 与 `test_expr_evaluation_golden` 合计 20 项通过。
- 已生成并入库：`site_fingerprints.json.gz`、`service_fingerprints.json.gz`。
- 工作区存在用户未跟踪文件 `ARL/app/services/site_fingerprint_registry.py`；本报告未修改或覆盖该文件。

## 四、仍未完成的关键缺口

| 等级 | 文件/模块 | 问题 | 影响 | 最小后续动作 |
|---|---|---|---|---|
| 阻断发布 | `fetchSite.py`、`fingerprint_cache.py`、`site_fingerprint_registry.py` | 运行时仍使用 legacy `utils/fingerprint.py` 与 Mongo/Kscan 双路径；Registry 文件目前未被 import 或调用 | 统一文件不会影响真实扫描，旧双路径仍然存在 | 完成 Registry/Matcher 接入 `fetchSite.py`，旧路径仅保留显式 fallback |
| 阻断发布 | 服务识别链路 | `service_fingerprints.json.gz` 当前仍是 `seed_v0`，没有接入 Nmap/NPoC 输出 | 服务指纹文件还不能影响端口服务识别 | 基于真实 Nmap/NPoC fixture 实现 `ServiceFingerprintRegistry/Matcher` 和冲突证据回写 |
| 高 | `site_fingerprint_registry.py:194-204`、配置系统 | 当前代码未发现 `Config.SITE_FINGERPRINT_FILE` 配置定义；Registry 默认路径可能为空 | 即使调用 Registry，也无法稳定定位 `.json.gz` 规范产物 | 增加默认路径、配置覆盖、文件缺失和压缩产物加载测试 |
| 高 | Registry/索引 | 当前产物含 `anchors` 契约，但运行时没有倒排索引和 no-anchor 兜底桶 | 大规模规则加载后可能仍逐条匹配，性能收益尚未兑现 | 先实现 Python 索引版，再接入 Rust；补无锚点、索引召回和结果一致性测试 |
| 高 | Kscan 构建输入 | `kscan_fingerprint.local.json` 仍被 Git 忽略，且是默认迁移输入 | 新环境无法仅凭仓库重新构建 9673 条基线；当前 gzip 产物可审计但不完全可再生 | 明确受控分发方案：纳入源文件、提供受控构建输入，或将其正式定义为不可再生外部输入 |
| 一般 | `build_unified_fingerprints.py` | 测试输出仍有 `ResourceWarning`，存在未关闭文件句柄 | 不影响当前结果，但会污染构建日志并可能掩盖真正资源问题 | 统一使用 `with open(...)`，补充 gzip 文件句柄关闭测试 |
| 一般 | 测试覆盖 | 目前验证集中在生成器和表达式；没有真实运行时 Registry、Nmap/NPoC 映射、旧 Mongo 文档和 API 回写回归 | 无法证明真实扫描链路结果不减少 | 第 3 阶段增加运行时加载、兼容字段、服务冲突和端到端 fixture 测试 |

## 五、当前真实识别链路

```text
端口扫描
  → Nmap 发现开放端口
  → 配置启用时执行 Nmap -sV
  → NPoC 对低置信度或显式目标补充识别
  → 回填 service_name/product/version

站点扫描
  → FetchSite
  → legacy webapp.json 匹配
  → Mongo fingerprint + Kscan 匹配
  → Wappalyzer 结果独立合并
```

当前新增的两个规范压缩文件还没有进入上述运行时链路。`site_fingerprint_registry.py` 已出现，但目前仍是未跟踪草稿，且没有被 `fetchSite.py` 调用。因此，当前阶段只能验收为“规则整理和构建前置完成”，不能验收为“运行时指纹统一完成”。

## 六、下一步建议

按计划进入第 3 阶段，顺序固定为：

1. 实现并测试 `SiteFingerprintRegistry`，透明读取 `.json` 和 `.json.gz`。
2. 实现 Python `SiteFingerprintMatcher`，复用现有置信度和 confirmed/candidate 语义。
3. 将 `fetchSite.py` 切换到 Registry，旧识别路径改为显式 fallback。
4. 增加真实响应样本的旧链路/新链路结果集合对比。
5. 再实现服务 Registry/Matcher，接收 Nmap 与 NPoC 证据，不改变 Mongo 字段。
6. 通过运行时回归后，才评估删除 `webapp.json`、legacy loader 和旧 Kscan 加载路径。

本报告不批准删除旧指纹文件，也不批准在第 3 阶段完成前进行 Rust Matcher 接入或性能门禁验收。
