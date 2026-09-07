# 06 附录 E · 计划 6 发布验收 runbook（双架构 + 40/64 目标）

状态：**未完成执行**（本文是执行手册；runbook 本体 2026-09-07 落盘，来源=当前 HEAD 复核 P2-02——此前计划 6 多处"附录 D"引用实指计划 5 指纹放行 runbook，属指向错误，本文件为计划 6 的专用替代入口）。

适用门禁：计划 6 §十二验收条件、§十三发布回滚流程、第 11 批（40/64 目标、双架构、Rust 模式升级、端到端 ≤5%）。**计划 5 的 x86 指纹切换门禁不在本文范围**（那份是 `docs/plan/[未完成]05-附录D-x86放行runbook.md`）。

红线前置：目标必须逐条在授权范围内；证据目录不得含 Token/Cookie/带凭据 URL/真实连接串；本手册所有命令不读取也不回显 `config-runtime.yaml` 内容（只做脱敏指纹）。

## 0. 固定输入与产物目录

```text
EVID=<repo>/docs/review/计划6发布验收证据-<YYYYMMDD>/
mkdir -p "$EVID"
```

| 输入 | 固化方法 | 记录 |
|---|---|---|
| revision | `git rev-parse HEAD` | `$EVID/revision.txt` |
| 应用镜像 | `docker buildx build ... -t arl-regression:<arch>` 后 `docker inspect --format '{{.Id}}' arl-regression:<arch>` | `$EVID/image-digest-<arch>.txt`（含 `Dockerfile` 与 lock 文件 sha256） |
| 目标集 | 授权清单文件 `targets-40.txt`/`targets-64.txt`（每行一目标） | `sha256sum` 记入 `$EVID/targets.sha256`，文件本身不入证据目录/不入库 |
| 非敏感配置指纹 | 对生效配置做键名脱敏后哈希：`python3 ARL/app/tools/collect_wih_baseline.py --help` 同源工具或 `grep -v -i 'uri\|password\|token\|key'` 管道 `sha256sum` | `$EVID/config-fingerprint.txt` |
| golden 基线 | `python3 scripts/api-unified-golden.py --check`；容器内 `compare_rust_python_corpus.py --run-native --strict-order`（双 corpus） | 完整 JSON 报告存 `$EVID/corpus-<arch>.json` |

## 1. 双架构功能回归（同一套命令）

```bash
bash scripts/run-container-regression.sh linux/arm64 arm64   # 原生环境
bash scripts/run-container-regression.sh linux/amd64 amd64   # 必须 x86 真机；qemu 仅功能面、其基准数据一律不采信
```

产物 `/tmp/arlreg-<arch>-discover.log`、`/tmp/arlreg-<arch>-hygiene.log` 复制入 `$EVID/`。

门禁：`polluted=0`；与 arm64 首轮基线（Ran 848 口径）对账，新增 FAIL/ERROR 逐条归因（环境/存量/新缺陷三分类，新缺陷必须立票）。

## 2. Rust 性能与模式门禁（x86 真机必做）

1. 容器内（或安装 release wheel 的 py3.10.20 环境）：
   `python3 ARL/app/tools/bench_api_unified_rust.py` → 存 `$EVID/bench-<arch>.json`。
2. 逐 stage 判定 CPU 闸（ratio ≤0.70 或吞吐 ≥1.5x）：**通过闸门的 stage 才允许加入
   `RUST_ACCEL_API_UNIFIED_RUST_STAGES`**（stats_prefix：`unified_normalize`/
   `unified_method`/`unified_hint`/`unified_dedupe`）；当前代码默认
   `unified_normalize,unified_method`（aarch64 native 实测过闸），`hint/dedupe`
   未过闸不得入列——stage 级硬门禁见附录 A §4.20，全局 `rust` 不放开列 stage。
3. 端到端对照（§十三.2 双跑口径）：同 revision 同目标集跑三组
   `API_UNIFIED_ENABLE=false`（legacy）/ `true+shadow` / `true+rust(allowlist)`：
   ```bash
   ARL_RUST_ACCEL_API_UNIFIED_MODE=shadow ARL_API_UNIFIED_ENABLE=true python3 -m app.tasks.arl_task ...   # 经任务提交接口下发，不手工改代码
   ```
   每组任务导出 JSON 后：
   ```bash
   python3 ARL/app/tools/collect_wih_baseline.py --input tasks-<组>.json --output baseline-<组>.json
   python3 ARL/app/tools/validate_wih_baseline.py --input baseline-<组>.json
   python3 ARL/app/tools/compare_task_baseline.py --python baseline-shadow.json --rust baseline-rust.json \
       --stage wih_api_doc_unified --stage wih_endpoint_followup_probe
   ```
   判定：`api_stage_wall_time` p95 恶化 ≤5%；`api_stage_network_wait_time` 按 §4.20
   新口径（只含真实 http_req）；结果集合与 Endpoint 集合不减少（下节 hash 对账）。

## 3. 结果集合一致性（Endpoint 集合 hash）

对每组任务的 Mongo 导出（脱敏投影：`url/method/api_type/status/sources` 排序聚合）：

```bash
python3 - <<'PY'
import json, hashlib, itertools
docs = list(json.load(open("endpoints-<组>.json")))
canon = sorted(f"{d['url']}|{d['method']}|{d['api_type']}|{d['status']}|{','.join(sorted(d['sources']))}" for d in docs)
print(hashlib.sha256("\n".join(canon).encode()).hexdigest(), len(canon))
PY
```

门禁：shadow 组 vs legacy 组集合差集必须逐条可解释（统一面新增 api_type/越界证据候选为允许增量，附录 A §4.12"越界证据化是唯一允许缺失面"）；rust 组 vs shadow 组**必须逐字节等集**（stage-gated 语义）。

## 4. 40 目标协同专项（先于 64）

任务提交后采集（每目标一条任务，同端口档位/同配置）：
- 数据联通：`js_intel → api_doc_url → 统一文档队列当前任务内消费`（`api_document_*` 计数与 `wih_api_doc_unified` 阶段日志）；
- 重复请求：按 T5/A8 四类口径出报表——`network_request_count`/`cache_hit_count`/
  `actual_duplicate_request_count`/`external_network_*`；`api_document_cross_bucket_hit_total` 为复用面；
- WAF 隔离：`api_probe_waf_blocked_total` 只停 endpoint_probe 类、`api_document_waf_blocked_total` 只停 api_doc 类、主机级封禁才 `degraded/host_waf_blocked`（资产面 `degraded_reason` 可归因，附录 A §4.20）；
- 首批可见 ≤5 分钟、终态家族正确（done/done_pending/done_degraded）；账本降级阈值（`LEDGER_DEGRADED_THRESHOLD`）如触发，done_degraded + `pending_backlog|ledger` 必须可见。
- 第 10 批 T10-A 口径出数：`api_doc_url` 记录面扩大的真实增量数与 `pending_backlog|api` 显影存量。

## 5. 回滚

全部单键回退，无数据迁移（`API_UNIFIED_ENABLE` 默认 False 期间统一层从未成为事实源）：

| 现象 | 回滚动作 | 生效面 |
|---|---|---|
| Endpoint 集合减少/异常 | `API_UNIFIED_ENABLE=false`（代码默认即此态） | 单任务起 |
| 某 stage native 行为异常 | 从 `RUST_ACCEL_API_UNIFIED_RUST_STAGES` 移除该 stats_prefix（保持 shadow） | 即时 |
| Rust 面需全停 | `RUST_ACCEL_API_UNIFIED_MODE=off` | 即时 |
| 降级/fallback 失效 | `RUST_ACCEL_FALLBACK_ENABLE=true`、`API_UNIFIED_FALLBACK_ENABLE=true` | 即时 |

回滚后仍需保留 `$EVID/` 现场（任务导出、日志）供归因，不得事后改写证据。

## 6. 完成定义

- [ ] 两架构 §1 全绿（含 hygiene polluted=0）
- [ ] x86 真机 §2 基准 + stage-gated 三组对照 ≤5% 恶化
- [ ] §3 三组集合 hash 对账可解释
- [ ] §4 40 目标专项四要点出数
- [ ] 64 目标两轮（冷/热）与首批 p95 门禁
- [ ] 以上齐备后才进入 `API_UNIFIED_ENABLE` 默认切换评审（§十三流程）；任一缺失保持默认关闭，不以本地单测或 qemu 数据替代。
