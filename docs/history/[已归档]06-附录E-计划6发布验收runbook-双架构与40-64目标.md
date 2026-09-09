# 06 附录 E · 计划 6 发布验收 runbook（双架构 + 40/64 目标）

状态：**开发完成；发布验收未执行**（2026-09-08 Review 修订：统一 API 开关接线、任务提交、脱敏证据流程、worker consumer 健康监督代码和离线代码门禁入口已补齐；真实重部署执行仍按用户安排暂不执行）。

适用门禁：计划 6 §十二验收条件、§十三发布回滚流程、第 11 批（40/64 目标、双架构、Rust 模式升级、端到端 ≤5%）。**计划 5 的 x86 指纹切换门禁不在本文范围**（那份是 `docs/history/[已归档]05-附录D-x86放行runbook.md`）。

红线前置：目标必须逐条在授权范围内；证据目录不得含 Token/Cookie/带凭据 URL/真实连接串；本手册所有命令不读取也不回显 `config-runtime.yaml` 内容（只做脱敏指纹）。

## 0. 固定输入与产物目录

以下命令块应在同一台验收机的同一 shell 会话中执行；切换发布组前必须等待上一组任务完成并导出。

```bash
set -euo pipefail
REPO_ROOT="${REPO_ROOT:-$(pwd)}"
EVID="${EVID:-$REPO_ROOT/docs/review/计划6发布验收证据-$(date +%Y%m%d)}"
# 原始任务/Endpoint 导出可能包含目标和 URL，只放在权限收紧的临时目录，不入 Git。
PRIVATE_EVID="${PRIVATE_EVID:-$(mktemp -d "${TMPDIR:-/tmp}/arl-release-private.XXXXXX")}"
mkdir -p "$EVID"
chmod 700 "$PRIVATE_EVID"
git -C "$REPO_ROOT" rev-parse HEAD > "$EVID/revision.txt"
```

| 输入 | 固化方法 | 记录 |
|---|---|---|
| revision | `git rev-parse HEAD` | `$EVID/revision.txt` |
| 应用镜像 | `docker buildx build ... -t arl-regression:<arch>` 后 `docker inspect --format '{{.Id}}' arl-regression:<arch>` | `$EVID/image-digest-<arch>.txt`（含 `Dockerfile` 与 lock 文件 sha256） |
| 目标集 | 授权清单文件 `targets-40.txt`/`targets-64.txt`（每行一目标） | `sha256sum` 记入 `$EVID/targets.sha256`，文件本身不入证据目录/不入库 |
| 非敏感配置指纹 | `docker exec arl_web python3 /code/scripts/fingerprint-runtime-config.py --config /code/app/config.yaml | sha256sum`；脚本采用 allowlist，不读取敏感字段 | `$EVID/config-fingerprint.txt` |
| golden 基线 | `python3 scripts/api-unified-golden.py --check`；容器内 `compare_rust_python_corpus.py --run-native --strict-order`（双 corpus） | 检查日志存 `$EVID/api-unified-golden.log`，完整 JSON 报告存 `$EVID/corpus-<arch>.json` |

固定配置指纹和离线 golden 检查：

```bash
docker exec arl_web python3 /code/scripts/fingerprint-runtime-config.py \
  --config /code/app/config.yaml | sha256sum | awk '{print $1}' > "$EVID/config-fingerprint.txt"
python3 scripts/api-unified-golden.py --check > "$EVID/api-unified-golden.log" 2>&1
```

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
3. 端到端对照（§十三.2 双跑口径）：同 revision、同目标文件、同端口档位跑三组
   `legacy` / `unified_shadow` / `stage_gated_rust`。开关由 Compose 环境注入，任务通过
   `/api/task/` 提交，不手工改代码：

   ```bash
   : "${DEPLOY_ENV:?设置部署 .env 文件路径，不要把内容打印到终端}"
   : "${ARL_BASE_URL:?设置应用基地址，例如 http://127.0.0.1}"
   : "${ARL_AUTH_COOKIE:?从安全存储注入 Cookie，不要写入证据目录}"
   WORKER_SERVICES="${WORKER_SERVICES:-worker_1 worker_2}"

   run_release_group() {
     local group="$1"
     case "$group" in
       legacy)
         export ARL_API_UNIFIED_ENABLE=false
         export ARL_RUST_ACCEL_API_UNIFIED_MODE=off
         ;;
       unified_shadow)
         export ARL_API_UNIFIED_ENABLE=true
         export ARL_RUST_ACCEL_API_UNIFIED_MODE=shadow
         ;;
       stage_gated_rust)
         export ARL_API_UNIFIED_ENABLE=true
         export ARL_RUST_ACCEL_API_UNIFIED_MODE=rust
         ;;
       *)
         echo "未知发布组: $group" >&2
         return 2
         ;;
     esac
     export ARL_API_UNIFIED_FALLBACK_ENABLE=true
     export ARL_RUST_ACCEL_API_UNIFIED_RUST_STAGES="${ARL_RUST_ACCEL_API_UNIFIED_RUST_STAGES:-unified_normalize,unified_method}"
     docker compose --env-file "$DEPLOY_ENV" -f "$REPO_ROOT/ARL/docker/docker-compose.yml" \
       up -d --force-recreate web $WORKER_SERVICES scheduler
     printf '%s\n' "$group" > "$PRIVATE_EVID/active-group.txt"
   }

   submit_group_tasks() {
     local group="$1"
     local target_file="$2"
     local submit_file="$PRIVATE_EVID/task-submit-${group}.jsonl"
     local id_file="$PRIVATE_EVID/task-ids-${group}.txt"
     : > "$submit_file"
     : > "$id_file"
     while IFS= read -r target; do
       [ -n "$target" ] || continue
       payload="$(TARGET="$target" GROUP="$group" python3 - <<'PY'
   import json
   import os

   print(json.dumps({
       "name": "plan6-{}".format(os.environ["GROUP"]),
       "target": os.environ["TARGET"],
       "domain_brute": False,
       "port_scan": True,
       "port_scan_type": "top100",
       "service_detection": False,
       "site_identify": True,
       "site_capture": False,
       "file_leak": False,
       "site_spider": False,
       "web_info_hunter": True,
       "ai_denoise": False,
       "skip_scan_cdn_ip": True,
   }))
   PY
       )"
       response="$(curl --fail --silent --show-error -X POST "${ARL_BASE_URL%/}/api/task/" \
         -H "Cookie: ${ARL_AUTH_COOKIE}" -H "Content-Type: application/json" \
         --data "$payload")"
       printf '%s\n' "$response" >> "$submit_file"
       printf '%s\n' "$response" | python3 -c '
   import json
   import sys
   payload = json.load(sys.stdin)
   for item in payload.get("items", []):
       if isinstance(item, dict) and (item.get("_id") or item.get("task_id")):
           print(str(item.get("_id") or item.get("task_id")))
   ' >> "$id_file"
     done < "$target_file"
     sort -u "$id_file" -o "$id_file"
     expected="$(awk 'NF {n++} END {print n + 0}' "$target_file")"
     actual="$(awk 'NF {n++} END {print n + 0}' "$id_file")"
     if [ "$actual" -ne "$expected" ]; then
       echo "$group 任务数不匹配: expected=$expected actual=$actual" >&2
       return 1
     fi
   }

   collect_group_exports() {
     local group="$1"
     local index=0
     : > "$PRIVATE_EVID/task-manifest-${group}.tsv"
     while IFS= read -r task_id; do
       [ -n "$task_id" ] || continue
       index=$((index + 1))
       printf '%s\t%s\n' "$index" "$task_id" >> "$PRIVATE_EVID/task-manifest-${group}.tsv"
       curl --fail --silent --show-error \
         "${ARL_BASE_URL%/}/api/task/?_id=${task_id}&page=1&size=1&_refresh=1" \
         -H "Cookie: ${ARL_AUTH_COOKIE}" \
         > "$PRIVATE_EVID/${group}-task-${index}.json"
       curl --fail --silent --show-error \
         "${ARL_BASE_URL%/}/api/wih_endpoint/?task_id=${task_id}&page=1&size=1000&_refresh=1" \
         -H "Cookie: ${ARL_AUTH_COOKIE}" \
         > "$PRIVATE_EVID/${group}-endpoint-${index}.json"
     done < "$PRIVATE_EVID/task-ids-${group}.txt"
   }

   wait_group_tasks() {
     local group="$1"
     local timeout="${2:-7200}"
     local deadline=$((SECONDS + timeout))
     while [ "$SECONDS" -lt "$deadline" ]; do
       local pending=0
       local failed=0
       while IFS= read -r task_id; do
         [ -n "$task_id" ] || continue
         status="$(curl --fail --silent --show-error \
           "${ARL_BASE_URL%/}/api/task/?_id=${task_id}&page=1&size=1&_refresh=1" \
           -H "Cookie: ${ARL_AUTH_COOKIE}" | \
           python3 -c 'import json, sys; print((json.load(sys.stdin).get("items") or [{}])[0].get("status", ""))')"
         case "$status" in
           done|done_pending|done_degraded) ;;
           stop|error) failed=1 ;;
           *) pending=1 ;;
         esac
       done < "$PRIVATE_EVID/task-ids-${group}.txt"
       if [ "$failed" -ne 0 ]; then
         echo "$group 存在 stop/error 任务，停止采集" >&2
         return 1
       fi
       [ "$pending" -eq 0 ] && return 0
       sleep 10
     done
     echo "$group 等待任务终态超时" >&2
     return 1
   }
   ```

   对每个发布组依次执行：

   ```bash
   TARGETS_40="${TARGETS_40:?授权的 40 目标文件路径}"
   run_release_group legacy
   submit_group_tasks legacy "$TARGETS_40"
   wait_group_tasks legacy
   collect_group_exports legacy

   run_release_group unified_shadow
   submit_group_tasks unified_shadow "$TARGETS_40"
   wait_group_tasks unified_shadow
   collect_group_exports unified_shadow

   run_release_group stage_gated_rust
   submit_group_tasks stage_gated_rust "$TARGETS_40"
   wait_group_tasks stage_gated_rust
   collect_group_exports stage_gated_rust
   ```

   将每组按任务拆分的 API 响应合并为基线输入；合并工具只读取私有目录，不把原始目标复制到
   `$EVID`：

   ```bash
   python3 scripts/merge-api-task-exports.py --input-dir "$PRIVATE_EVID" \
     --group legacy --output "$PRIVATE_EVID/tasks-legacy.json"
   python3 scripts/merge-api-task-exports.py --input-dir "$PRIVATE_EVID" \
     --group unified_shadow --output "$PRIVATE_EVID/tasks-shadow.json"
   python3 scripts/merge-api-task-exports.py --input-dir "$PRIVATE_EVID" \
     --group stage_gated_rust --output "$PRIVATE_EVID/tasks-rust.json"
   ```

   将三组私有导出整理成 `$PRIVATE_EVID/release-groups.json`，必须使用以下字段：
   `metadata.revision/image_digest/config_fingerprint/target_set_sha256`；每个 group 的每个
   target 必须包含 `target_id/endpoints/terminal_status/waf`，每个 Endpoint 至少包含
   `url/method/api_type/status/sources`。原始目标、URL 和任务响应只允许存在于
   `$PRIVATE_EVID`，最终报告只存哈希和计数。整理完成后执行：

   ```bash
   python3 ARL/app/tools/collect_wih_baseline.py \
     --input "$PRIVATE_EVID/tasks-legacy.json" --output "$PRIVATE_EVID/baseline-legacy.json"
   python3 ARL/app/tools/collect_wih_baseline.py \
     --input "$PRIVATE_EVID/tasks-shadow.json" --output "$PRIVATE_EVID/baseline-shadow.json"
   python3 ARL/app/tools/collect_wih_baseline.py \
     --input "$PRIVATE_EVID/tasks-rust.json" --output "$PRIVATE_EVID/baseline-rust.json"
   python3 ARL/app/tools/validate_wih_baseline.py --input "$PRIVATE_EVID/baseline-legacy.json" \
     --target-count 40 --min-runs 1
   python3 ARL/app/tools/validate_wih_baseline.py --input "$PRIVATE_EVID/baseline-shadow.json" \
     --target-count 40 --min-runs 1
   python3 ARL/app/tools/validate_wih_baseline.py --input "$PRIVATE_EVID/baseline-rust.json" \
     --target-count 40 --min-runs 1
   python3 ARL/app/tools/compare_task_baseline.py \
     --python "$PRIVATE_EVID/baseline-legacy.json" --rust "$PRIVATE_EVID/baseline-shadow.json" \
     --target-count 40 --min-runs 1 \
     --stage wih_api_doc_unified --stage wih_endpoint_followup_probe
   python3 ARL/app/tools/compare_task_baseline.py \
     --python "$PRIVATE_EVID/baseline-shadow.json" --rust "$PRIVATE_EVID/baseline-rust.json" \
     --target-count 40 --min-runs 1 \
     --stage wih_api_doc_unified --stage wih_endpoint_followup_probe
   ```

   判定：`api_stage_wall_time` p95 恶化 ≤5%；`api_stage_network_wait_time` 按 §4.20
   新口径（只含真实 `http_req`）；结果集合与 Endpoint 集合不减少（下节 hash 对账）。

## 3. 结果集合一致性（Endpoint 集合 hash）

对每组任务整理 `$PRIVATE_EVID/release-groups.json` 后，使用仓库现有比较器生成脱敏报告；
比较器会校验三组 metadata、目标集合、Endpoint 完整 identity、终态和 WAF 摘要，报告只输出
目标哈希、Endpoint 哈希和计数：

```bash
python3 scripts/compare-release-groups.py \
  --input "$PRIVATE_EVID/release-groups.json" \
  --target-count 40 \
  --output "$EVID/release-groups-report.json" \
  || { echo "三组 Endpoint/终态/WAF 对账失败，禁止进入 64 目标" >&2; exit 1; }
```

门禁：shadow 组 vs legacy 组集合差集必须逐条可解释（统一面新增 api_type/越界证据候选为允许增量，附录 A §4.12"越界证据化是唯一允许缺失面"）；rust 组 vs shadow 组**必须逐字节等集**（stage-gated 语义）。

## 4. 40 目标协同专项（先于 64）

目标文件必须来自授权清单，并在执行前固定 hash：

```bash
TARGETS_40="${TARGETS_40:?授权的 40 目标文件路径}"
TARGETS_64="${TARGETS_64:?授权的 64 目标文件路径}"
sha256sum "$TARGETS_40" > "$EVID/targets-40.sha256"
sha256sum "$TARGETS_64" > "$EVID/targets-64.sha256"
```

任务提交后采集（每目标一条任务，同端口档位/同配置）：
- 数据联通：`js_intel → api_doc_url → 统一文档队列当前任务内消费`（`api_document_*` 计数与 `wih_api_doc_unified` 阶段日志）；
- 重复请求：按 T5/A8 四类口径出报表——`network_request_count`/`cache_hit_count`/
  `actual_duplicate_request_count`/`external_network_*`；`api_document_cross_bucket_hit_total` 为复用面；
- WAF 隔离：`api_probe_waf_blocked_total` 只停 endpoint_probe 类、`api_document_waf_blocked_total` 只停 api_doc 类、主机级封禁才 `degraded/host_waf_blocked`（资产面 `degraded_reason` 可归因，附录 A §4.20）；
- 首批可见 ≤5 分钟、终态家族正确（done/done_pending/done_degraded）；账本降级阈值（`LEDGER_DEGRADED_THRESHOLD`）如触发，done_degraded + `pending_backlog|ledger` 必须可见。
- 第 10 批 T10-A 口径出数：`api_doc_url` 记录面扩大的真实增量数与 `pending_backlog|api` 显影存量。

40 目标门禁通过后，用同一套三组流程执行 64 目标冷/热两轮。每组必须等待任务进入终态、
完成导出后才能切换下一组，避免运行中的任务跨组读取配置：

```bash
PRIVATE_EVID_ROOT="$PRIVATE_EVID"
for mode in cold hot; do
  for group in legacy unified_shadow stage_gated_rust; do
    PRIVATE_EVID="$PRIVATE_EVID_ROOT/64-${mode}-${group}"
    mkdir -p "$PRIVATE_EVID"
    chmod 700 "$PRIVATE_EVID"
    run_release_group "$group"
    submit_group_tasks "$group" "$TARGETS_64"
    wait_group_tasks "$group"
    collect_group_exports "$group"
  done
done
```

64 目标基线使用 `merge-api-task-exports.py` 合并每个私有目录，再按
`--target-count 64 --min-runs 2` 执行 `validate_wih_baseline.py` 和
`compare_task_baseline.py`；冷/热两轮必须都被纳入同一组 baseline，不能只保留 p95 较好的轮次。

## 5. 回滚

全部单键回退，无数据迁移（`API_UNIFIED_ENABLE` 默认 False 期间统一层从未成为事实源）：

| 现象 | 回滚动作 | 生效面 |
|---|---|---|
| Endpoint 集合减少/异常 | `API_UNIFIED_ENABLE=false`（代码默认即此态） | 单任务起 |
| 某 stage native 行为异常 | 从 `RUST_ACCEL_API_UNIFIED_RUST_STAGES` 移除该 stats_prefix（保持 shadow） | 即时 |
| Rust 面需全停 | `RUST_ACCEL_API_UNIFIED_MODE=off` | 即时 |
| 降级/fallback 失效 | `RUST_ACCEL_FALLBACK_ENABLE=true`、`API_UNIFIED_FALLBACK_ENABLE=true` | 即时 |

回滚后仍需保留 `$EVID/` 现场（任务导出、日志）供归因，不得事后改写证据。

## 5.1 Worker consumer/control-plane 运行时检查

重建并强制重建 worker 后，必须确认启动日志同时出现四个队列的健康标记：

```bash
for container in arl_worker_1 arl_worker_2; do
  docker logs --since 2m --timestamps "$container" 2>&1 \
    | grep -E 'worker consumer health inspect_ok=1 healthy=1 .*arlheavy=1.*arltask=1'
done
```

在单目标 smoke 运行期间，继续采集同一日志窗口；若出现 `healthy=0`，或连续三次
`celery consumer health check failed`，该轮不得进入 40 目标验收。该检查用于覆盖“Celery
主进程/PID 仍存活但 AMQP consumer 已消失”的故障模式，不替代任务终态、RabbitMQ 队列和
Endpoint 导出。

## 5.2 开发期离线代码门禁

在不连接 Mongo、RabbitMQ、Web API 或外部目标的情况下，可运行：

```bash
python3 scripts/plan567-code-check.py --plan 6
```

该命令逐模块启动独立 Python 进程，检查统一 API 模型、Parser、Registry、shadow、发布组
离线比较器和 WIH baseline 校验器。它只能证明代码回归通过，不能替代本 runbook 的双架构、
40/64 目标、Rust 性能或真实 worker consumer 门禁。

## 6. 完成定义

- [ ] 两架构 §1 全绿（含 hygiene polluted=0）
- [ ] x86 真机 §2 基准 + stage-gated 三组对照 ≤5% 恶化
- [ ] §3 三组集合 hash 对账可解释
- [ ] §4 40 目标专项四要点出数
- [ ] 64 目标两轮（冷/热）与首批 p95 门禁
- [ ] 以上齐备后才进入 `API_UNIFIED_ENABLE` 默认切换评审（§十三流程）；任一缺失保持默认关闭，不以本地单测或 qemu 数据替代。
- [ ] worker consumer/control-plane 启动与运行期检查通过，单目标 smoke 无健康告警。
