# 计划 6 第 11 批发布验收证据（2026-09-07 起）

按 [附录 E runbook](../../plan/[未完成]06-附录E-计划6发布验收runbook-双架构与40-64目标.md) 归档。授权目标清单与部署机密不进本目录。

## revision / 镜像钉
- 两架构测试镜像同代码基线：`616cce02`（T11-1 identity 收口）；生产修复 `be7d0605` 见 runtime smoke 段
- arm64 镜像 `arl-regression:arm64` = `sha256:cca8da442d1a…`（本机 Apple Silicon 原生）
- amd64 镜像 `arl-regression:amd64` = `sha256:3734d9d24e77…`（x86 真机 wp-kali-linux, 5.9.0-kali1-amd64, 8C/7G）
- 生产镜像 `arl:local`(x86) = `sha256:fe18afc66b53…`（含 `be7d0605`，重建 EXIT=0）

## 文件清单
| 文件 | 内容 |
|---|---|
| `amd64-bench.log` | T11-4 x86 真机 Rust 基准（normalize 0.050 / method 0.458 / hint 0.339 / dedupe 1.030 median 比） |
| `arm64-discover-issues.txt` | arm64 第四轮全量 discover FAIL/ERROR 逐名清单 |
| `amd64-discover-issues.txt` | amd64 首轮 FAIL/ERROR 逐名清单（差分定性见计划 6 T11-4 节） |
| `amd64-hygiene-firstpass.log` | amd64 全量 hygiene（148 clean + test.test_wih timeout） |
| `amd64-test-wih-hygiene-rerun.log` | test_wih 隔离复跑（工具路径仍 timeout，裁定见下） |

## test.test_wih 裁定（复核要求：不得直接归网络桶，须隔离资源复跑）
- **隔离直跑证据**（空载机、`python3 -m unittest test.test_wih`）：**Ran 1 test in 398.756s → OK (rc=0)**——单用例真网 WIH 集成（公网目标），文件本身无槽位污染、可通过。
- hygiene 工具子进程路径在 amd64 上超 1800s 未终且 `HYGIENE_TIMEOUT` 未生效（kill 后进程残留）→ 登记为**工具健壮性调查项**（arm64 jobs=10 正常完成同文件）。
- 定性=两项并列：环境依赖（真网集成时长特性）+ 工具 timeout kill 缺陷；不豁免为产品缺陷，也不满足"149/149 tool-clean"字面。
- 后续建议：test_wih 类真网集成移 mock 或加网络标记（与计划 1 交错专项同批）。

## production runtime smoke（`be7d0605` 二次验证，x86 真机）
- 首轮实锤：`arl_web` 重启循环 16 次，`gunicorn -w` 收到 EFFECTIVE 诊断 JSON（stdout 污染）。
- 修复后新镜像 `arl:local(fe18afc)` 预验证：`import app.config` stdout **0 字节**；命令替换捕获 worker 数 = **纯 `6`**；镜像内 `/usr/bin/start_web.sh` 含整数校验兜底（取末行 + 非数字回退默认）。
- **完整 compose 拉起待用户在机器上创建 `ARL/docker/.env`**（nginx 基础认证参数由部署方提供，不入库、不入证据目录、不由开发侧生成）；web 容器零重启 + 连续健康检查两项在 .env 就绪后闭环。
