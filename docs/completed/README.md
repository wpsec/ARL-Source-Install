# 已完成文档

本目录保存已经完成并闭环、且不再作为当前执行依据的独立文档。

## 当前内容

- `[已完成]04-附录A-API契约冻结清单.md`：计划 4 UI 重构的 API 契约冻结基线。
- `[已完成]05-附录A-指纹现状冻结清单.md`：计划 5 指纹现状取证基线。
- `[已完成]05-附录B-local增量审计报告.md`：计划 5 local 指纹增量审计结果。
- `[已完成]06-附录A-API契约冻结清单.md`：计划 6 API 统一解析契约冻结基线。
- [Strix-cn 兼容性预检报告](./[已完成]Strix-cn兼容性预检报告.md)：预检结论已完成，生产集成未通过，因此不代表 Strix-cn 已上线。

计划 1–7 的开发正文、附录 D/E、WIH 调度专项和统一发现系统紧急修复方案已移至 `../history/`；本目录继续只保存已经完成并闭环的独立文档。冻结清单已经闭环：04/05 附录 A 由脚本按固定路径再生（`scripts/freeze-api-contract.py`、`scripts/fingerprint-baseline.py`），输出指向本目录；06 附录 A 的机器可验基线由 `scripts/api-unified-golden.py` 生成至 `ARL/test/fixtures/api_unified/expected/`，本目录内文档为人工维护的语义冻结说明。
