#!/usr/bin/env python3
"""
功能说明：运行环境修复显式 bootstrap 入口（任务 tag、Mongo 索引、NPoC 数据同步）。

背景：
- 原实现挂在 app.main 导入期执行 arl_update()，任何仅导入路由的进程都带上写副作用。
- 本入口把它收口为 start_web.sh 在 gunicorn 启动前的显式步骤，导入路径保持纯净。

主要函数：
- main: 执行一次 arl_update 并以退出码反馈结果

幂等性：arl_update 内部有 TMP_PATH/arl_update.lock 文件锁，重复执行为安全空转。
"""
import sys

from app.utils import arl_update


def main() -> int:
    try:
        arl_update()
    except Exception as exc:
        # 启动前置修复失败不应静默成功：返回非零由调用脚本决定是否继续。
        print("arl bootstrap update failed error_type:{}".format(type(exc).__name__))
        return 1
    print("arl bootstrap update done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
