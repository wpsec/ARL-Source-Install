"""启动 ARL 应用容器进程数心跳上报器。"""

from app.services.system_monitor_processes import main


if __name__ == "__main__":
    main()
