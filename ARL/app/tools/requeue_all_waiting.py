import argparse
import json

from app.utils import get_logger
from app import celerytask

logger = get_logger()


def recover():
    """只恢复确认丢失的消息，保留仍在 Broker 中的任务。"""
    waiting = celerytask.requeue_orphan_waiting_tasks_on_worker_start(
        reason="manual queue recovery"
    )
    deep_scan = celerytask.recover_orphan_domain_deep_tasks_on_worker_start()
    logger.info("recover done waiting=%s deep_scan=%s", waiting, deep_scan)
    return {"waiting": waiting, "deep_scan": deep_scan}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mark-interrupted",
        action="store_true",
        help="仅收口指定的失联深度扫描任务；默认 dry-run",
    )
    parser.add_argument(
        "--task-id",
        action="append",
        default=[],
        help="要检查的任务 ID，可重复指定",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="写入 error/interrupted 终态；必须同时指定 --mark-interrupted",
    )
    args = parser.parse_args(argv)

    if args.mark_interrupted:
        if not args.task_id:
            parser.error("--mark-interrupted 至少需要一个 --task-id")
        result = celerytask.reconcile_stale_domain_deep_tasks(
            args.task_id,
            apply=args.apply,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0

    if args.task_id or args.apply:
        parser.error("--task-id 和 --apply 必须与 --mark-interrupted 一起使用")

    recover()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
