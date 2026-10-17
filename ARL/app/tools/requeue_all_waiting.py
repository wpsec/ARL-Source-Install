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

if __name__ == "__main__":
    recover()
