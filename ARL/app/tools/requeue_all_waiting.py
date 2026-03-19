import sys
import bson
from app.utils import conn_db, get_logger
from app import celerytask
from app.modules import TaskType, CeleryAction

logger = get_logger()

type_map_action = {
    TaskType.DOMAIN: CeleryAction.DOMAIN_TASK,
    TaskType.IP: CeleryAction.IP_TASK,
    TaskType.RISK_CRUISING: CeleryAction.RUN_RISK_CRUISING,
    TaskType.ASSET_SITE_UPDATE: CeleryAction.ASSET_SITE_UPDATE,
    TaskType.FOFA: CeleryAction.FOFA_TASK,
    TaskType.ASSET_SITE_ADD: CeleryAction.ADD_ASSET_SITE_TASK,
    TaskType.ASSET_WIH_UPDATE: CeleryAction.ASSET_WIH_UPDATE,
}

def recover():
    logger.info("Purging celery queue...")
    try:
        celerytask.celery.control.purge()
    except Exception as e:
        logger.warning("purge error: %s", e)
    
    tasks = list(conn_db('task').find({"status": "waiting"}))
    for t in tasks:
        task_id = str(t["_id"])
        action = type_map_action.get(t.get("type"))
        if not action:
            continue
            
        options = {
            "celery_action": action,
            "data": {**t, "task_id": task_id, "_id": task_id}
        }
        
        queue_name = t.get("dispatch_queue", "arltask")
        qt = celerytask.arl_task_heavy if queue_name == "arlheavy" else celerytask.arl_task
        
        cid = qt.delay(options=options)
        conn_db('task').update_one({"_id": bson.ObjectId(task_id)}, {"$set": {"celery_id": str(cid)}})
        logger.info("Re-queued task %s", task_id)

    g_tasks = list(conn_db('github_task').find({"status": "waiting"}))
    for t in g_tasks:
        task_id = str(t["_id"])
        action = CeleryAction.GITHUB_TASK_MONITOR if t.get("task_tag") == "monitor" else CeleryAction.GITHUB_TASK_TASK
        
        options = {
            "celery_action": action,
            "data": {**t, "task_id": task_id, "_id": task_id}
        }
        
        cid = celerytask.arl_github.delay(options=options)
        conn_db('github_task').update_one({"_id": bson.ObjectId(task_id)}, {"$set": {"celery_id": str(cid)}})
        logger.info("Re-queued github_task %s", task_id)
    
    logger.info("recover done.")

if __name__ == "__main__":
    recover()
# 脚本作用：清理 MQ 并且将所有数据库中状态为 waiting 的任务强制重新打入 Celery 排队
