"""为隔离浏览器链路临时建立登录用户。"""

import os
import sys

from pymongo import MongoClient

from app.config import Config
from app.utils.user import gen_md5, salt


def main(action):
    username = os.environ["ARL_SYSTEM_TEST_UI_USERNAME"]
    password = os.environ["ARL_SYSTEM_TEST_UI_PASSWORD"]
    client = MongoClient(Config.MONGO_URL, serverSelectionTimeoutMS=3000)
    try:
        users = client[Config.MONGO_DB].user
        if action == "create":
            users.update_one(
                {"username": username},
                {"$set": {"password": gen_md5(salt + password), "token": None}},
                upsert=True,
            )
        elif action == "delete":
            users.delete_one({"username": username})
        else:
            raise ValueError("未知用户维护操作")
    finally:
        client.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: system_test_ui_user.py create|delete")
    main(sys.argv[1])
