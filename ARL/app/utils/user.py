"""
用户认证和授权工具
"""
from flask import  request
from app import modules
from app.config import Config
from . import gen_md5, random_choices
from .conn import conn_db

salt = 'arlsalt!@#'

def user_login(username = None, password = None):
    if not username or not password:
        return

    query = {"username": username, "password": gen_md5(salt + password)}

    if conn_db('user').find_one(query):
        item = {
            "username": username,
            "token": gen_md5(random_choices(50)),
            "type": "login"
        }
        conn_db('user').update_one(query, {"$set": {"token": item["token"]}})

        return item


def user_login_header():
    # Token 只能通过请求头传递，避免出现在浏览器历史、代理日志和 Referer 中。
    token = request.headers.get("Token")

    if not Config.AUTH:
        return True

    item = {
        "username": "ARL-API",
        "token": Config.API_KEY,
        "type": "api"
    }


    if not token:
        return False

    if token == Config.API_KEY:
        return item


    data = conn_db('user').find_one({"token": token})
    if data:
        item["username"] = data.get("username")
        item["token"] = token
        item["type"] = "login"
        return item

    return False


def current_principal():
    """返回当前请求主体；未认证或关闭认证时返回 None。"""
    principal = user_login_header()
    return principal if isinstance(principal, dict) else None


def request_owner_username():
    """取得当前请求对应的资源归属标识，不接受客户端提交的归属字段。"""
    principal = current_principal()
    if not principal:
        return ""
    return str(principal.get("username") or "").strip()


def can_access_owned_resource(owner_username, principal=None):
    """API 主体可管理全局资源，普通登录主体只能访问自己的资源。"""
    if not Config.AUTH:
        return True
    principal = principal if isinstance(principal, dict) else current_principal()
    if not principal:
        return False
    if principal.get("type") == "api":
        return True
    owner = str(owner_username or "").strip()
    username = str(principal.get("username") or "").strip()
    return bool(owner and username and owner == username)



def user_logout(token):
    if user_login_header():
        conn_db('user').update_one({"token": token}, {"$set": {"token": None}})


def change_pass(token, old_password, new_password):
    query = {"token": token, "password": gen_md5(salt + old_password)}
    data = conn_db('user').find_one(query)
    if data:
        conn_db('user').update_one({"token": token}, {"$set": {"password": gen_md5(salt + new_password)}})
        return True
    else:
        return False


import functools


def auth(func):
    ret = {
        "message": "not login",
        "code": 401,
        "data": {}
    }

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if Config.AUTH and not user_login_header():
            return  ret

        return func(*args, **kwargs)

    return wrapper
