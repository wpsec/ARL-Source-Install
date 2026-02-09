"""
用户管理模块

功能：
- 用户登录认证
- 用户登出
- 修改密码

说明：
- 用户认证基于Token机制
- Token存储在请求头中
- 支持修改密码功能
"""
from flask import request
from flask_restx import fields, Namespace
from app.utils import get_logger
from app import utils
from . import  ARLResource
from app import modules

ns = Namespace('user', description="管理员登录认证")

logger = get_logger()


# 登录请求模型
login_fields = ns.model('LoginARL', {
    'username': fields.String(required=True, description="用户名"),
    'password': fields.String(required=True, description="密码"),
})


@ns.route('/login')
class LoginARL(ARLResource):
    """用户登录接口"""

    @ns.expect(login_fields)
    def post(self):
        """
        用户登录认证
        
        请求体：
            {
                "username": "用户名",
                "password": "密码"
            }
        
        返回：
            {
                "code": 200,
                "message": "success",
                "data": {
                    "token": "认证Token",
                    "username": "用户名"
                }
            }
        
        说明：
        - 登录成功返回Token，用于后续API认证
        - Token需要放在请求头的 Token 字段中
        - 登录失败返回401错误
        
        示例：
            POST /api/user/login
            {
                "username": "admin",
                "password": "admin123"
            }
        """
        args = self.parse_args(login_fields)

        return build_data(utils.user_login(**args))




@ns.route('/logout')
class LogoutARL(ARLResource):
    """用户登出接口"""

    def get(self):
        """
        用户登出
        
        请求头：
            Token: 用户的认证Token
        
        返回：
            {
                "code": 200,
                "message": "success",
                "data": {}
            }
        
        说明：
        - 登出后Token失效
        - 需要重新登录获取新Token
        """
        token = request.headers.get("Token")
        utils.user_logout(token)

        return build_data({})


# 修改密码请求模型
change_pass_fields = ns.model('ChangePassARL', {
    'old_password': fields.String(required=True, description="旧密码"),
    'new_password': fields.String(required=True, description="新密码"),
    'check_password': fields.String(required=True, description="确认密码"),
})


@ns.route('/change_pass')
class ChangePassARL(ARLResource):
    """修改密码接口"""
    
    @ns.expect(change_pass_fields)
    def post(self):
        """
        修改用户密码
        
        请求头：
            Token: 用户的认证Token
        
        请求体：
            {
                "old_password": "旧密码",
                "new_password": "新密码",
                "check_password": "确认新密码"
            }
        
        返回：
            {
                "code": 200|301|302|303,
                "message": "操作结果说明",
                "data": {}
            }
        
        返回码说明：
            - 200: 修改成功
            - 301: 新密码和确认密码不一致
            - 302: 新密码不能为空
            - 303: 旧密码错误
        
        说明：
        - 修改成功后会自动登出，需要使用新密码重新登录
        - 新密码和确认密码必须一致
        - 需要提供正确的旧密码
        """
        args = self.parse_args(change_pass_fields)
        ret = {
            "message": "success",
            "code": 200,
            "data": {}
        }
        token = request.headers.get("Token")

        # 检查新密码和确认密码是否一致
        if args["new_password"] != args["check_password"]:
            ret["code"] = 301
            ret["message"] = "新密码和确定密码不一致"
            return ret

        # 检查新密码是否为空
        if not args["new_password"]:
            ret["code"] = 302
            ret["message"] = "新密码不能为空"
            return ret

        # 修改密码
        if utils.change_pass(token, args["old_password"], args["new_password"]):
            # 修改成功后自动登出
            utils.user_logout(token)
        else:
            ret["message"] = "旧密码错误"
            ret["code"] = 303

        return ret


def build_data(data):
    """
    构建返回数据格式
    
    参数：
        data: 业务数据，如果为None或False表示失败
    
    返回：
        统一格式的响应数据
    """
    ret = {
        "message": "success",
        "code": 200,
        "data": {}
    }

    if data:
        ret["data"] = data
    else:
        ret["code"] = 401

    return ret



