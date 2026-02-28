"""
站点截图访问模块

功能说明：
- 提供站点截图图片的访问接口
- 支持按任务ID和文件名获取截图
- 自动处理截图不存在的情况

截图存储：
- 存储路径：screenshot_dir/task_id/filename.jpg
- 支持格式：jpg、png
- 失败时返回默认图片

使用场景：
- 前端展示站点截图
- 快速预览站点外观
- 辅助资产识别
"""
import os
import re
from flask import make_response, request
from flask_restx import Resource, Namespace
from app import utils
from app.config import Config
from app.modules import ErrorMsg
from app.utils import get_logger, auth
from werkzeug.utils import secure_filename

ns = Namespace('image', description="截图信息")

logger = get_logger()
TASK_ID_PATTERN = re.compile(r"^[a-f0-9]{24}$")


def allowed_file(filename):
    """
    检查文件扩展名是否允许
    
    参数：
        filename: 文件名
    
    返回：
        bool: 是否允许
    
    说明：
    - 只允许jpg和png格式
    - 用于防止路径遍历攻击
    """
    allowed_extensions = ['jpg', 'jpeg', 'png']
    if '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in allowed_extensions


def check_image_magic(file_name, file_data):
    """
    通过图片魔数校验文件内容，避免回传任意二进制文件。
    """
    ext = file_name.rsplit('.', 1)[1].lower()
    if ext in ['jpg', 'jpeg']:
        return file_data.startswith(b"\xff\xd8")
    if ext == 'png':
        return file_data.startswith(b"\x89PNG\r\n\x1a\n")
    return False


@ns.route('/<string:task_id>/<string:file_name>')
class ARLImage(Resource):
    """站点截图访问接口"""

    def get(self, task_id, file_name):
        """
        获取站点截图图片
        
        参数：
            task_id: 任务ID
            file_name: 截图文件名
        
        返回：
            图片数据（JPG格式）
        
        说明：
        - 文件名会经过安全过滤，防止路径遍历
        - 只允许访问jpg和png格式
        - 截图不存在时返回默认失败图片
        - 截图路径：screenshot_dir/{task_id}/{file_name}
        
        使用示例：
        - /api/image/60a1b2c3d4e5f6789/example_com.jpg
        """
        # 安全过滤文件名，防止路径遍历攻击
        task_id = secure_filename(task_id)
        file_name = secure_filename(file_name)
        
        # 检查文件扩展名
        if not allowed_file(file_name):
            return
        
        # 构建截图文件路径
        imgpath = os.path.join(Config.SCREENSHOT_DIR,
                               '{task_id}/{file_name}'.format(task_id=task_id,
                                                              file_name=file_name))
        
        # 返回截图或默认图片
        if os.path.exists(imgpath):
            with open(imgpath, "rb") as f:
                image_data = f.read()
            response = make_response(image_data)
            response.headers['Content-Type'] = 'image/jpg'
            return response
        else:
            # 截图不存在，返回默认失败图片
            with open(Config.SCREENSHOT_FAIL_IMG, "rb") as f:
                image_data = f.read()
            response = make_response(image_data)
            response.headers['Content-Type'] = 'image/jpg'
            return response


@ns.route('/internal/upload')
class ARLImageInternalUpload(Resource):
    """
    worker 截图回传接口（仅内部调用）
    """

    @auth
    def post(self):
        """
        截图回传：
        - 复用系统 Token 鉴权（ARL.AUTH / ARL.API_KEY）
        - 严格校验 task_id / file_name / 文件大小 / 图片魔数
        """
        if not Config.SCREENSHOT_SYNC_ENABLE:
            return {
                "code": 403,
                "message": "screenshot sync is disabled",
                "data": {}
            }

        raw_task_id = str(request.form.get("task_id", "")).strip().lower()
        raw_file_name = str(request.form.get("file_name", "")).strip()
        upload_file = request.files.get("file")

        if upload_file is None:
            return utils.build_ret(ErrorMsg.Error, {"msg": "file is required"})

        if not raw_file_name:
            raw_file_name = str(upload_file.filename or "").strip()

        task_id = secure_filename(raw_task_id)
        file_name = secure_filename(raw_file_name)
        if task_id != raw_task_id or not TASK_ID_PATTERN.fullmatch(task_id):
            return {
                "code": 400,
                "message": "invalid task_id",
                "data": {}
            }

        if not file_name or not allowed_file(file_name):
            return {
                "code": 400,
                "message": "invalid file_name",
                "data": {}
            }

        file_data = upload_file.read()
        if not file_data:
            return {
                "code": 400,
                "message": "file content is empty",
                "data": {}
            }

        if len(file_data) > Config.SCREENSHOT_SYNC_MAX_SIZE:
            return {
                "code": 413,
                "message": "file too large",
                "data": {"max_size": Config.SCREENSHOT_SYNC_MAX_SIZE}
            }

        if not check_image_magic(file_name, file_data):
            return {
                "code": 400,
                "message": "invalid image content",
                "data": {}
            }

        screenshot_dir = os.path.join(Config.SCREENSHOT_DIR, task_id)
        os.makedirs(screenshot_dir, 0o777, True)
        save_path = os.path.join(screenshot_dir, file_name)
        with open(save_path, "wb") as f:
            f.write(file_data)

        logger.info("screenshot sync save success task_id={} file={}".format(task_id, file_name))
        return utils.build_ret(ErrorMsg.Success, {"task_id": task_id, "file_name": file_name})




