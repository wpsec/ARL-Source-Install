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
from flask import  make_response
from flask_restx import Resource, Namespace
import os
from app.config import Config
from app.utils import get_logger
from werkzeug.utils import secure_filename

ns = Namespace('image', description="截图信息")

logger = get_logger()


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
    ALLOWED_EXTENSIONS = ['jpg','png']
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


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
            image_data = open(imgpath, "rb").read()
            response = make_response(image_data)
            response.headers['Content-Type'] = 'image/jpg'
            return response
        else:
            # 截图不存在，返回默认失败图片
            image_data = open(Config.SCREENSHOT_FAIL_IMG, "rb").read()
            response = make_response(image_data)
            response.headers['Content-Type'] = 'image/jpg'
            return response








