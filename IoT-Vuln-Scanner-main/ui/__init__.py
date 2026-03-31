# ui\__init__.py
# -*- coding: utf-8 -*-
from flask import Flask
from .device_list import device_bp


def create_app(config_name=None):
    """
    Flask应用工厂函数
    """
    import os

    # 确定模板和静态文件路径
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

    app = Flask(__name__,
                template_folder=template_dir,
                static_folder=static_dir)

    # 配置
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    app.config['JSON_AS_ASCII'] = False
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB上传限制

    # 注册蓝图
    app.register_blueprint(device_bp)

    # 错误处理
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Not found"}, 404

    @app.errorhandler(500)
    def internal_error(error):
        return {"error": "Internal server error"}, 500

    return app


# 兼容直接导入（某些旧代码可能用 from ui import app）
app = create_app()