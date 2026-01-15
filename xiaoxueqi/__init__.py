"""Flask 应用工厂"""
from flask import Flask
from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # 注册蓝图
    from .views.main import bp as main_bp
    from .views.dashboard import bp as dashboard_bp
    from .views.log_view import bp as log_bp, api_bp as logontracer_api_bp
    from .views.behavior_view import bp as behavior_bp
    from .views.traffic_view import bp as traffic_bp
    from .views.attack_view import bp as attack_bp
    from .views.traceback_view import bp as traceback_bp

    app.register_blueprint(main_bp)  # /
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(log_bp, url_prefix='/logs')
    app.register_blueprint(logontracer_api_bp, url_prefix='/api')
    app.register_blueprint(behavior_bp, url_prefix='/behavior')
    app.register_blueprint(traffic_bp, url_prefix='/traffic')
    app.register_blueprint(attack_bp, url_prefix='/attack')
    app.register_blueprint(traceback_bp, url_prefix='/traceback')

    return app
