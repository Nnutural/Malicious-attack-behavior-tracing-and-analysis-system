"""项目配置文件"""
import os


class Config:
    """基础配置"""
    # Flask 配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-for-traceback-system'

    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///traceback. db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 上传文件配置
    UPLOAD_FOLDER = 'data/uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

    # 分析配置
    TIME_WINDOW = 300  # 时间窗口（秒）
    ATTCK_THRESHOLD = 0.7  # ATT&CK 匹配阈值
    MAX_PROCESS_DEPTH = 10  # 进程树最大深度

    # 知识库路径
    KNOWLEDGE_BASE_PATH = 'knowledge_base/'
    ATTCK_DATA_FILE = 'knowledge_base/attck_techniques.json'