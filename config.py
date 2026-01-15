"""项目配置文件"""
import os


class Config:
    """基础配置"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-for-traceback-system'

    # ========== SQL Server 连接串（给 pyodbc/dbutils 用）==========
    # 你也可以通过环境变量覆盖（更安全）
    DB_DRIVER = os.environ.get("DB_DRIVER") or "ODBC Driver 17 for SQL Server"
    DB_SERVER = os.environ.get("DB_SERVER") or "10.21.226.213,1433"  #10.21.226.213  10.21.211.11
    DB_DATABASE = os.environ.get("DB_DATABASE") or "SecurityTraceDB"
    DB_USERNAME = os.environ.get("DB_USERNAME") or "sa"
    DB_PASSWORD = os.environ.get("DB_PASSWORD") or "123123"

    SQL_CONN_STR = (
        f"DRIVER={{{DB_DRIVER}}};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_DATABASE};"
        f"UID={DB_USERNAME};"
        f"PWD={DB_PASSWORD};"
        "TrustServerCertificate=yes;"
    )

    @classmethod
    def build_sql_conn_str(cls, server: str | None = None) -> str:
        db_server = server or cls.DB_SERVER
        return (
            f"DRIVER={{{cls.DB_DRIVER}}};"
            f"SERVER={db_server};"
            f"DATABASE={cls.DB_DATABASE};"
            f"UID={cls.DB_USERNAME};"
            f"PWD={cls.DB_PASSWORD};"
            "TrustServerCertificate=yes;"
        )

    # 下面 SQLAlchemy 的配置你当前用不到，可以先留空或保留原样（避免别处引用报错）
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or ''
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = 'data/uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

    TIME_WINDOW = 300
    ATTCK_THRESHOLD = 0.7
    MAX_PROCESS_DEPTH = 10

    KNOWLEDGE_BASE_PATH = 'knowledge_base/'
    ATTCK_DATA_FILE = 'knowledge_base/attck_techniques.json'
