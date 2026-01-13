"""
SQL Server 简单版 db.py（不使用连接池）

特点：
- 每次操作：新建连接 -> 执行 -> 提交/关闭
- 代码简单，适合你当前阶段快速跑通
- 缺点：频繁调用时性能不如连接池，但对小项目/开发阶段足够

依赖：
pip install pyodbc
"""

import pyodbc
from config import Config


def get_conn(conn_str: str | None = None):
    """获取一个新的数据库连接"""
    return pyodbc.connect(conn_str or Config.SQL_CONN_STR)


def fetch_one(sql, params=None, conn_str: str | None = None):
    """查询一条，返回 dict；没有数据返回 None"""
    conn = get_conn(conn_str)
    cursor = conn.cursor()
    cursor.execute(sql, params or [])
    row = cursor.fetchone()
    if row is None:
        cursor.close()
        conn.close()
        return None
    columns = [col[0] for col in cursor.description]
    result = dict(zip(columns, row))
    cursor.close()
    conn.close()
    return result


def fetch_all(sql, params=None, conn_str: str | None = None):
    """查询多条，返回 dict 列表"""
    conn = get_conn(conn_str)
    cursor = conn.cursor()

    cursor.execute(sql, params or [])
    rows = cursor.fetchall()

    columns = [col[0] for col in cursor.description]
    result = [dict(zip(columns, r)) for r in rows]

    cursor.close()
    conn.close()
    return result


def execute(sql, params=None, conn_str: str | None = None):
    """
    执行写操作（INSERT/UPDATE/DELETE）
    返回：受影响行数
    """
    conn = get_conn(conn_str)
    cursor = conn.cursor()

    cursor.execute(sql, params or [])
    conn.commit()

    rowcount = cursor.rowcount
    cursor.close()
    conn.close()
    return rowcount


if __name__ == "__main__":
    # 1) 测试连接：看一下当前数据库名
    print(fetch_one("SELECT DB_NAME() AS db_name"))

    # 2) 测试查询：查最新一条网络流量
    print(fetch_one("SELECT TOP 1 * FROM dbo.NetworkTraffic ORDER BY create_time DESC"))

    # 3) 测试写入：插入一条网络流量
    print(
        "插入影响行数：",
        execute(
            "INSERT INTO dbo.NetworkTraffic (result, content) VALUES (?, ?)",
            ["{test:1}", "hello traffic (no pool)"]
        )
    )
