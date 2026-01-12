from.import db

# 查询用户的测试历史，分页
def fetch_user_history(user_id,size,offset):
    # 查询分页数据
    sql_items = """
                SELECT test_id, algorithm, indicator, test_case, create_time, value, input_data
                FROM test_history
                WHERE user_id=%s
                ORDER BY create_time DESC
                    LIMIT %s \
                OFFSET %s \
                """
    items = db.fetch_all(sql_items, [user_id, size, offset])
    # 查询总数
    sql_total = "SELECT COUNT(*) AS total FROM test_history WHERE user_id=%s"
    total_row = db.fetch_one(sql_total, [user_id])
    total = total_row['total'] if total_row else 0
    return items,total

# 插入测试历史记录到test_history表
def insert_test_history(params):
    # params=[user_id, algorithm, indicator, test_case, value, input_data]
    sql = "INSERT INTO test_history (user_id, algorithm, indicator, test_case, value, input_data) VALUES (%s,%s,%s,%s,%s,%s)"
    db.insert(sql, params)

# 插入测试历史记录到后量子密码的表
def insert_pqc_history(params, table_name):
    # params=[user_id, algorithm, indicator, mode, value]
    sql = f"INSERT INTO {table_name} (user_id, algorithm, indicator, mode, value ) VALUES (%s,%s,%s,%s,%s)"
    db.insert(sql, params)

# 分页查询 后量子密码 的历史记录
def fetch_pqc_history(user_id, size, offset, algorithm):
    sql_items = f"""
        SELECT {algorithm}_id, algorithm, indicator, mode, value, create_time
        FROM {algorithm}_table
        WHERE user_id=%s
        ORDER BY create_time DESC
        LIMIT %s OFFSET %s
    """
    items = db.fetch_all(sql_items, [user_id, size, offset])

    sql_total = f"SELECT COUNT(*) AS total FROM {algorithm}_table WHERE user_id=%s"
    total_row = db.fetch_one(sql_total, [user_id])
    total = total_row['total'] if total_row else 0
    return items, total

