import pymysql
from dbutils.pooled_db import PooledDB
from pymysql import cursors
POOL=PooledDB(
    creator=pymysql, # 使用链接数据库的模块
    maxconnections=10,# 连接池允许的最大连接数，0和None表示不限制连接数
    mincached=2,# 初始化时，链接池中至少创建的空闲的链接，0表示不创建
    maxcached=3,# 链接池中最多闲置的链接，0和None不限制
    blocking=True,# 连接池中如果没有可用链接后，是否阻塞等待，True等待，False不等待然后报错
    setsession=[],# 开始会话前执行的命令列表,是否阻塞等待，True等待,False不等待然后报错
    ping=0,# ping Mysql服务器，检查是否服务可用

    host='localhost',port=3306,user='root',password='Wmy142739',database='misai',charset='utf8'
)

def fetch_one(sql,params):
    conn=POOL.connection()
    cursor=conn.cursor(cursor=cursors.DictCursor) # "cursors.DictCursor"使这个游标可以返回字典格式的数据
    cursor.execute(sql,params)
    result=cursor.fetchone() # fetchone()只返回一条数据,返回匹配成功时的第一条数据
    print("数据库匹配到的用户数据：",result)
    cursor.close()
    conn.close() # 引入连接池后，这一步就不是关闭连接，而是释放资源,把链接放回连接池了
    return result

def fetch_all(sql,params):
    conn=POOL.connection()
    cursor=conn.cursor(cursor=cursors.DictCursor) # "cursors.DictCursor"使这个游标可以返回字典格式的数据
    cursor.execute(sql,params)
    result=cursor.fetchall() # fetchall()返回匹配成功的所有数据
    # print(result)
    cursor.close()
    conn.close() # 引入连接池后，这一步就不是关闭连接，而是释放资源,把链接放回连接池了
    return result

def insert(sql,params):
    conn=POOL.connection()
    cursor=conn.cursor(cursor=cursors.DictCursor) # "cursors.DictCursor"使这个游标可以返回字典格式的数据
    cursor.execute(sql,params)
    conn.commit() # 提交事务,在执行创建，删除的数据库操作时要提交事务
    cursor.close()
    conn.close() # 引入连接池后，这一步就不是关闭连接，而是释放资源,把链接放回连接池了
    return cursor.lastrowid # 返回插入数据的主键id,也是最后一条数据的id


if __name__ == '__main__':
    # 连接MySQL数据库，并执行SQL语句查询用户名和密码是否正确
    sql = "select * from userinfo where role=%s and mobile=%s and password=%s"
    user_dict=fetch_one(sql,[1,19303272074,123123])
    print(user_dict)
