# _*_ coding:utf-8 _*_
import pymysql

# 打开数据库
conn = pymysql.connect('localhost', user='root', password='root', db='npc')
print(conn)

# 获取游标
cursor = conn.cursor()
print(cursor)

sql_select = """
select * from npc_user
"""

cursor.execute(sql_select)         # execute()执行单条SQL语句，返回的是受影响的行数

while 1:
    res = cursor.fetchone()        # 获取游标所在处的一行数据，返回元组，没有返回None
    if res is None:
        break
    print(res)

cursor.close()              # 关闭游标
conn.close()                # 关闭数据库连接