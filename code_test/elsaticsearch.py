# _*_ coding:utf-8 _*_'

from elasticsearch import Elasticsearch
from elasticsearch import helpers

host = '10.0.170.110'
port = '9200'
es = Elasticsearch("{host}:{port}".format(host=host, port=port))

print("connect result: {}".format(es))

# 创建一个索引
es.indices.create(index='my_index',ignore=400)

# 定义一些插入操作请求
actions_add = [
    {
        "_index": "my_index",
        "_type": "my_type",
        "_id": "1",
        "_source": {"title": "foo"}
    },
    {
        "_index": "my_index",
        "_type": "my_type",
        "_id": "2",
        "_source": {"title": "bar"}
    },
    {
        "_index": "my_index",
        "_type": "my_type",
        "_id": "3",
        "_source": {"title": "baz"}
    }
]

# 定义一些删除操作请求
actions_del = [
    {
        '_op_type': 'delete',
        "_index": "my_index",
        "_type": "my_type",
        "_id": "1",
    },
    {
        '_op_type': 'delete',
        "_index": "my_index",
        "_type": "my_type",
        "_id": "2",
    },
    {
        '_op_type': 'delete',
        "_index": "my_index",
        "_type": "my_type",
        "_id": "3",
    }
]

# # 使用bulk方法提交请求
# res = helpers.bulk(es, actions_add)
# print("result: {}".format(res))
#
# res = helpers.bulk(es, actions_del)
# print("result: {}".format(res))

# # 添加一条文档
# es.index(index='my_index', id=1, body={'title': 'Hello World', 'content': 'This is my first document.'})
#
# # 搜索文档
# res = es.search(index='my_index', body={'query': {'match': {'title': 'Hello'}}})
# for hit in res['hits']['hits']:
#     print(hit['_source'])

# 查看所有索引，且展示每个索引的详细结构。
indexs = es.indices.get("*")
print("result: {}".format(indexs))

# 查看es中的所有索引的名称
index_names = indexs.keys()
print("result: {}".format(index_names))

# 查看某个索引
index = es.indices.get("index_name")
print("result: {}".format(index))

# 删除一个索引
res = es.indices.delete(index='my_index')
print("result: {}".format(res))

# 判断索引是否存在，存在将会返回True
res = es.indices.exists(index='my_index')
print("result: {}".format(res))