# _*_ coding:utf-8 _*_
import requests
import re

# # findall: 匹配字符串中所以符合正则的内容，返回列表
# list  = re.findall(r"\d+", 'phone number is 10086, the another is 10010')
# print(list)
#
# # finditer: 匹配字符串中所有内容，返回的是迭代器，拿数据用 .group()
# it = re.finditer(r"\d+", 'phone number is 10086, the another is 10010')
# for i in it:
#     print(i.group())

# # search: 全文匹配，找到一个结果就返回，返回的是match对象，拿数据用 .group()
# s = re.search(r"\d+", 'phone number is 10086, the another is 10010')
# print(s.group())

# # match: 从头开始匹配
# s = re.match(r"\d+", 'phone number is 10086, the another is 10010')
# print(s.group)

# # 预加载正则
# obj = re.compile(r"\d+")
# s = re.findall(obj,'phone number is 10086, the another is 10010')
# print(s)

s = '''
<div class='a1'><span id ='1'>aa</span></div>
<div class='b2'><span id ='2'>bb</span></div>
<div class='c3'><span id ='3'>cc</span></div>
<div class='d4'><span id ='4'>dd</span></div>
<div class='e5'><span id ='5'>ee</span></div>
'''

                                                            # (?P<分组名>正则) 从正则中提取到分组名内容
obj = re.compile(r"<div class='.*?'><span id ='(?P<id>\d+)'>(?P<name>.*?)</span></div>", re.S)  #re.S 能让. 匹配换行符
res = obj.finditer(s)
print(res)
for i in res:
    print(i.group('id'), i.group('name'))