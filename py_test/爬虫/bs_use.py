# _*_ coding:utf-8 _*_
from bs4 import BeautifulSoup
import requests

url = ''
headers = {}

rsp = requests.get(url, headers=headers)
page = BeautifulSoup(rsp.txt, 'html.parser') # 指定html解释器
# 从bs对象查找数据
# find(标签，属性=值) 只找第一个
# find_all(标签，属性=值)  返回所有
table = page.find("table", class_ = "aa")
table = page.find("table", attrs = {
    "class" : "aa"
})
