# _*_ coding:utf-8 _*_
import requests
import re

from py_test.爬虫.爬虫_豆瓣 import page

url = 'https://dytt8.com/'
headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.82'
}
res = requests.get(url, headers=headers) # verify=False 去掉安全认证
res.encoding = 'gb2312'
page_code = res.text

obj = re.compile(r'2023新片精品.*?<ul>(?P<ul>.*?)</ul>', re.S)
s = obj.finditer(page_code)
url_list = []
for i in s:
    ul = i.group('ul')
    obj1 = re.compile(r'最新电影下载.*?<a href=(?P<url>.*?)>2023年.*?《(?P<name>.*?)》.*?</a><br/>')
    s1 = obj1.finditer(ul)
    for j in s1:
        url1 =str(j.group('url'))
        new_url = url1.replace('\'','')
        url_1 = url + new_url
        url_list.append(url_1)
        # print(j.group('url'),j.group('name'))
print(url_list)
for i in url_list:
    res = requests.get(i, headers=headers)  # verify=False 去掉安全认证
    res.encoding = 'gbk'
    print(res.text)