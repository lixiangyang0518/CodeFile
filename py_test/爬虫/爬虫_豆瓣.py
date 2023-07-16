# _*_ coding:utf-8 _*_

# step1 : 拿页面源代码
# step2 : 用正则拿到相应数据
import requests
import re
import csv

page = 10
f = open("data.csv", 'w', encoding='utf-8')
for i in range(page):
    url = 'https://movie.douban.com/top250?start={}&filter='.format(i*25)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.57'
    }
    req = requests.get(url, headers = headers)
    page_code = req.text
    # print(page_code)

    #解析数据
    obj = re.compile(r'<li>.*?<div class="item">.*?<span class="title">(?P<name>.*?)</span>.*? <p class="">.*?'
                     r'<br>(?P<year>.*?)&nbsp.*?<span class="rating_num" property="v:average">(?P<score>.*?)</span>'
                     r'.*?<span class="inq">(?P<info>.*?)</span>', re.S)
    # obj = re.compile(r'<span class="title">(?P<movie_name>.*?)</span>', re.S)
    res = obj.finditer(page_code)
    csvwriter = csv.writer(f)
    for i in res:
        dic = i.groupdict()
        dic['year'] = dic['year'].strip()
        csvwriter.writerow(dic.values())
f.close()
print('done')