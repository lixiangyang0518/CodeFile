import requests
from lxml import etree

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.41'}
kw = {
    'kw':'hello'
}

response = requests.get('http://www.baidu.com', headers=headers, params=kw)

response.encoding = 'utf-8'

html = etree.HTML(response.text)

result = html.xpath('//div/@class')
print(result)
