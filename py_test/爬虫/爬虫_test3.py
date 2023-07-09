import requests

url = 'https://y.qq.com/mediastyle/yqq/img/player_logo.png?max_age=2592000'



headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.57'}
req = requests.get(url, headers=headers)

print(req.content)
# with open('vedio.mp3', 'wb') as file:
#     file.write(req.content)
