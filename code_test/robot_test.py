# _*_ coding:utf-8 _*_
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager


def test_selenium():
    # 配置浏览器driver
    web_service = Service(executable_path=ChromeDriverManager().install())
    # 规避ssl安全验证
    web_options = Options()
    web_options.add_experimental_option('excludeSwitches', ['enable-logging'])

    web_options.add_argument('--allow-running-insecure-content')

    web_options.add_argument('--ignore-certificate-errors')

    # 启动driver, 连接浏览器

    driver = webdriver.Chrome(service=web_service, options=web_options)

    # get打开链接的页面
    driver.get("https://www.baidu.com")

    # 隐性等待网页相应
    driver.implicitly_wait(1)

    # 抓取元素，模拟鼠标操作
    driver.find_element(By.ID, "kw").send_keys('python')
    driver.find_element(By.ID, "su").click()
    driver.implicitly_wait(1)
    time.sleep(2)

    # 退出driver, 释放资源
    driver.quit()

if __name__ == '__main__':
    test_selenium()