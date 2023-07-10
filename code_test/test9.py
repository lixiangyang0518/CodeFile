# _*_ coding:utf-8 _*_
# 导包
from time import sleep
from selenium import webdriver

#鼠标操作
from selenium.webdriver.common.action_chains import ActionChains

"""
鼠标操作：
context_click() 右键
double_click() 鼠标双击
"""
from time import sleep
from selenium import webdriver
from selenium.webdriver import ActionChains

# 实例化浏览器
driver = webdriver.Edge(executable_path='E:\python2.7.18\msedgedriver.exe')

# 打开网址
driver.get('https://www.baidu.com/')

# 定位目标
ele = driver.find_element_by_id('kw')
# 实例化 鼠标对象
action = ActionChains(driver)

# 鼠标右键
action.context_click(ele)

# 鼠标双击
action.double_click(ele)

# 鼠标执行操作！！！不执行没效果
action.perform()

sleep(3)

# 窗口最大化
driver.maximize_window()
sleep(1)
# 设置浏览器宽，高 【了解】
driver.set_window_size(1000, 1000)
sleep(1)
# 设置窗口浏览器位置  【了解】
driver.set_window_position(200, 200)

sleep(3)

# 后退
driver.back()
sleep(2)

# 前进
driver.forward()
sleep(2)

# 刷新
driver.refresh()

# 需求
ele = driver.find_element_by_css_selector('#kw')
ele.send_keys('aaa')
sleep(2)

# 清空
ele.clear()
ele.send_keys('bbb')

# 时间轴看效果
sleep(3)

# 关闭页面
driver.quit()
