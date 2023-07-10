# _*_ coding:utf-8 _*_

from turtle import *

# 画粽子
# 将海龟笔尖提起
penup()
# 将海龟图形移动到画布上指定的位置(算是为了居中绘画吧)
goto(-100, -50)
# 将海龟笔尖落下
pendown()

# 画笔宽度
pensize(2)
# 画笔颜色
pencolor("black")
# 粽子大体的填充色
fillcolor("green")
# 开始填充
begin_fill()
# 绘制粽子的正面
for i in range(3):
    # forward,在当前位置方向移动一定的距离
    fd(200)
    # 画圆弧
    circle(15, 120)
# 绘制粽子的侧面
fd(200)
circle(15, 60)
fd(100)
circle(15, 90)
fd(173)
circle(1, 90)
# 停止填充
end_fill()

# 将海龟笔尖提起
penup()
fd(100)
# 向右旋转60
right(60)
# 向后移动105
back(105)
# 表存当前的坐标点
a = pos()
pendown()

# 画笔颜色
color("black")
# 带子的颜色（深卡其色）
fillcolor("darkkhaki")
# 绘制正面的带子
begin_fill()
fd(120)
goto(a)
# pen up调整位置
penup()
back(15)
left(90)
fd(20)
right(90)
pendown()
fd(150)
right(120)
fd(24)
right(60)
fd(120)
right(60)
fd(24)
end_fill()
# 侧面的带子
begin_fill()
left(110)
fd(65)
left(100)
fd(24)
left(80)
fd(50)
# 结束填充
end_fill()

# 画下面的那条带子
# 绘制正面的带子
# 摆正他的方向
right(50)
# 得到a点的坐标
x, y = a
# 让a点坐标向右下靠
x = x + 30
y = y - 50
b = x, y
# 提起画笔把初始的位置什么设置好（角度和准备）,此时不能填充
penup()
fd(120)
goto(b)
back(15)
left(90)
fd(20)
right(90)
# 配置好了之后就可以填充了
begin_fill()
pendown()
# 先画下面的直线
fd(210)
right(120)
# 右边的直线
fd(24)
right(60)
# 上面的直线
fd(180)
right(60)
# 左边的直线
fd(24)
end_fill()
# 侧面的带子
begin_fill()
left(110)
fd(90)
left(100)
fd(24)
left(80)
fd(75)
# 结束填充
end_fill()

# 隐藏turtle图形(箭头)
hideturtle()

# 输出祝福语
# 将海龟笔尖提起
penup()
goto(-80, -160)
pendown()
write("端午安康", font=('楷体', 30, 'bold'))
# 暂停程序，停止画笔绘制，但绘图窗体不关闭，直到用户关闭pythonTurtle图形化窗口为止
done()