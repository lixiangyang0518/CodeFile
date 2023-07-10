# _*_ coding:utf-8 _*_

# 多个线程可以在同一个程序中，并且每个线程都完成不同的任务
# 多线程的特点是提高程序执行效率 和 处理速度

import threading

def test(a,b):
    print b,a

thread1 = threading.Thread(name="t1",target=test,args=(1,2))  # daemon用来判断是否为主线程， 从主线程创建的所有线程不设置daemon，默认都是False
thread2 = threading.Thread(name="t2",target=test,args=(3,4))
thread1.start()
thread2.start()
thread1.join()
thread2.join()


class test_thread(threading.Thread):
    print "this is a test thread"
thread3 = test_thread()
thread3.start()