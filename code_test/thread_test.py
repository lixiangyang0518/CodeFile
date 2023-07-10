# str = raw_input("input number:")
# a = ''
# b = []
# for i in str:
#     if i.isdigit():
#         a = i
#         b.append(a)
# print(b)
# str1 = ''
# str2 = str1.join(b)
# print (str2)

import time
import threading

def how_much_time(func):
    def inner():
        t_start = time.time()
        func()
        t_end = time.time()
        print("time cost: %s" % (t_end - t_start))
    return inner

@how_much_time
def sleep_5s():
    time.sleep(5)
    print("%d seconds cost" %(5,) )

@how_much_time
def sleep_6s():
    time.sleep(6)
    print("%d seconds cost" %(6,) )

t1 = threading.Thread(target=sleep_5s)
t2 = threading.Thread(target=sleep_6s)
t1.start()
t2.start()


