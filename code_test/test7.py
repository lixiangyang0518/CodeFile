import gevent
from gevent import monkey;monkey.patch_all()
import time

def fun(a):
    time.sleep(1)
    print(a)

def run(l):
    start_time = time.time()
    for i in l:
        fun(i)
    end_time = time.time()
    time_codt = end_time - start_time
    print(time_codt)

def gevent_run(l):
    threads = []
    start_time = time.time()
    for i in l:
        thread = gevent.spawn(fun(i))
        threads.append(thread)
    for i in threads:
        print(i.join())
    time_cost = time.time()-start_time
    print(time_cost)

if __name__ == "__main__":
    L=[1,2,3,4,5]
    run(L)
    gevent_run(L)