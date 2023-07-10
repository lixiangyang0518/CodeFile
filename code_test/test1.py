# _*_ coding:utf-8 _*_
def aaa(req,kind=1):
    if kind == 1:
        print("str1  kind 1")
    if kind == 2:
        print("str2  kind 2")

def main1():
    str1 = "this is str1"
    aaa(str1,1)

def main2():
    str2 = "this is str2"
    aaa(str2,2)

if __name__ == "__main__":
    main1()