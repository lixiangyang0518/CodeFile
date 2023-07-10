# _*_ coding:utf-8 _*_
import re
import socket
import time

def main():
    tcp_sever_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #  服务器先关闭，保证重新开启不占用端口
    tcp_sever_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # R series 8888; I series 443
    tcp_sever_socket.bind(("10.0.160.94", 443))
    tcp_sever_socket.listen(128)
    tcp_sever_socket.setblocking(False)  # 套接字设为非阻塞

    client_socket_list = list()
    while True:
        try:
            #  等待新客户端的链接
            new_socket, client_addr = tcp_sever_socket.accept()
            print client_addr,"----", time.ctime()
        except Exception as ret:
            pass
        else:
            new_socket.setblocking(False)
            client_socket_list.append(new_socket)

if __name__ == '__main__':
    main()