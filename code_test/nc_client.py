# _*_ coding:utf-8 _*_
from ncclient import manager
import threading

import sys
reload(sys)
sys.setdefaultencoding('utf8')

host = '10.0.150.111'
port = 830
username = 'admin'
password = 'admin'

rpc_json = """
<config>
    <configure xmlns="urn:nokia.com:sros:ns:yang:sr:conf">
        <service>
            <vprn>
                <service-name>109</service-name>
                <admin-state>enable</admin-state>
                <customer>1</customer>
                <autonomous-system>109</autonomous-system>
                <bgp-ipvpn>
                    <mpls>
                        <admin-state>enable</admin-state>
                        <route-distinguisher>109:109</route-distinguisher>
                        <auto-bind-tunnel>
                            <resolution>any</resolution>
                        </auto-bind-tunnel>
                    </mpls>
                </bgp-ipvpn>
            </vprn>
        </service>
    </configure>
</config>
"""

nc1 = manager.connect(host=host,
                            port=port,
                            username=username,
                            password=password,
                            hostkey_verify=False,
                            )
print("nc1是否完成连接：" + str(nc1.connected))
reply = nc1.edit_config(
    target="candidate", config=rpc_json)
print("nc1 edit_config reply: " + str(reply))

nc2 = manager.connect(host=host,
                            port=port,
                            username=username,
                            password=password,
                            hostkey_verify=False,
                            )
print("nc2是否完成连接：" + str(nc2.connected))
reply = nc2.edit_config(
    target="candidate", config=rpc_json)
print("nc2 edit_config reply: " + str(reply))

def thread1():
    reply = nc1.commit()
    print("nc1 commit reply: " + str(reply))

def thread2():
    reply = nc2.commit()
    print("nc2 commit reply: " + str(reply))

def main():
    thread = []
    t1 = threading.Thread(target=thread1)
    thread.append(t1)
    t2 = threading.Thread(target=thread2)
    thread.append(t2)
    for t in thread:
        t.start()

if __name__ == "__main__":
    main()

# print("是否commit：1. 是  2.否")
# num = input("请选择：")
# if num == 1:
#     reply = nc_client.commit()
#     print("commit reply:"+str(reply))
#     nc_client.close_session()
# elif num == 2:
#     nc_client.discard_changes()
#     print("discard reply:"+str(reply))
#     nc_client.close_session()



