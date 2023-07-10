# _*_ coding:utf-8 _*_
import requests
import json
from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()

def get_all_r_vlan(username, password, hostname):

    url = "https://{}:8888/restconf/data/openconfig-vlan:vlans".format(hostname)
    response = requests.get(
        url,
        verify=False,
        auth=HTTPBasicAuth(username, password),
        headers={"Content-type": "application/yang-data+json"}
    )
    if response.status_code == 200:
        d = json.loads(response.content)
        list1 = d['openconfig-vlan:vlans']['vlan']
        vlan = []
        for i in list1:
            print i
            #if i['members']['member'][0]['state']['interface'] == 'trunk_1':
            #    vlan.append(i['vlan-id'])
        #print vlan

    else:
        print "error"

get_all_r_vlan('admin','yunao@123','10.0.170.228')

