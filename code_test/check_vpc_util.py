# coding = 'utf-8'
import json
import requests
import sys
import urllib3
import traceback
import logging
import base64
import prettytable as pt

# neutron information
neutron_ip = '10.253.80.181'
keystone_ip = ''
admin_username = 'neutron'
admin_password = 'Keystone_Ne_48b521e3101c8298df6f'
project = 'service'

# ruijie neutron: flag = 1 ; beier neutron: flag = 2
flag = 1

# ruijie_vsd information
vsd_ip = '10.253.81.201'
vsd_user = 'admin'
vsd_password = 'rgsdn.123'

# beier_vsd information
beier_vsd = '10.253.146.23:8443'
server_auth = 'openstack:Ydyjq12!@'
partition_name = 'SZTEST-CMCC'

LOG = logging.getLogger('log')

class CheckVpc(object):

    def __init__(self, vpc_id, neutron_ip, keystone_ip, vsd_ip, beier_vsd, admin_username, admin_password, project, flag, vsd_user, vsd_password, server_auth, partition_name):
        self.neutron_ip = neutron_ip
        self.keystone_ip = keystone_ip
        self.vsd_ip = vsd_ip
        self.beier_vsd = beier_vsd
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.project = project
        self.flag = flag
        self.vsd_username = vsd_user
        self.vsd_password = vsd_password
        self.server_auth = server_auth
        self.partition_name = partition_name
        self.token = None
        self.vsd_token = None
        self.vpc_router_id = vpc_id
        while len(self.vpc_router_id) == 0:
            print("***** please input router_id again! *****")
            self.vpc_router_id = input('please input router_id:')

    # neutron token
    def _get_token(self):
        if self.flag == 1:
            api_url = 'http://' + self.neutron_ip + ':5000/v3/auth/tokens'
            header = {'Content-Type': 'application/json'}
            data = {"auth": {"identity": {"methods": ["password"], "password": {
                "user": {"domain": {"name": "default"},
                         "name": self.admin_username,
                         "password": self.admin_password}}},
                             "scope": {"project": {"domain": {"name": "Default"},
                                                   "name": self.project}}}}
            for t in range(0, 3):
                try:
                    req = requests.post(api_url, data=json.dumps(data), headers=header, verify=False,
                                        timeout=10)
                except Exception as e:
                    print(str(e))
                    continue
                if req.status_code == 201:
                    self.token = req.headers['X-Subject-Token']
                    print('get neutron token success token:' + self.token)
                    return
                else:
                    print(str(req.text))
                    continue
            print('get neutron token fail')
        elif self.flag == 2:
            if self.keystone_ip:
                api_url = 'http://' + self.keystone_ip + ':5000/v3/auth/tokens'
            else:
                api_url = 'http://' + self.neutron_ip + ':5000/v3/auth/tokens'
            header = {'Content-Type': 'application/json'}
            data = {"auth": {"identity": {"methods": ["password"], "password": {
                "user": {"domain": {"name": "default"},
                         "name": self.admin_username,
                         "password": self.admin_password}}},
                             "scope": {"project": {"domain": {"name": "Default"},
                                                   "name": self.project}}}}

            req = requests.post(api_url, data=json.dumps(data), headers=header, verify=False,
                                        timeout=10)
            if req.status_code == 201:
                self.token = req.headers['X-Subject-Token']
                print('get neutron token success token:' + self.token)
                return
            else:
                print(str(req.text))
        print('get neutron token fail')

    # ruijie vsd_token
    def _get_vsd_token(self):
        api_url = 'http://{0}:8181/oauth2/token?grant_type=password&username={1}&password={2}&scope=sdn'.format(
            self.vsd_ip, self.vsd_username, self.vsd_password)
        header = {'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8'}
        for t in range(3):
            try:
                req = requests.post(api_url, headers=header, verify=False, timeout=30)
            except Exception as e:
                LOG.warning(traceback.format_exc())
                continue
            if req.status_code in [200, 201]:
                self.vsd_token = json.loads(req.text)['access_token']
                print('get ruijie controller token success token:' + self.vsd_token)
                return
            else:
                LOG.warning(str(req.text))
                continue
        print('get ruijie controller token fail')

    # ruijie_vsd
    def get_router_info_from_vsd(self):
        if not self.vsd_token:
            self._get_vsd_token()
        api_url = 'http://{0}:8181/controller/nb/v2/neutron/routers/{1}'.format(self.vsd_ip, self.vpc_router_id)
        for t in range(3):
            try:
                header = {'Content-Type': 'application/json;charset=utf-8',
                          'Authorization': "Bearer {}".format(self.vsd_token)}
                req = requests.get(api_url, data={}, headers=header, verify=False, timeout=30)
            except Exception as e:
                LOG.warning(traceback.format_exc())
                continue
            if req.status_code == 200:
                req_dict = json.loads(req.text)
                print('check from vsd success')
                if req_dict.get("router"):
                    print(req_dict)
                    return {"l3vni": req_dict.get("router").get("provider:segmentation_id"),
                            "rt": req_dict.get("router").get("route_target"),
                            "rd": req_dict.get("router").get("route_distinguisher"),
                            "vrf_name": req_dict.get("router").get("vrf_name")}
            elif req.status_code == 401:
                LOG.warning('Incorrect token permission')
                self._get_vsd_token()
                continue
            else:
                LOG.warning(str(req.text))
                continue
        LOG.warning('check from vsd fail , Check whether there is a VM in the VPC')

    def create_network(self):
        if not self.token:
            self._get_token()

        if self.flag == 1:
            name = input("please input network_name:")
            while len(name) == 0:
                print("***** please input network_name again! *****")
                name = input("please input network_name:")

            api_url = 'http://' + self.neutron_ip + ':9696/v2.0/networks'
            header = {
                'Content-Type': 'application/json',
                'X-Auth-Token': self.token}
            data = {"network": {"name": name, "admin_state_up": True}}
            req = requests.post(api_url, data=json.dumps(data), headers=header,
                                verify=False,
                                timeout=180)
            response_text = req.text.encode('utf8')
            response_obj = json.loads(response_text)
            if req.status_code == 201:
                network_id = response_obj['network']['id']
                return network_id

        elif self.flag == 2:
            name = input("please input network_name:")
            while len(name) == 0:
                print("***** please input network_name again! *****")
                name = input("please input network_name:")
            availability_zone_hints = input("please input availability_zone_hints:")
            while len(availability_zone_hints) == 0:
                print("***** please input availability_zone_hints again! *****")
                availability_zone_hints = input("please input availability_zone_hints:")

            api_url = 'http://' + self.neutron_ip + ':9696/v2.0/networks'
            header = {
                'Content-Type': 'application/json',
                'X-Auth-Token': self.token}
            data = {"network": {"name": name, "availability_zone_hints": [availability_zone_hints],"admin_state_up": True}}
            req = requests.post(api_url, data=json.dumps(data), headers=header,
                                verify=False,
                                timeout=180)
            response_text = req.text.encode('utf8')
            response_obj = json.loads(response_text)
            if req.status_code == 201:
                network_id = response_obj['network']['id']
                return network_id
            else:
                print("Error:"+response_obj['NeutronError']['message'])

    def delete_network(self):
        if not self.token:
            self._get_token()

        network_id = input("please in put network_id:")
        while len(network_id) == 0:
            print("***** please input network_id again! *****")
            network_id = input("please in put network_id:")

        api_url = 'http://' + self.neutron_ip + ':9696/v2.0/networks/' + network_id
        header = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token}
        req = requests.delete(api_url, data={}, headers=header,
                              verify=False,
                              timeout=180)
        if req.status_code == 204:
            print("***** delete network success *****")

    def create_subnet(self):
        if not self.token:
            self._get_token()

        # create a new network
        network_id = self.create_network()
        while len(network_id) == 0:
            print("***** create network fail, please input correct data! *****")
            network_id = self.create_network()
        tb = pt.PrettyTable()
        tb.field_names = ['new_network_id']
        network = []
        network.append(network_id)
        tb.add_row(network)
        print("new network:")
        print tb

        ip_version = input("please input ip_version:")
        while len(ip_version) == 0:
            print("***** please input ip_version again! *****")
            ip_version = input("please input ip_version:")
        cidr = input("please input cidr:")
        while len(cidr) == 0:
            print("***** please input cidr again! *****")
            cidr = input("please input cidr:")
        name = input("please input subnet_name:")
        while len(name) == 0:
            print("***** please input subnet_name again! *****")
            name = input("please input subnet_name:")

        api_url = 'http://' + self.neutron_ip + ':9696/v2.0/subnets'
        header = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token}
        data = {"subnet": {"network_id": network_id, "ip_version": ip_version,
                           "cidr": cidr, "name": name}}
        req = requests.post(api_url, data=json.dumps(data), headers=header,
                            verify=False,
                            timeout=180)
        response_text = req.text.encode('utf8')
        response_obj = json.loads(response_text)
        if req.status_code == 201:
            tb = pt.PrettyTable()
            tb.field_names = ['new_subnet_id']
            subnet_list = []
            print("***** create subnet success! *****")
            subnet_id = response_obj['subnet']['id']
            subnet_list.append(subnet_id)
            tb.add_row(subnet_list)
            print("subnet_id:")
            print tb
            self.add_router_interface(subnet_id)

    def add_router_interface(self, subnet_id):
        if not self.token:
            self._get_token()

        api_url = 'http://' + self.neutron_ip + ':9696/v2.0/routers/' + self.vpc_router_id + '/add_router_interface'
        data = {"subnet_id": subnet_id}
        header = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token}
        req = requests.put(api_url, json.dumps(data), headers=header,
                           verify=False,
                           timeout=180)
        if req.status_code == 200:
            print("***** add subnet interface to router seccuss! *****")

    def remove_interface_delete(self, subnet_id):
        if not self.token:
            self._get_token()
        api_url = 'http://' + self.neutron_ip + ':9696/v2.0/routers/' + self.vpc_router_id + '/remove_router_interface'
        data = {"subnet_id": subnet_id}
        header = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token}
        req = requests.put(api_url, json.dumps(data), headers=header,
                           verify=False,
                           timeout=180)
        if req.status_code == 200:
            print("***** remove subnet interface to router seccuss! *****")

    def delete_subnet(self):
        if not self.token:
            self._get_token()

        subnet_id = input("please input subnet_id:")
        while len(subnet_id) == 0:
            print("***** please input subnet_id again! *****")
            subnet_id = input("please input subnet_id:")
        self.remove_interface_delete(subnet_id)

        api_url = 'http://' + self.neutron_ip + ':9696/v2.0/subnets/' + subnet_id
        header = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token}
        req = requests.delete(api_url, data={}, headers=header,
                              verify=False,
                              timeout=180)
        if req.status_code == 204:
            print("delete subnet: " +subnet_id+" success!")

    def get_subnet(self, subnets):
        if not self.token:
            self._get_token()
        tb = pt.PrettyTable()
        tb.field_names = ['subnet_id', 'subnet_cidr', 'network_id', 'az']
        for subnet_id in subnets:
            subnet = []
            api_url = 'http://' + self.neutron_ip + ':9696/v2.0/subnets' \
                                                    '/' + subnet_id
            header = {
                'Content-Type': 'application/json',
                'X-Auth-Token': self.token}
            req = requests.get(api_url, data={}, headers=header,
                               verify=False,
                               timeout=10)
            subnet_id = req.json()['subnet']['id']
            cidr = req.json()['subnet']['id']
            network_id = req.json()['subnet']['network_id']
            if req.status_code == 200:
                api_url = 'http://' + self.neutron_ip + ':9696/v2.0/networks/' + network_id
                header = {
                    'Content-Type': 'application/json',
                    'X-Auth-Token': self.token}
                req = requests.get(api_url, data={}, headers=header,
                                   verify=False,
                                   timeout=180)
                az = req.json()['network']['availability_zone_hints']
                subnet.append(subnet_id)
                subnet.append(cidr)
                subnet.append(network_id)
                subnet.append(az)
                tb.add_row(subnet)
        print ("")
        print("subnet_list:")
        print tb
        print ("")

    def get_vpc(self):
        if not self.token:
            self._get_token()
        api_url = 'http://' + self.neutron_ip + ':9696/v2.0/routers/' + self.vpc_router_id
        header = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token}

        req = requests.get(api_url, data={}, headers=header,
                           verify=False,
                           timeout=180)
        if req.status_code == 200:
            print("***** vpc exist！*****")
        else:
            print("***** not found vpc！*****")

    def get_vpc_subnets(self):
        if not self.token:
            self._get_token()

        api_url = 'http://' + self.neutron_ip + ':9696/v2.0/ports?device_id=' + self.vpc_router_id
        header = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token}
        subnets = []

        req = requests.get(api_url, data={}, headers=header,
                           verify=False,
                           timeout=180)
        if req.status_code == 200:
            ports = req.json()['ports']

            for port in ports:
                for fixed_ip in port['fixed_ips']:
                    subnet_id = fixed_ip['subnet_id']
                    subnets.append(subnet_id)
            if len(subnets) == 0:
                print("***** no subnets! *****")
            else:
                self.get_subnet(subnets)

            tb = pt.PrettyTable()
            tb.field_names = ['port_id', 'fixed_subnet_id', 'fixed_ip']
            for i in range(0, len(ports)):
                port_list = []
                port_id = ports[i]['id']
                subnet_id = ports[i]['fixed_ips'][0]['subnet_id']
                port_ip = ports[i]['fixed_ips'][0]['ip_address']
                port_list.append(port_id)
                port_list.append(subnet_id)
                port_list.append(port_ip)
                tb.add_row(port_list)
            print("port_list:")
            print tb
            print("")

            if len(port_list) == 0:
                print("***** no ports! *****")

    # beier_vsd
    def get_subnet_from_vsd(self):
        serverauth = self.server_auth
        encoded_auth = base64.b64encode(
            serverauth.encode()).decode()
        Authorization ='Basic ' + encoded_auth
        user_name = serverauth.split(':')[0]
        api_url = 'https://' + self.beier_vsd + '/nuage/api/v6/me'
        headers = {
            'Accept': 'application/json',
            'Authorization': Authorization,
            'X-Nuage-Organization': 'csp',
        }
        requests.packages.urllib3.disable_warnings()
        req = requests.get(api_url, data={}, headers=headers,
                           verify=False,
                           timeout=10)
        req1 = req.text.encode('utf8')
        req_obj = json.loads(req1)
        APIKey = req_obj[0]['APIKey']
        auth = user_name +':'+ APIKey
        key = base64.b64encode(auth.encode('utf-8')).decode("utf-8")
        Authorization_vsd = 'Basic ' + key

        api_url1 = 'https://' + self.beier_vsd + '/nuage/api/v6/enterprises'
        headers = {
            'Accept': 'application/json',
            'Authorization': Authorization_vsd,
            'X-Nuage-Organization': 'csp',
        }
        requests.packages.urllib3.disable_warnings()
        req_1 = requests.get(api_url1, data={}, headers=headers,
                           verify=False,
                           timeout=10)
        req1 = req_1.text.encode('utf8')
        req_obj1 = json.loads(req1)
        for i in range(0, len(req_obj1)):
            if self.partition_name == req_obj1[i]['name']:
                enterprise_id = req_obj1[i]['ID']

        api_url2 = 'https://' + self.beier_vsd + '/nuage/api/v6/enterprises/' + enterprise_id +'/domains'
        headers = {
            'Accept': 'application/json',
            'Authorization': Authorization_vsd,
            'X-Nuage-Organization': 'csp',
            'X-Nuage-Filter':self.vpc_router_id
        }
        requests.packages.urllib3.disable_warnings()
        req_2 = requests.get(api_url2, data={}, headers=headers,
                           verify=False,
                           timeout=10)
        req2 = req_2.text.encode('utf8')
        req_obj2 = json.loads(req2)
        if req_2.status_code == 200:
            domain_id = req_obj2[0]['ID']

        api_url3 = 'https://'+self.beier_vsd+ '/nuage/api/v6/domains/' + domain_id + '/subnets'
        headers = {
            'Accept': 'application/json',
            'Authorization': Authorization_vsd,
            'X-Nuage-Organization': 'csp'
        }
        requests.packages.urllib3.disable_warnings()
        req_3 = requests.get(api_url3, data={}, headers=headers,
                           verify=False,
                           timeout=10)
        req3 = req_3.text.encode('utf8')
        req_obj3 = json.loads(req3)
        tb = pt.PrettyTable()
        tb.field_names = ['subnet_id', 'ipv4_address', 'ipv6_address']
        for i in range(0, len(req_obj3)):
            subnet = []
            subnet_id = req_obj3[i]['name']
            ipv4_address = req_obj3[i]['address']
            ipv6_address = req_obj3[i]['IPv6Address']
            subnet.append(subnet_id)
            subnet.append(ipv4_address)
            subnet.append(ipv6_address)
            tb.add_row(subnet)
        print("")
        print("subnet_list:")
        print tb

    def main(self):
        print("============================================this is menu=============================================================")
        print("1.check vpc exist     2.get router info from neutron     3.get router info from vsd     4.subnet operation     5.exit")
        str = input("please input number:")
        x = ''
        b = []
        for i in str:
           if i.isdigit():
               x = i
               b.append(x)
        str1 = ''
        shuzi = str1.join(b)
        while len(shuzi) == 0:
            print("***** the number can not be none! *****")
            shuzi = input("please input number:")
        num = int(shuzi)
        if num == 1:
            self.get_vpc()
            self.main()
        elif num == 2:
            self.get_vpc_subnets()
            self.main()
        elif num == 3:
            if self.flag == 1:
                self.get_router_info_from_vsd()
                self.main()
            elif self.flag == 2:
                self.get_subnet_from_vsd()
                self.main()
            # print("please choose vendor:1.ruijie     2.beier")
            # s = int(input("please input number:"))
            # if s == 1:
            #     if self.flag == 1:
            #         self.get_router_info_from_vsd()
            #         self.main()
            #     elif self.flag == 2:
            #         print("***** this is beier neutron!!! *****")
            #         self.main()
            # elif s == 2:
            #     if self.flag == 1:
            #         print("***** this is ruijie neutron!!! *****")
            #         self.main()
            #     elif self.flag == 2:
            #         self.get_subnet_from_vsd()
            #         self.main()
            else:
                self.main()
        elif num == 4:
            print("1.create subnet     2.delete subnet")
            a = int(input("please input number:"))
            if a == 1:
                self.create_subnet()
                self.main()
            elif a == 2:
                self.delete_subnet()
                self.delete_network()
                self.main()
            else:
                self.main()
        elif num == 5:
            print("---------- exit! ----------")
        else:
            print("***** please input right number! *****")
            self.main()

if __name__ == "__main__":
    vpc_id = sys.argv[1]
    checkvpc = CheckVpc(vpc_id, neutron_ip, keystone_ip, vsd_ip, beier_vsd, admin_username, admin_password, project, flag, vsd_user, vsd_password, server_auth, partition_name)
    checkvpc.main()
