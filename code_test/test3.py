# _*_ coding:utf-8 _*_

import requests    # requests库是一个好用的HTTP请求库，用于网络请求

class RequestApi():
    def __init__(self):
        self.token = None
        self.neutron_session = requests.session()
        self.keystone_v2_auth()

    def keystone_v2_auth(self):
            url = KEYSTONE_URL + '/v2.0/tokens'
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            }
            payload = {
                'auth': {
                    'tenantName': project,
                    'passwordCredentials': {
                        'username': USERNAME,
                        'password': PASSWORD
                    }
                }
            }
            response = self.neutron_session.post(url, headers=headers, data=json.dumps(payload))
            if response.status_code == 200:
                response_text = response.text.encode('utf8')
                response_obj = json.loads(response_text)
                service_catalogs = response_obj['access']['serviceCatalog']
                for service_catalog in service_catalogs:
                    if service_catalog['type'] == 'network':
                        for endpoint in service_catalog['endpoints']:
                            if endpoint['region'] == REGION:
                                global NEUTRON_BASE_URL
                                NEUTRON_BASE_URL = endpoint['publicURL']
                    elif service_catalog['type'] == 'compute':
                        for endpoint in service_catalog['endpoints']:
                            if endpoint['region'] == REGION:
                                global NOVA_BASE_URL
                                NOVA_BASE_URL = endpoint['publicURL']
                    elif service_catalog['type'] == 'image':
                        for endpoint in service_catalog['endpoints']:
                            if endpoint['region'] == REGION:
                                global GLANCE_BASE_URL
                                GLANCE_BASE_URL = endpoint['publicURL']

                self.token = response_obj['access']['token']['id']
            else:
                raise Exception('keystone_v2_auth({}) error, response status code: {}'.format(url, response.status_code))

    def http_get(self, url):
        headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.token
        }
        response = self.neutron_session.get(url, headers=headers)
        if response.status_code == 200:
            response_text = response.text.encode('utf8')
            return response_text
        elif response.status_code == 401:
            self.keystone_v2_auth()
            return self.http_get(url)
        else:
            raise Exception('http_get({}) error, response: {}'.format(url, response.__dict__))

    def http_post(self, url, payload):
        headers = {
            'User-Agent': 'python-neutronclient',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token
        }
        response = self.neutron_session.post(url, headers=headers,
                                             data=json.dumps(payload))
        # 201: sync creation, 202: async creation
        if response.status_code == 201 or response.status_code == 202:
            response_text = response.text.encode('utf8')
            return response_text
        elif response.status_code == 401:
            self.keystone_v2_auth()
            return self.http_post(url, payload)
        else:
            raise Exception('http_post({}) error, response: {}'.format(url, response.__dict__))

    def http_put(self, url, payload):
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token
        }
        response = self.neutron_session.put(url, headers=headers,
                                            data=json.dumps(payload))             # json.dumps() 将python数据机构转为json
        if response.status_code == 200:
            response_text = response.text.encode('utf8')
            return response_text
        elif response.status_code == 401:
            self.keystone_v2_auth()
            return self.http_put(url, payload)
        else:
            raise Exception('http_put({}) error, response: {}'.format(url, response.__dict__))

    def http_delete(self, url):
        headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.token
        }
        response = self.neutron_session.delete(url, headers=headers)
        if response.status_code == 401:
            self.keystone_v2_auth()
            self.http_delete(url)
        elif response.status_code != 204:
            raise Exception('http_delete({}) error, response: {}'.format(url, response.__dict__))

req = RequestApi().http_delete(url)






# 以表格形式打印
import prettytable as pt

tb = pt.PrettyTable()
tb.field_names = ['loadbalancer_id', 'name', 'lb_ip1', 'lb_ip2', 'vlan', 'flavor', 'AZ']
list = []

tb.add_row(list)
print(tb)