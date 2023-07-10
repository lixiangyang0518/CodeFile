#!/usr/bin/env python
# coding=utf-8
# 100个neutron api并发测试脚本

import argparse
import eventlet
import functools
import json
import logging
import os
import requests
import signal
import sys
import time
import uuid
import random

eventlet.monkey_patch()
requests.packages.urllib3.disable_warnings()

logging.basicConfig(format='%(asctime)s %(process)d %(levelname)s [%(funcName)s line:%(lineno)d]: %(message)s',
                    level=logging.INFO)
LOG = logging.getLogger(__name__)

LOG_LEVEL_ERROR = 'error'
LOG_LEVEL_WARNING = 'warning'
LOG_LEVEL_INFO = 'info'
LOG_LEVEL_DEBUG = 'debug'

LOG_LEVEL_DICT = {
    LOG_LEVEL_ERROR: logging.ERROR,
    LOG_LEVEL_WARNING: logging.WARNING,
    LOG_LEVEL_INFO: logging.INFO,
    LOG_LEVEL_DEBUG: logging.DEBUG
}

if not (os.environ.get('OS_USERNAME') and os.environ.get('OS_PASSWORD') and os.environ.get(
        'OS_PROJECT_NAME') and os.environ.get('OS_AUTH_URL') and os.environ.get('OS_REGION_NAME')):
    LOG.error('Keystone environment variables not found, '
              'please source keystonerc_xxx file first!\n')
    sys.exit(1)

USERNAME = os.environ.get('OS_USERNAME')
PASSWORD = os.environ.get('OS_PASSWORD')
project = os.environ.get('OS_PROJECT_NAME')
# http://10.10.10.151:5000/v3 -> http://10.10.10.151:5000
KEYSTONE_URL = os.environ.get('OS_AUTH_URL')[:os.environ.get('OS_AUTH_URL').rfind('/')]
NEUTRON_BASE_URL = 'http://10.0.170.1:9696'
NOVA_BASE_URL = ''
GLANCE_BASE_URL = ''
REGION = os.environ.get('OS_REGION_NAME')

BASENAME = os.path.basename(sys.argv[0])

SESSION = requests.Session()
SESSION.mount('https' if KEYSTONE_URL.startswith('https') else 'http' + '://',
              requests.adapters.HTTPAdapter(pool_connections=1000,
                                            pool_maxsize=1000,
                                            max_retries=3,
                                            pool_block=True))


def sigterm_handler(signum, frame):
    LOG.info('Catch sigterm({}), process {} exit...'.format(signum, os.getpid()))
    # cleanup_all_resources()
    sys.exit()


def sigint_handler(signum, frame):
    LOG.info('Catch sigint({}), process {} exit...'.format(signum, os.getpid()))
    # cleanup_all_resources()
    sys.exit()


def logjo(obj):
    LOG.debug(json.dumps(obj, sort_keys=True, indent=4, separators=(',', ': ')))


def logjs(s):
    logjo(json.loads(s))


def keystone_v2_auth():
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
    response = SESSION.post(url, headers=headers, data=json.dumps(payload))
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

        token_id = response_obj['access']['token']['id']
        SESSION.headers.update({'X-Auth-Token': token_id})
    else:
        raise Exception('keystone_v2_auth({}) error, response status code: {}'.format(url, response.status_code))


keystone_v2_auth()


def http_get(url):
    LOG.debug('GET %s HTTP 1.1' % url)
    headers = {
        'Accept': 'application/json',
    }
    logjo(headers)
    t1 = time.time()
    response = SESSION.get(url, headers=headers)
    t2 = time.time()
    if response.status_code == 200:
        response_text = response.text.encode('utf8')
        logjs(response_text)
        LOG.info('GET: ({}) {} elapsed time: {} seconds'.format(response.headers['X-Openstack-Request-Id'], response.url, t2-t1))
        return response_text
    elif response.status_code == 401:
        keystone_v2_auth()
        return http_get(url)
    else:
        raise Exception('http_get({}) error, response: {}'.format(url, response.__dict__))


def http_post(url, payload):
    LOG.debug('POST %s HTTP 1.1' % url)
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    logjo(headers)
    logjo(payload)
    t1 = time.time()
    response = SESSION.post(url, headers=headers, data=json.dumps(payload))
    t2 = time.time()
    # 201: sync creation, 202: async creation
    if response.status_code == 201 or response.status_code == 202:
        response_text = response.text.encode('utf8')
        logjs(response_text)
        LOG.info('POST: ({}) {} elapsed time: {} seconds'.format(response.headers['X-Openstack-Request-Id'], response.url, t2-t1))
        return response_text
    elif response.status_code == 401:
        keystone_v2_auth()
        return http_post(url, payload)
    else:
        raise Exception('http_post({}) error, response: {}'.format(url, response.__dict__))


def http_put(url, payload):
    LOG.debug('PUT %s HTTP 1.1' % url)
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    logjo(headers)
    logjo(payload)
    t1 = time.time()
    response = SESSION.put(url, headers=headers, data=json.dumps(payload))
    t2 = time.time()
    if response.status_code == 200:
        response_text = response.text.encode('utf8')
        logjs(response_text)
        LOG.info('PUT: ({}) {} elapsed time: {} seconds'.format(response.headers['X-Openstack-Request-Id'], response.url, t2-t1))
        return response_text
    elif response.status_code == 401:
        keystone_v2_auth()
        return http_put(url, payload)
    else:
        raise Exception('http_put({}) error, response: {}'.format(url, response.__dict__))


def http_delete(url):
    LOG.debug('DELETE %s HTTP 1.1' % url)
    headers = {
        'Accept': 'application/json'
    }
    logjo(headers)
    t1 = time.time()
    response = SESSION.delete(url, headers=headers)
    t2 = time.time()
    if response.status_code == 401:
        keystone_v2_auth()
        http_delete(url)
    elif response.status_code != 204:
        raise Exception('http_delete({}) error, response: {}'.format(url, response.__dict__))
    LOG.info('DELETE: ({}) {}  elapsed time: {} seconds'.format(response.headers['X-Openstack-Request-Id'], response.url, t2-t1))

def api(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        LOG.info('Invoking OpenStack API: {}{}'.format(func.__name__, args))

        #t1 = time.time()
        result = func(*args, **kwargs)
        #t2 = time.time()

        #LOG.info('[{}{}] elapsed time: {} seconds'.format(func.__name__, args, t2 - t1))
        return result

    return wrapper


@api
def create_network(name, availability_zone_hints):
    payload = {
        'network': {
            'name': name,
            'availability_zone_hints': availability_zone_hints
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/networks', payload)
    response_obj = json.loads(response_text)
    return response_obj['network']


@api
def get_networks():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/networks')
    response_obj = json.loads(response_text)
    return response_obj['networks']


@api
def get_network(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/networks?name={}'.format(name))
    response_obj = json.loads(response_text)
    networks = response_obj['networks']
    return networks[0] if networks else None


@api
def delete_network(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/networks/{}'.format(id))


def delete_network_by_name(name):
    network = get_network(name)
    if network:
        delete_network(network['id'])


@api
def create_subnet(name, network_id, cidr, ip_version=4, gateway_ip=None, start_ip=None, end_ip=None):
    payload = {
        'subnet': {
            'name': name,
            'network_id': network_id,
            'cidr': cidr,
            'ip_version': ip_version
        }
    }
    if gateway_ip:
        payload['subnet']['gateway_ip'] = gateway_ip
    if start_ip and end_ip:
        payload['subnet']['allocation_pools'] = [{'start': start_ip, 'end': end_ip}]

    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/subnets', payload)
    response_obj = json.loads(response_text)
    return response_obj['subnet']


@api
def get_subnets():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/subnets')
    response_obj = json.loads(response_text)
    return response_obj['subnets']


@api
def get_subnet(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/subnets?name={}'.format(name))
    response_obj = json.loads(response_text)
    subnets = response_obj['subnets']
    return subnets[0] if subnets else None


@api
def delete_subnet(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/subnets/{}'.format(id))


def delete_subnet_by_name(name):
    subnet = get_subnet(name)
    if subnet:
        delete_subnet(subnet['id'])


@api
def create_router(name):
    payload = {
        'router': {
            'name': name
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/routers', payload)
    response_obj = json.loads(response_text)
    return response_obj['router']


@api
def get_routers():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/routers')
    response_obj = json.loads(response_text)
    return response_obj['routers']


@api
def get_router(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/routers?name={}'.format(name))
    response_obj = json.loads(response_text)
    routers = response_obj['routers']
    return routers[0] if routers else None


@api
def add_router_interface(router_id, subnet_id):
    payload = {
        'subnet_id': subnet_id
    }
    http_put(NEUTRON_BASE_URL + '/v2.0/routers/{}/add_router_interface'.format(router_id), payload)


@api
def remove_router_interface(router_id, subnet_id):
    payload = {
        'subnet_id': subnet_id
    }
    http_put(NEUTRON_BASE_URL + '/v2.0/routers/{}/remove_router_interface'.format(router_id), payload)


def remove_router_interface_by_name(router_name, subnet_name):
    router = get_router(router_name)
    subnet = get_subnet(subnet_name)
    remove_router_interface(router['id'], subnet['id'])


@api
def delete_router(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/routers/{}'.format(id))


def delete_router_by_name(name):
    router = get_router(name)
    if router:
        delete_router(router['id'])


@api
def create_vpc_connection(name, local_router, peer_router, local_subnets=[], peer_subnets=[], status='ACTIVE'):
    payload = {
        'vpc_connection': {
            'name': name,
            'local_router': local_router,
            'peer_router': peer_router,
            'local_subnets': local_subnets,
            'peer_subnets': peer_subnets,
            'status': status
        }
    }

    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/vpc-connections', payload)
    response_obj = json.loads(response_text)
    return response_obj['vpc_connection']


@api
def get_vpc_connections():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpc-connections')
    response_obj = json.loads(response_text)
    return response_obj['vpc_connections']


@api
def get_vpc_connection(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpc-connections?name={}'.format(name))
    response_obj = json.loads(response_text)
    vpc_connections = response_obj['vpc_connections']
    return vpc_connections[0] if vpc_connections else None


@api
def delete_vpc_connection(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/vpc-connections/{}'.format(id))


def delete_vpc_connection_by_name(name):
    vpc_connection = get_vpc_connection(name)
    if vpc_connection:
        delete_vpc_connection(vpc_connection['id'])


@api
def update_vpc_connection(id, local_subnets=[], peer_subnets=[]):
    if not local_subnets and not peer_subnets:
        return

    payload = {'vpc_connection': {}}
    if local_subnets:
        payload['vpc_connection']['local_subnets'] = local_subnets
    if peer_subnets:
        payload['vpc_connection']['peer_subnets'] = peer_subnets

    response_text = http_put(NEUTRON_BASE_URL + '/v2.0/vpc-connections/{}'.format(id), payload)
    response_obj = json.loads(response_text)
    return response_obj['vpc_connection']


@api
def create_security_group(name):
    payload = {
        'security_group': {
            'name': name,
            'stateful': True
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/security-groups', payload)
    response_obj = json.loads(response_text)
    return response_obj['security_group']


@api
def get_security_groups():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/security-groups')
    response_obj = json.loads(response_text)
    return response_obj['security_groups']


@api
def get_security_group(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/security-groups?name={}'.format(name))
    response_obj = json.loads(response_text)
    security_groups = response_obj['security_groups']
    return security_groups[0] if security_groups else None


@api
def delete_security_group(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/security-groups/{}'.format(id))


def delete_security_group_by_name(name):
    security_group = get_security_group(name)
    if security_group:
        delete_security_group(security_group['id'])


@api
def create_security_group_rule(security_group_id, direction, ethertype, protocol=None, port_range_min=None, port_range_max=None,
                               remote_ip_prefix=None):
    payload = {
        'security_group_rule': {
            'security_group_id': security_group_id,
            'direction': direction,
            'ethertype': ethertype
        }
    }
    if protocol:
        payload['security_group_rule']['protocol'] = protocol
    if port_range_min is not None:
        payload['security_group_rule']['port_range_min'] = port_range_min
    if port_range_max is not None:
        payload['security_group_rule']['port_range_max'] = port_range_max
    if remote_ip_prefix:
        payload['security_group_rule']['remote_ip_prefix'] = remote_ip_prefix

    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/security-group-rules', payload)
    response_obj = json.loads(response_text)
    return response_obj['security_group_rule']


@api
def get_security_group_rules():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/security-group-rules')
    response_obj = json.loads(response_text)
    return response_obj['security_group_rules']


@api
def get_security_group_rule(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/security-group-rules?name={}'.format(name))
    response_obj = json.loads(response_text)
    security_group_rules = response_obj['security_group_rules']
    return security_group_rules[0] if security_group_rules else None


@api
def delete_security_group_rule(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/security-group-rules/{}'.format(id))


def delete_security_group_rule_by_name(name):
    security_group_rule = get_security_group_rule(name)
    if security_group_rule:
        delete_security_group_rule(security_group_rule['id'])


@api
def create_port(name, network_id, subnet_id, ip_address=None, security_group_id=None):
    payload = {
        'port': {
            'name': name,
            'network_id': network_id,
            'fixed_ips': [{'subnet_id': subnet_id}]
        }
    }
    if ip_address:
        payload['port']['fixed_ips'][0]['ip_address'] = ip_address
    if security_group_id:
        payload['port']['security_groups'] = [security_group_id]
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/ports', payload)
    response_obj = json.loads(response_text)
    return response_obj['port']


@api
def get_ports():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/ports')
    response_obj = json.loads(response_text)
    return response_obj['ports']


@api
def get_port(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/ports?name={}'.format(name))
    response_obj = json.loads(response_text)
    ports = response_obj['ports']
    return ports[0] if ports else None


@api
def delete_port(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/ports/{}'.format(id))


def delete_port_by_name(name):
    port = get_port(name)
    if port:
        delete_port(port['id'])


@api
def create_dummyfloatingip(floating_network_id):
    payload = {
        'dummyfloatingip': {
            'floating_network_id': floating_network_id
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/dummyfloatingips', payload)
    response_obj = json.loads(response_text)
    return response_obj['dummyfloatingip']


@api
def get_dummyfloatingips():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/dummyfloatingips')
    response_obj = json.loads(response_text)
    return response_obj['dummyfloatingips']


@api
def delete_dummyfloatingip(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/dummyfloatingips/{}'.format(id))


@api
def update_dummyfloatingip(dummyfloatingip_id, port_id=None):
    payload = {
        'dummyfloatingip': {}
    }
    if port_id:
        payload['dummyfloatingip']['port_id'] = port_id
    http_put(NEUTRON_BASE_URL + '/v2.0/dummyfloatingips/{}'.format(dummyfloatingip_id), payload)


@api
def create_floatingip(floating_network_id):
    payload = {
        'floatingip': {
            'floating_network_id': floating_network_id
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/floatingips', payload)
    response_obj = json.loads(response_text)
    return response_obj['floatingip']

@api
def create_floatingip_assoc_port(floating_network_id, port_id):
    payload = {
        'floatingip': {
            'floating_network_id': floating_network_id,
            'qos_policy_id': 'b5b228df-cbd7-45f9-bb96-ef1015bd53ca',
            'port_id': port_id
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/floatingips', payload)
    response_obj = json.loads(response_text)
    return response_obj['floatingip']

@api
def get_floatingips():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/floatingips')
    response_obj = json.loads(response_text)
    return response_obj['floatingips']


@api
def delete_floatingip(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/floatingips/{}'.format(id))


@api
def update_floatingip(floatingip_id, port_id=None):
    payload = {
        'floatingip': {}
    }
    if port_id:
        payload['floatingip']['port_id'] = port_id
        payload['floatingip']['qos_policy_id'] = 'b5b228df-cbd7-45f9-bb96-ef1015bd53ca'
    http_put(NEUTRON_BASE_URL + '/v2.0/floatingips/{}'.format(floatingip_id), payload)

@api
def update_floatingip_qos(floatingip_id, port_id=None):
    payload = {
        'floatingip': {
           'qos_policy_id' : '1bbbabd9-d42a-4ac1-b487-f4e8192d3f9c'
        }
    }
    http_put(NEUTRON_BASE_URL + '/v2.0/floatingips/{}'.format(floatingip_id), payload)


@api
def create_vpnservice(name, router_id, floatingip_id):
    payload = {
        'vpnservice': {
            'name': name,
            'router_id': router_id,
            'floatingip_id': floatingip_id
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/vpn/vpnservices', payload)
    response_obj = json.loads(response_text)
    return response_obj['vpnservice']


@api
def get_vpnservices():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/vpnservices')
    response_obj = json.loads(response_text)
    return response_obj['vpnservices']


@api
def get_vpnservice(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/vpnservices?name={}'.format(name))
    response_obj = json.loads(response_text)
    vpnservices = response_obj['vpnservices']
    return vpnservices[0] if vpnservices else None


@api
def delete_vpnservice(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/vpn/vpnservices/{}'.format(id))


def delete_vpnservice_by_name(name):
    vpnservice = get_vpnservice(name)
    if vpnservice:
        delete_vpnservice(vpnservice['id'])


@api
def create_ikepolicy(name):
    payload = {
        'ikepolicy': {
            'name': name
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/vpn/ikepolicies', payload)
    response_obj = json.loads(response_text)
    return response_obj['ikepolicy']


@api
def get_ikepolicys():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/ikepolicies')
    response_obj = json.loads(response_text)
    return response_obj['ikepolicies']


@api
def get_ikepolicy(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/ikepolicies?name={}'.format(name))
    response_obj = json.loads(response_text)
    ikepolicies = response_obj['ikepolicies']
    return ikepolicies[0] if ikepolicies else None


@api
def delete_ikepolicy(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/vpn/ikepolicies/{}'.format(id))


def delete_ikepolicy_by_name(name):
    ikepolicy = get_ikepolicy(name)
    if ikepolicy:
        delete_ikepolicy(ikepolicy['id'])


@api
def create_ipsecpolicy(name):
    payload = {
        'ipsecpolicy': {
            'name': name
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/vpn/ipsecpolicies', payload)
    response_obj = json.loads(response_text)
    return response_obj['ipsecpolicy']


@api
def get_ipsecpolicys():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/ipsecpolicies')
    response_obj = json.loads(response_text)
    return response_obj['ipsecpolicies']


@api
def get_ipsecpolicy(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/ipsecpolicies?name={}'.format(name))
    response_obj = json.loads(response_text)
    ipsecpolicies = response_obj['ipsecpolicies']
    return ipsecpolicies[0] if ipsecpolicies else None


@api
def delete_ipsecpolicy(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/vpn/ipsecpolicies/{}'.format(id))


def delete_ipsecpolicy_by_name(name):
    ipsecpolicy = get_ipsecpolicy(name)
    if ipsecpolicy:
        delete_ipsecpolicy(ipsecpolicy['id'])


@api
def create_endpoint_group(name, type, endpoints):
    payload = {
        'endpoint_group': {
            'name': name,
            'type': type,
            'endpoints': endpoints
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/vpn/endpoint-groups', payload)
    response_obj = json.loads(response_text)
    return response_obj['endpoint_group']


@api
def get_endpoint_groups():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/endpoint-groups')
    response_obj = json.loads(response_text)
    return response_obj['endpoint_groups']


@api
def get_endpoint_group(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/endpoint-groups?name={}'.format(name))
    response_obj = json.loads(response_text)
    endpoint_groups = response_obj['endpoint_groups']
    return endpoint_groups[0] if endpoint_groups else None


@api
def delete_endpoint_group(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/vpn/endpoint-groups/{}'.format(id))


def delete_endpoint_group_by_name(name):
    endpoint_group = get_endpoint_group(name)
    if endpoint_group:
        delete_endpoint_group(endpoint_group['id'])


@api
def create_ipsec_site_connection(name, vpnservice_id, ikepolicy_id, ipsecpolicy_id, local_ep_group_id, peer_ep_group_id,
                                 peer_id, peer_address, psk):
    payload = {
        'ipsec_site_connection': {
            'name': name,
            'vpnservice_id': vpnservice_id,
            'ikepolicy_id': ikepolicy_id,
            'ipsecpolicy_id': ipsecpolicy_id,
            'local_ep_group_id': local_ep_group_id,
            'peer_ep_group_id': peer_ep_group_id,
            'peer_id': peer_id,
            'peer_address': peer_address,
            'psk': psk
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/vpn/ipsec-site-connections', payload)
    response_obj = json.loads(response_text)
    return response_obj['ipsec_site_connection']


@api
def get_ipsec_site_connections():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/ipsec-site-connections')
    response_obj = json.loads(response_text)
    return response_obj['ipsec_site_connections']


@api
def get_ipsec_site_connection(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/vpn/ipsec-site-connections?name={}'.format(name))
    response_obj = json.loads(response_text)
    ipsec_site_connections = response_obj['ipsec_site_connections']
    return ipsec_site_connections[0] if ipsec_site_connections else None


@api
def delete_ipsec_site_connection(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/vpn/ipsec-site-connections/{}'.format(id))


def delete_ipsec_site_connection_by_name(name):
    ipsec_site_connection = get_ipsec_site_connection(name)
    if ipsec_site_connection:
        delete_ipsec_site_connection(ipsec_site_connection['id'])


@api
def get_images():
    response_text = http_get(GLANCE_BASE_URL + '/v2/images')
    response_obj = json.loads(response_text)
    return response_obj['images']


@api
def get_image(name):
    response_text = http_get(GLANCE_BASE_URL + '/v2/images?name={}'.format(name))
    response_obj = json.loads(response_text)
    images = response_obj['images']
    return images[0] if images else None


@api
def get_flavors():
    response_text = http_get(NOVA_BASE_URL + '/flavors')
    response_obj = json.loads(response_text)
    return response_obj['flavors']


@api
def get_flavor(flavor_name):
    response_text = http_get(NOVA_BASE_URL + '/flavors?name={}'.format(flavor_name))
    response_obj = json.loads(response_text)
    flavors = response_obj['flavors']
    return flavors[0] if flavors else None


@api
def create_server(name, flavor_id, image_id, availability_zone, port_id, security_group_name='default'):
    payload = {
        'server': {
            'name': name,
            'flavorRef': flavor_id,
            'imageRef': image_id,
            'availability_zone': availability_zone,
            'networks': [{'port': port_id}],
            'security_groups': [{'name': security_group_name}]
        }
    }
    response_text = http_post(NOVA_BASE_URL + '/servers', payload)
    response_obj = json.loads(response_text)
    return response_obj['server']


@api
def get_servers():
    response_text = http_get(NOVA_BASE_URL + '/servers')
    response_obj = json.loads(response_text)
    return response_obj['servers']


@api
def get_server(name):
    response_text = http_get(NOVA_BASE_URL + '/servers?name={}'.format(name))
    response_obj = json.loads(response_text)
    servers = response_obj['servers']
    return servers[0] if servers else None


@api
def get_servers_detail():
    response_text = http_get(NOVA_BASE_URL + '/servers/detail')
    response_obj = json.loads(response_text)
    return response_obj['servers']


@api
def get_server_detail(name):
    response_text = http_get(NOVA_BASE_URL + '/servers/detail?name={}'.format(name))
    response_obj = json.loads(response_text)
    servers = response_obj['servers']
    return servers[0] if servers else None


@api
def delete_server(id):
    http_delete(NOVA_BASE_URL + '/servers/{}'.format(id))


def delete_server_by_name(name):
    server = get_server(name)
    if server:
        delete_server(server['id'])


@api
def create_loadbalancer(name, vip_subnet_id, vip_address, bandwidth):
    payload = {
        'loadbalancer': {
            'name': name,
            'vip_subnet_id': vip_subnet_id,
            'vip_address': vip_address,
            'bandwidth': bandwidth
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/lbaas/loadbalancers', payload)
    response_obj = json.loads(response_text)
    return response_obj['loadbalancer']


@api
def get_loadbalancers():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/lbaas/loadbalancers')
    response_obj = json.loads(response_text)
    return response_obj['loadbalancers']


@api
def get_loadbalancer(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/lbaas/loadbalancers?name={}'.format(name))
    response_obj = json.loads(response_text)
    loadbalancers = response_obj['loadbalancers']
    return loadbalancers[0] if loadbalancers else None


@api
def delete_loadbalancer(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/lbaas/loadbalancers/{}'.format(id))


def delete_loadbalancer_by_name(name):
    loadbalancer = get_loadbalancer(name)
    if loadbalancer:
        delete_loadbalancer(loadbalancer['id'])


@api
def create_firewall_rule(name, source_ip, destination_ip, destination_port, protocol, action):
    payload = {
        'firewall_rule': {
            'name': name,
            'source_ip_address': source_ip,
            'destination_ip_address': destination_ip,
            'destination_port': destination_port,
            'protocol': protocol,
            'action': action,
            'ip_version': 4
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/fw/firewall_rules', payload)
    response_obj = json.loads(response_text)
    return response_obj['firewall_rule']


@api
def get_firewall_rules():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/fw/firewall_rules')
    response_obj = json.loads(response_text)
    return response_obj['firewall_rules']


@api
def get_firewall_rule(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/fw/firewall_rules?name={}'.format(name))
    response_obj = json.loads(response_text)
    firewall_rules = response_obj['firewall_rules']
    return firewall_rules[0] if firewall_rules else None


@api
def delete_firewall_rule(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/fw/firewall_rules/{}'.format(id))


def delete_firewall_rule_by_name(name):
    firewall_rule = get_firewall_rule(name)
    if firewall_rule:
        delete_firewall_rule(firewall_rule['id'])


@api
def create_firewall_policy(name, firewall_rules_id):
    payload = {
        'firewall_policy': {
            'name': name,
            'firewall_rules': [firewall_rules_id]
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/fw/firewall_policies', payload)
    response_obj = json.loads(response_text)
    return response_obj['firewall_policy']


@api
def get_firewall_policys():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/fw/firewall_policies')
    response_obj = json.loads(response_text)
    return response_obj['firewall_policies']


@api
def get_firewall_policy(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/fw/firewall_policies?name={}'.format(name))
    response_obj = json.loads(response_text)
    firewall_policies = response_obj['firewall_policies']
    return firewall_policies[0] if firewall_policies else None


@api
def delete_firewall_policy(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/fw/firewall_policies/{}'.format(id))


def delete_firewall_policy_by_name(name):
    firewall_policy = get_firewall_policy(name)
    if firewall_policy:
        delete_firewall_policy(firewall_policy['id'])


@api
def create_firewall(name, router_id, policy_id):
    payload = {
        'firewall': {
            'name': name,
            'router_ids': [router_id],
            'firewall_policy_id': policy_id,
            'admin_state_up': True
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/fw/firewalls', payload)
    response_obj = json.loads(response_text)
    return response_obj['firewall']


@api
def get_firewalls():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/fw/firewalls')
    response_obj = json.loads(response_text)
    return response_obj['firewalls']


@api
def get_firewall(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/fw/firewalls?name={}'.format(name))
    response_obj = json.loads(response_text)
    firewalls = response_obj['firewalls']
    return firewalls[0] if firewalls else None


@api
def delete_firewall(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/fw/firewalls/{}'.format(id))


def delete_firewall_by_name(name):
    firewall = get_firewall(name)
    if firewall:
        delete_firewall(firewall['id'])


@api
def create_nat_gateway(name, vpc_id):
    payload = {
        'nat_gateway': {
            'name': name,
            'vpc_id': vpc_id
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/nat-gateways', payload)
    response_obj = json.loads(response_text)
    return response_obj['nat_gateway']


@api
def get_nat_gateways():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/nat-gateways')
    response_obj = json.loads(response_text)
    return response_obj['nat_gateways']


@api
def get_nat_gateway(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/nat-gateways?name={}'.format(name))
    response_obj = json.loads(response_text)
    nat_gateways = response_obj['nat_gateways']
    return nat_gateways[0] if nat_gateways else None


@api
def delete_nat_gateway(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/nat-gateways/{}'.format(id))


def delete_nat_gateway_by_name(name):
    nat_gateway = get_nat_gateway(name)
    if nat_gateway:
        delete_nat_gateway(nat_gateway['id'])


@api
def create_nat_gateway_snat_rules(name, nat_gateway_id, subnet_cidr, fip_ip, fip_bandwidth):
    payload = {
        'nat_gateway_snat_rule': {
            'name': name,
            'nat_gateway_id': nat_gateway_id,
            'subnet_cidr': subnet_cidr,
            'fip_ip': fip_ip,
            'fip_bandwidth': fip_bandwidth
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/nat-gateway-snat-rules', payload)
    response_obj = json.loads(response_text)
    return response_obj['nat_gateway_snat_rule']


@api
def get_nat_gateway_snat_rules():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/nat-gateway-snat-rules')
    response_obj = json.loads(response_text)
    return response_obj['nat_gateway_snat_rules']


@api
def get_nat_gateway_snat_rule(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/nat-gateway-snat-rules?name={}'.format(name))
    response_obj = json.loads(response_text)
    nat_gateway_snat_rules = response_obj['nat_gateway_snat_rules']
    return nat_gateway_snat_rules[0] if nat_gateway_snat_rules else None


@api
def delete_nat_gateway_snat_rule(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/nat-gateway-snat-rules/{}'.format(id))


def delete_nat_gateway_snat_rule_by_name(name):
    nat_gateway_snat_rule = get_nat_gateway_snat_rule(name)
    if nat_gateway_snat_rule:
        delete_nat_gateway_snat_rule(nat_gateway_snat_rule['id'])


@api
def create_nat_gateway_dnat_rules(name, nat_gateway_id, external_ip, external_port, internal_ip, internal_port,
                                  protocol, external_bandwidth):
    payload = {
        'nat_gateway_dnat_rule': {
            'name': name,
            'nat_gateway_id': nat_gateway_id,
            'external_ip': external_ip,
            'external_port': external_port,
            'internal_ip': internal_ip,
            'internal_port': internal_port,
            'protocol': protocol,
            'external_bandwidth': external_bandwidth,
        }
    }
    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/nat-gateway-dnat-rules', payload)
    response_obj = json.loads(response_text)
    return response_obj['nat_gateway_dnat_rule']


@api
def get_nat_gateway_dnat_rules():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/nat-gateway-dnat-rules')
    response_obj = json.loads(response_text)
    return response_obj['nat_gateway_dnat_rules']


@api
def get_nat_gateway_dnat_rule(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/nat-gateway-dnat-rules?name={}'.format(name))
    response_obj = json.loads(response_text)
    nat_gateway_dnat_rules = response_obj['nat_gateway_dnat_rules']
    return nat_gateway_dnat_rules[0] if nat_gateway_dnat_rules else None


@api
def delete_nat_gateway_dnat_rule(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/nat-gateway-dnat-rules/{}'.format(id))


def delete_nat_gateway_dnat_rule_by_name(name):
    nat_gateway_dnat_rule = get_nat_gateway_dnat_rule(name)
    if nat_gateway_dnat_rule:
        delete_nat_gateway_dnat_rule(nat_gateway_dnat_rule['id'])


@api
def create_ipv6_ns_qos_policy(name, router_id, port_id, qos_policy_id):
    payload = {
        'ipv6_ns_qos_policy': {
            'name': name,
            'router_id': router_id,
            'port_id': port_id,
            'qos_policy_id': qos_policy_id
        }
    }

    response_text = http_post(NEUTRON_BASE_URL + '/v2.0/ipv6_ns_qos_policies', payload)
    response_obj = json.loads(response_text)
    return response_obj['ipv6_ns_qos_policy']


@api
def get_ipv6_ns_qos_policies():
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/ipv6_ns_qos_policies')
    response_obj = json.loads(response_text)
    return response_obj['ipv6_ns_qos_policies']


@api
def get_ipv6_ns_qos_policy(name):
    response_text = http_get(NEUTRON_BASE_URL + '/v2.0/ipv6_ns_qos_policies?name={}'.format(name))
    response_obj = json.loads(response_text)
    ipv6_ns_qos_policies = response_obj['ipv6_ns_qos_policies']
    return ipv6_ns_qos_policies[0] if ipv6_ns_qos_policies else None


@api
def delete_ipv6_ns_qos_policy(id):
    http_delete(NEUTRON_BASE_URL + '/v2.0/ipv6_ns_qos_policies/{}'.format(id))


def delete_ipv6_ns_qos_policy_by_name(name):
    ipv6_ns_qos_policy = get_ipv6_ns_qos_policy(name)
    if ipv6_ns_qos_policy:
        delete_ipv6_ns_qos_policy()


@api
def update_ipv6_ns_qos_policy(id, port_id=None, qos_policy_id=None):
    if not port_id and not qos_policy_id:
        return

    payload = {'ipv6_ns_qos_policy': {}}
    if port_id:
        payload['ipv6_ns_qos_policy']['port_id'] = port_id
    if qos_policy_id:
        payload['ipv6_ns_qos_policy']['qos_policy_id'] = qos_policy_id

    response_text = http_put(NEUTRON_BASE_URL + '/v2.0/ipv6_ns_qos_policies/{}'.format(id), payload)
    response_obj = json.loads(response_text)
    return response_obj['ipv6_ns_qos_policy']


def get_argparser():
    """
    Supports the command-line arguments listed below.
    """
    parser = argparse.ArgumentParser(
        description='{} is an concurrent neutron API testing tool.'.format(BASENAME))
    parser.add_argument('-c', '--concurrency',
                        dest='concurrency',
                        type=int,
                        required=True,
                        help='Concurrent value to execute neutron API')
    parser.add_argument('-l', '--log-file',
                        dest='log_file',
                        type=str,
                        required=False,
                        help='Log file path')
    return parser


def delete_all_resources(concurrency):

    # Delete floatingip
    floatingips = get_floatingips()
    for fip in floatingips:
        try:
            delete_floatingip(fip['id'])
        except Exception:
            LOG.exception()

    # Delete port
    for i in range(concurrency):
        try:
            delete_port_by_name('neutron-api3-port-%d' % i)
        except Exception:
            LOG.exception()

    for i in range(1):
        try:
            router = get_router('neutron-api3-router-%d' % i)
            subnet = get_subnet('neutron-api3-subnet-%d' % i)
            remove_router_interface(router['id'], subnet['id'])
        except Exception:
            LOG.exception()

    # Delete router
    for i in range(1):
        try:
            delete_router_by_name('neutron-api3-router-%d' % i)
        except Exception:
            LOG.exception()

    # Delete subnet
    for i in range(1):
        try:
            delete_subnet_by_name('neutron-api3-subnet-%d' % i)
        except Exception:
            LOG.exception()

    # Delete network
    for i in range(1):
        try:
            delete_network_by_name('neutron-api3-network-%d' % i)
        except Exception:
            LOG.exception()


def main():
    parser = get_argparser()
    args = parser.parse_args()

    # Write log to file
    if args.log_file:
        handler = logging.FileHandler(filename=args.log_file, mode='w', encoding='UTF-8')
        formatter = logging.Formatter('%(asctime)s %(process)d %(levelname)s [%(funcName)s line:%(lineno)d]: %(message)s')
        handler.setFormatter(formatter)
        LOG.addHandler(handler)

    pool = eventlet.GreenPool()
    try:
        # Create test Data
        # Create network
        networks = []
        threads = []
        for i in range(1):
            thread = pool.spawn(create_network, 'neutron-api3-network-%d' % i,
                                ['az1'])
            threads.append(thread)
        for thread in threads:
            networks.append(thread.wait())
        
        # Create subnet
        subnets = []
        threads = []
        for i in range(len(networks)):
            thread = pool.spawn(create_subnet, 'neutron-api3-subnet-%d' % i,
                                networks[i]['id'], '192.%d.3.0/24' % i)
            threads.append(thread)
        for thread in threads:
            subnets.append(thread.wait())

        # Create router
        routers = []
        threads = []
        for i in range(len(networks)):
            thread = pool.spawn(create_router, 'neutron-api3-router-%d' % i)
            threads.append(thread)
        for thread in threads:
            routers.append(thread.wait())

        # Add router interface
        threads = []
        for i in range(len(routers)):
            thread = pool.spawn(add_router_interface, routers[i]['id'],
                                subnets[i]['id'])
            threads.append(thread)
        for thread in threads:
            thread.wait()

        # Create ports
        ports = []
        threads = []
        for i in range(args.concurrency):
            time.sleep(random.randint(200, 999) / 1000)
            thread = pool.spawn(create_port, 'neutron-api3-port-%d' % i,
                                networks[0]['id'], subnets[0]['id'])
            threads.append(thread)
        for thread in threads:
            ports.append(thread.wait())
            
        start_st = time.time()
        # Create floatingip
        floatingips = []
        threads = []
        '''
        for i in range(args.concurrency):
            thread = pool.spawn(create_floatingip_assoc_port,
                                '5f06867a-8246-4719-a080-4b8a35a853e8', ports[i]['id'])
            threads.append(thread)
        for thread in threads:
            floatingips.append(thread.wait())
        LOG.info('[{} {}] elapsed time: {} seconds'
                 .format(args.concurrency, 'floatingips concurrency create',
                         time.time() - start_st))
        '''
        for i in range(args.concurrency):
            time.sleep(random.randint(200, 999) / 1000)
            thread = pool.spawn(create_floatingip,
                                '5f06867a-8246-4719-a080-4b8a35a853e8')
            threads.append(thread)
        for thread in threads:
            floatingips.append(thread.wait())
        LOG.info('[{} {}] elapsed time: {} seconds'
                 .format(args.concurrency, 'floatingips concurrency create',
                         time.time() - start_st))
        #import pdb;pdb.set_trace()                 
        start_st = time.time()
        # associate fips
        try:
            threads = []
            for i in range(args.concurrency):
                time.sleep(random.randint(10, 50) / 1000)
                thread = pool.spawn(update_floatingip, floatingips[i]['id'],
                                    ports[i]['id'])
                threads.append(thread)
            for thread in threads:
                thread.wait()
            LOG.info('[{} {}] elapsed time: {} seconds'
                     .format(args.concurrency,
                             'floatingips concurrency associate',
                             time.time() - start_st))
        except Exception:
            threads = []
            for fip in floatingips:
                thread = pool.spawn(delete_floatingip, fip['id'])
                threads.append(thread)
            for thread in threads:
                thread.wait()
            raise Exception
   
        start_st = time.time()
        # disassociate fips
        try:
            threads = []
            for i in range(args.concurrency):
                time.sleep(random.randint(10, 50) / 1000)
                thread = pool.spawn(update_floatingip, floatingips[i]['id'])
                threads.append(thread)
            for thread in threads:
                thread.wait()
            LOG.info('[{} {}] elapsed time: {} seconds'
                     .format(args.concurrency,
                             'floatingips concurrency disassociate',
                             time.time() - start_st))
        except Exception:
            threads = []
            for fip in floatingips:
                thread = pool.spawn(delete_floatingip, fip['id'])
                threads.append(thread)
            for thread in threads:
                thread.wait()
            raise Exception
        
        start_st = time.time()
        # Delete floatingip
        threads = []
        for fip in floatingips:
            thread = pool.spawn(delete_floatingip, fip['id'])
            threads.append(thread)
        for thread in threads:
            thread.wait()
        LOG.info('[{} {}] elapsed time: {} seconds'
                .format(args.concurrency,
                        'floatingips concurrency delete',
                        time.time() - start_st))
        # Delete port
        threads = []
        for port in ports:
            thread = pool.spawn(delete_port, port['id'])
            threads.append(thread)
        for thread in threads:
            thread.wait()

        # Remove router interface
        threads = []
        for i in range(len(routers)):
            thread = pool.spawn(remove_router_interface, routers[i]['id'],
                                subnets[i]['id'])
            threads.append(thread)
        for thread in threads:
            thread.wait()

        # Delete router
        threads = []
        for router in routers:
            thread = pool.spawn(delete_router, router['id'])
            threads.append(thread)
        for thread in threads:
            thread.wait()

        # Delete subnet
        threads = []
        for subnet in subnets:
            thread = pool.spawn(delete_subnet, subnet['id'])
            threads.append(thread)
        for thread in threads:
            thread.wait()
        
        # Delete network
        threads = []
        for network in networks:
            thread = pool.spawn(delete_network, network['id'])
            threads.append(thread)
        for thread in threads:
            thread.wait()

    except Exception:
        LOG.exception('Exception happened while testing neutron API')
        delete_all_resources(args.concurrency)


# Start program
if __name__ == '__main__':
    main()
