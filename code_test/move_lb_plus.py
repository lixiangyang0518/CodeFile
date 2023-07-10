# _*_ coding:utf-8 _*_
from sqlalchemy import create_engine
from sqlalchemy import Column, String, Integer, Enum
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from nuage_neutron.vsdclient.common.nuagelib import NuageGatewayRedundantPort
from collections import OrderedDict
from copy import deepcopy
from nuage_neutron.vsdclient import restproxy
from nuageextension.netlib import nuageextendlib
from nuageextension.f5_lbaas import lbaas as f5_driver
from neutron_lib import exceptions as e
from nuage_neutron.vsdclient.common import nuagelib
from neutron.db.models import l3 as l3_model
from nuageextension.newarch.db.models import db_model
from neutron_lib import constants as lib_constants
from nuage_neutron.plugins.common import nuagedb
from nuageextension.newarch.plugins.common import newarch_model
from nuageextension.newarch.utils.dummy_port import NetCreateDict
from nuageextension.newarch.utils.dummy_port import PortCreateDict
from oslo_serialization import jsonutils
from oslo_config import cfg
from oslo_utils import uuidutils
from neutron.db import models_v2
from neutron.common import utils
import os
import sys
import six
import json
import random
import netaddr
import requests
import ipaddress
import ConfigParser
import IPy as ipy
import logging
LOG = logging.getLogger('log')

# 连接数据库
neutron_config = '/etc/neutron/neutron.conf'
config = ConfigParser.ConfigParser()
config.readfp(open(neutron_config))
conn = config.get('database', 'connection')
engine = create_engine(conn)
Session = sessionmaker(bind=engine)
session = Session()

database = cfg.OptGroup(name='database',
                        title='group database Options')
opts = [
    cfg.StrOpt('connection',
               default='',
               help='item connection in group database.')
]
cfg.CONF.register_group(database)
cfg.CONF.register_opts(opts, group=database)

opt_group = cfg.OptGroup('F5')
opts = [
    cfg.StrOpt('username'),
    cfg.StrOpt('password'),
]
cfg.CONF.register_group(opt_group)
cfg.CONF.register_opts(opts, group=opt_group)

restproxy_opts = [
    cfg.StrOpt('server', default='vsd.example.com:8443',
               help="IP address and port of Nuage's VSD server or cluster"),
    cfg.StrOpt('serverauth', default='csproot:csproot',
               secret=True,
               help="Username and password for authentication"),
    cfg.BoolOpt('serverssl', default=True,
                help="Boolean for SSL connection with VSD server"),
    cfg.StrOpt('verify_cert', default='False',
               help="Either a boolean (True or False), indicating whether "
                    "we verify the VSD's certificate, or a string which is "
                    "the local path of the VSD's PEM file or CA_BUNDLE file "
                    "to be verified"),
    cfg.IntOpt('server_timeout', default=30,
               help="VSD server invocation timeout"),
    cfg.IntOpt('server_max_retries', default=5,
               help="Number of retries invoking VSD server"),
    cfg.StrOpt('base_uri', default='/nuage/api/v5_0',
               help="Nuage provided base uri to reach out to VSD"),
    cfg.StrOpt('organization', default='csp',
               help="Organization name in which VSD will orchestrate "
                    "network resources using openstack"),
    cfg.StrOpt('auth_resource', default='/me',
               help="Nuage provided uri for initial authorization to "
                    "access VSD"),
    cfg.StrOpt('cms_id', default=None,
               help="ID of a Cloud Management System on the VSD which "
                    "identifies this openstack instance"),
    cfg.StrOpt('gw_vlan_tag_lb')
]

restproxy_list_opts = [
    cfg.ListOpt('availibility_zone_list', default=[],
                help="Key is az name, value is IP address and port of Nuage's VSD server or cluster"),
    cfg.ListOpt('server_list', default=[],
                help="IP address and port of Nuage's VSD server or cluster"),
    cfg.ListOpt('serverauth_list', default=[],
                help="Username and password for authentication"),
    cfg.ListOpt('verify_cert_list', default=[],
                help="Either a boolean (True or False), indicating whether "
                     "we verify the VSD's certificate, or a string which is "
                     "the local path of the VSD's PEM file or CA_BUNDLE file "
                     "to be verified"),
    cfg.ListOpt('base_uri_list', default=[],
                help="Nuage provided base uri to reach out to VSD"),
    cfg.ListOpt('organization_list', default=[],
                help="Organization name in which VSD will orchestrate "
                     "network resources using openstack"),
    cfg.ListOpt('auth_resource_list', default=[],
                help="Nuage provided uri for initial authorization to "
                     "access VSD"),
    cfg.ListOpt('cms_id_list', default=[],
                help="ID of a Cloud Management System on the VSD which "
                     "identifies this openstack instance")
]

cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")
cfg.CONF.register_opts(restproxy_list_opts, "EXTENSIONRESTPROXY")

cfg.CONF(default_config_files=['/etc/neutron/neutron.conf',
                                '/etc/neutron/neutron_lbaas.conf',
                                '/etc/neutron/plugin.ini',
                                '/etc/neutron/f5_nfv.ini'])
# 获取 F5配置文件信息
f5_nfv_file = '/etc/neutron/f5_nfv.ini'
f5h_conf_file = '/etc/neutron/f5_nfv_az.conf'
config = ConfigParser.ConfigParser()
config.readfp(open(f5_nfv_file))
username = config.get('F5', 'username')
password = cfg.CONF.F5.password
inside_interface = config.get('F5', 'inside_interface')
outside_interface = config.get('F5', 'outside_interface')

if not (os.environ.get('OS_USERNAME') and os.environ.get('OS_PASSWORD') and os.environ.get(
        'OS_PROJECT_NAME') and os.environ.get('OS_AUTH_URL') and os.environ.get('OS_REGION_NAME')):
    print('Keystone environment variables not found, please source keystonerc_xxx file first!\n')
    sys.exit(1)

USERNAME = os.environ.get('OS_USERNAME')
PASSWORD = os.environ.get('OS_PASSWORD')
project = os.environ.get('OS_PROJECT_NAME')
KEYSTONE_URL = os.environ.get('OS_AUTH_URL')[:os.environ.get('OS_AUTH_URL').rfind('/')]
NEUTRON_BASE_URL = ''
NOVA_BASE_URL = ''
GLANCE_BASE_URL = ''
REGION = os.environ.get('OS_REGION_NAME')
SUPPORT_PROVIDER = ['nokia', 'f5hardware']
DEVICE_OWNER_LOADBALANCER = "network:f5lbaasv2"
NET_STATUS_ACTIVE = 'ACTIVE'

FAKE_PORT_RULE_EXT_ID = 'ccccb42e-20e0-4c30-ac09-75e13eaaaaaa'
ACL_INGRESS_ID = 'eeeeb42e-20e0-4c30-ac09-75e13eeeeeee'

default_nuage = None
nuageclient_dict = {}

class F5Error(e.NeutronException):
    message = ("F5_NFV [node1: %(node1)s,node2: %(node2)s] return error %(error)s")

# 数据表映射
Base = declarative_base()

class Lbaas_f5_vlans_pool_az(Base):
    __tablename__ = 'lbaas_f5_vlans_pool_az'
    id = Column(Integer, primary_key=True)
    node1 = Column(String(255))
    node2 = Column(String(255))
    mac1 = Column(String(32))
    mac2 = Column(String(32))
    min_vlan = Column(Integer)
    max_vlan = Column(Integer)
    vrsg_id = Column(String(255))
    az = Column(String(255))
    key = Column(String(255))
    used = Column(Integer)
    used_bandwidth = Column(Integer)
    max_bandwidth = Column(Integer)
    max_session = Column(Integer)
    max_newsession = Column(Integer)
    used_session = Column(Integer)
    used_newsession = Column(Integer)
    special = Column(Integer)

class Lbaas_F5_snatpoolports_az(Base):
    __tablename__ = 'lbaas_f5_snatpoolports_az'
    loadbalancer_id =  Column(String(36), primary_key=True)
    port_id = Column(String(36), primary_key=True)

class F5_loadbalancers_az(Base):
    __tablename__ = 'lbaas_f5_loadbalancers_az'
    id = Column(Integer, primary_key=True)
    node1 = Column(String(255))
    node2 = Column(String(255))
    vrsg_id = Column(String(255))
    vlan = Column(Integer)
    neutron_id = Column(String(73))
    self_port1 = Column(String(36))
    self_port2 = Column(String(36))
    key = Column(String(36))
    bandwidth = Column(Integer)
    session = Column(Integer)
    newsession = Column(Integer)
    inactive_f5_node = Column(String(255))

class Lbaas_F5_available_vlans_az(Base):
    __tablename__ = 'lbaas_f5_available_vlans_az'
    id = Column(Integer, primary_key=True)
    vlanspool_id = Column(Integer)
    vlan = Column(Integer)

class Lbaas_Loadbalancers(Base):
    __tablename__ = 'lbaas_loadbalancers'
    id = Column(String(36), primary_key=True, nullable=False, default=None)
    project_id = Column(String(255), nullable=True, default=None)
    name = Column(String(255), nullable=True, default=None)
    description = Column(String(11600), nullable=True, default=None)
    vip_port_id = Column(String(36), nullable=True, default=None)
    vip_subnet_id = Column(String(36), nullable=False, default=None)
    vip_address = Column(String(36), nullable=True, default=None)
    admin_state_up = Column(Integer, nullable=False, default=None)
    provisioning_status = Column(String(16), nullable=False, default=None)
    operating_status = Column(String())
    flavor_id = Column(String(36))
    bandwidth = Column(Integer)
    availability_zone_hints = Column(String(255))
    flavor = Column(Integer)
    max_concurrency = Column(Integer)
    new_connection = Column(Integer)
    access_log = Column(Integer)

class Lbaas_Listener(Base):
    __tablename__ = 'lbaas_listeners'
    id = Column(String(255),primary_key=True)
    project_id = Column(String(255))
    name = Column(String(255))
    description = Column(String(225))
    protocol = Column(Enum('HTTP','HTTPS','TCP','UDP','TERMINATED_HTTPS'))
    protocol_port = Column(Integer)
    connection_limit = Column(Integer)
    loadbalancer_id = Column(String(36))
    default_pool_id = Column(String(36))
    admin_state_up = Column(Integer)
    provisioning_status = Column(String(16))
    operating_status = Column(String(16))
    default_tls_container_id = Column(String(128))
    transparent = Column(Integer)
    mutual_authentication_up = Column(Integer)
    ca_container_id = Column(String(128))
    redirect_up = Column(Integer)
    redirect_protocol = Column(Enum('HTTP','HTTPS','TCP','TERMINATED_HTTPS','UDP'))
    redirect_port = Column(Integer)
    http2 = Column(Integer)
    keepalive_timeout = Column(Integer)
    tls_protocols = Column(String(128))
    cipher_suites = Column(String(1024))
    proxy_protocol = Column(Integer)

class Lbaas_Pools(Base):
    __tablename__ = 'lbaas_pools'
    id = Column(String(36), primary_key=True)
    project_id = Column(String(255))
    name = Column(String(255))
    description = Column(String(225))
    protocol = Column(Enum('HTTP','HTTPS','TCP','UDP'))
    lb_algorithm = Column(Enum('ROUND_ROBIN','LEAST_CONNECTIONS','SOURCE_IP'))
    healthmonitor_id = Column(String(36))
    admin_state_up = Column(Integer)
    provisioning_status = Column(String(16))
    operating_status = Column(String(16))
    loadbalancer_id = Column(String(36))

class Lbaas_members(Base):
    __tablename__ = 'lbaas_members'
    id = Column(String(36), primary_key=True)
    project_id = Column(String(255))
    pool_id = Column(String(36))
    subnet_id = Column(String(36))
    address = Column(String(64))
    protocol_port = Column(Integer)
    weight = Column(Integer)
    admin_state_up = Column(Integer)
    provisioning_status = Column(String(16))
    operating_status = Column(String(16))
    name = Column(String(255))

class Lbaas_healthmonitors(Base):
    __tablename__ = 'lbaas_healthmonitors'
    id = Column(String(36), primary_key=True)
    project_id = Column(String(255))
    type = Column(Enum('PING', 'TCP', 'HTTP', 'HTTP10', 'HTTP11', 'HTTPS', 'UDP'))
    delay = Column(Integer)
    timeout = Column(Integer)
    max_retries = Column(Integer)
    http_method = Column(String(16))
    url_path = Column(String(255))
    expected_codes = Column(String(64))
    admin_state_up = Column(Integer)
    provisioning_status = Column(String(16))
    name = Column(String(255))
    max_retries_down = Column(Integer)

class Lbaas_l7policies(Base):
    __tablename__ = 'lbaas_l7policies'
    id = Column(String(36), primary_key=True)
    project_id = Column(String(255))
    name = Column(String(255))
    description = Column(String(255))
    listener_id = Column(String(36))
    action = Column(Enum('REJECT', 'REDIRECT_TO_URL', 'REDIRECT_TO_POOL'))
    redirect_pool_id = Column(String(36))
    redirect_url = Column(String(255))
    position = Column(Integer)
    provisioning_status = Column(String(16))
    admin_state_up = Column(Integer)

class Lbaas_l7rules(Base):
    __tablename__ = 'lbaas_l7rules'
    id = Column(String(36), primary_key=True)
    project_id = Column(String(255))
    l7policy_id = Column(String(36))
    type = Column(Enum('HOST_NAME', 'PATH', 'FILE_TYPE', 'HEADER', 'COOKIE'))
    compare_type = Column(Enum('REGEX', 'STARTS_WITH', 'ENDS_WITH', 'CONTAINS', 'EQUAL_TO'))
    invert = Column(Integer)
    key = Column(String(255))
    value = Column(String(255))
    provisioning_status = Column(String(16))
    admin_state_up = Column(Integer)

class Subnets(Base):
    __tablename__ = 'subnets'
    id = Column(String(36), primary_key=True)
    name = Column(String(255))
    project_id = Column(String(255))
    network_id = Column(String(36))
    ip_version = Column(Integer)
    cidr = Column(String(64))
    gateway_ip = Column(String(64))
    enable_dhcp = Column(Integer)
    ipv6_ra_mode = Column(Enum('slaac', 'dhcpv6-stateful', 'dhcpv6-stateless'))
    ipv6_address_mode = Column(Enum('slaac', 'dhcpv6-stateful', 'dhcpv6-stateless'))
    subnetpool_id = Column(String(36))
    standard_attr_id = Column(String(Integer))
    segment_id = Column(String(36))
    path = Column(String(256))
    ip_frozen = Column(Integer)

class Ipallocations(Base):
    __tablename__ = 'ipallocations'
    port_id = Column(String(36))
    ip_address = Column(String(64), primary_key=True)
    subnet_id = Column(String(36), primary_key=True)
    network_id = Column(String(36), primary_key=True)

class Ports(Base):
    __tablename__ = 'ports'
    id = Column(String(36), primary_key=True)
    name = Column(String(255))
    project_id = Column(String(255))
    mac_address = Column(String(32))
    admin_state_up = Column(Integer)
    status = Column(String(16))
    device_id = Column(String(255))
    device_owner = Column(String(255))
    standard_attr_id = Column(Integer)
    ip_allocation = Column(String(16))
    profile = Column(String(256))

class Routerports(Base):
    __tablename__ = 'routerports'
    router_id = Column(String(36), primary_key=True)
    port_id = Column(String(36), primary_key=True)
    port_type = Column(String(255))

class NewarchDummyFip(Base):
    __tablename__ = 'newarch_dummyfip'
    id = Column(String(36), primary_key=True)
    project_id = Column(String(255))
    floating_ip_address = Column(String(64))
    floating_network_id = Column(String(36))
    floating_port_id = Column(String(36))
    fixed_port_id = Column(String(36))
    fixed_ip_address = Column(String(64))
    router_id = Column(String(36))
    last_known_router_id = Column(String(36))
    status = Column(String(16))
    standard_attr_id = Column(Integer)

class RestAPI(object):
    def __init__(self):
        self.token = None
        self.neutron_session = requests.session()
        self.keystone_v2_auth()

    def http_get(self, url):
        headers = {
            'Accept': 'application/json'
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
            'Content-Type': 'application/json'
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
            'Content-Type': 'application/json'
        }
        response = self.neutron_session.put(url, headers=headers,
                                            data=json.dumps(payload))
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
            'Accept': 'application/json'
            #'X-Auth-Token': self.token
        }
        response = self.neutron_session.delete(url, headers=headers)
        print("delete port response: {}, url: {}".format(response.status_code, response.url))
        if response.status_code == 401:
            self.keystone_v2_auth()
            self.http_delete(url)
        elif response.status_code != 204:
            raise Exception('http_delete({}) error, response: {}'.format(url, response.__dict__))

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
            token_id = self.token
            self.neutron_session.headers.update({'X-Auth-Token': token_id})
        else:
            raise Exception('keystone_v2_auth({}) error, response status code: {}'.format(url, response.status_code))

    def create_port(self, port_dict):
        port = {'port': port_dict}
        response_text = self.http_post(NEUTRON_BASE_URL + '/v2.0/ports', port)
        response_obj = json.loads(response_text)
        return response_obj['port']

    def delete_port(self, port_id):
        self.http_delete(NEUTRON_BASE_URL + '/v2.0/ports/' + port_id)

    def get_port(self, port_id):
        self.http_get(NEUTRON_BASE_URL + '/v2.0/ports/' + port_id)

class MyContext():
    def __init__(self, session):
        self.session = session
        self.is_admin = True
        self.is_advsvc = False

def check_lb_node(lb_id, node1, node2):

    # 检查lb是否存在
    lb_info = session.query(Lbaas_Loadbalancers).filter_by(id=lb_id).all()
    if len(lb_info) == 0:
        print("LB: {} not exist !".format(lb_id))
        return False
    else:
        # 检查输入的node是否正确
        input_node_list = []
        input_node_list.append(node1)
        input_node_list.append(node2)
        f5_vlans_pool_az_info = session.query(Lbaas_f5_vlans_pool_az).all()
        node_list = []
        for l in f5_vlans_pool_az_info:
            f5_node_list = []
            f5_node_list.append(l.node1)
            f5_node_list.append(l.node2)
            node_list.append(f5_node_list)
        if input_node_list in node_list:
            # 检查输入的node是否与lb的node一致
            f5_loadbalancer_az_info = session.query(F5_loadbalancers_az).filter_by(neutron_id=lb_id).first()
            if not f5_loadbalancer_az_info:
                print("LB: {} does not exist in table: lbaas_f5_loadbalancers_az !".format(lb_id))
                return False
            else:
                lb_ip1 = f5_loadbalancer_az_info.node1
                lb_ip2 = f5_loadbalancer_az_info.node2
                if lb_ip1 == node1 and lb_ip2 == node2:
                    print("LB: {} has already in f5_node1: {} f5_node2: {} !!!".format(lb_id, lb_ip1, lb_ip2))
                    return False
                else:
                    return True
        else:
            print("please inout right node !!!")
            return False

def get_lb_info(lb_id):
    l = session.query(Lbaas_Loadbalancers).filter_by(id=lb_id).first()
    lb_dict = OrderedDict()
    lb_dict['project_id'] = l.project_id
    lb_dict['lb_id'] = l.id
    lb_dict['lb_name'] = l.name
    lb_dict['lb_vip_port_id'] = l.vip_port_id
    lb_dict['vip_subnet_id'] = l.vip_subnet_id
    lb_dict['vip_address'] = l.vip_address
    lb_dict['admin_state_up'] = l.admin_state_up
    lb_dict['lb_bandwidth'] = l.bandwidth
    lb_dict['lb_availability_zone_hints'] = l.availability_zone_hints
    lb_dict['lb_flavor'] = l.flavor
    lb_dict['max_concurrency'] = l.max_concurrency
    lb_dict['new_connection'] = l.new_connection
    lb_dict['lb_provisioning_status'] = l.provisioning_status
    lb_dict['operating_status'] = l.operating_status

    # 获取两个 self port
    self_port_info = session.query(F5_loadbalancers_az).filter_by(neutron_id=lb_id).first()
    port1_info = session.query(Ipallocations).filter_by(port_id=self_port_info.self_port1).first()
    port2_info = session.query(Ipallocations).filter_by(port_id=self_port_info.self_port2).first()
    lb_dict['vlan'] = self_port_info.vlan
    lb_dict['node1'] = self_port_info.node1
    lb_dict['node2'] = self_port_info.node2
    lb_dict['self_port1_id'] = self_port_info.self_port1
    lb_dict['self_port2_id'] = self_port_info.self_port2
    lb_dict['self_port1_ip'] = port1_info.ip_address
    lb_dict['self_port2_ip'] = port2_info.ip_address

    # 获取两个 snat port
    snat_port_info = session.query(Lbaas_F5_snatpoolports_az).filter_by(loadbalancer_id=lb_id).all()
    snat_port_list = []
    for i in snat_port_info:
        port_address = session.query(Ipallocations).filter_by(port_id=i.port_id).first()
        snat_port_list.append(port_address.ip_address)

    snat_port1 = ''.join(snat_port_list[0])
    snat_port2 = ''.join(snat_port_list[1])
    lb_dict['snat_port1_ip'] = snat_port1
    lb_dict['snat_port2_ip'] = snat_port2

    # 获取 subnet
    subnet_info = session.query(Subnets).filter_by(id=l.vip_subnet_id).first()
    lb_dict['lb_subnet_name'] = subnet_info.name
    lb_dict['lb_subnet_network'] = subnet_info.network_id
    lb_dict['lb_subnet_ip_version'] = subnet_info.ip_version
    lb_dict['lb_subnet_cidr'] = subnet_info.cidr
    lb_dict['lb_subnet_gateway_ip'] = subnet_info.gateway_ip

    # 获取 router
    port_info = session.query(Ipallocations).filter_by(subnet_id=l.vip_subnet_id).first()
    router_info = session.query(Routerports).filter_by(port_id=port_info.port_id).first()
    router_id = router_info.router_id
    lb_dict['router_id'] = router_id
    return lb_dict

def get_f5_node_info(node1, node2):
    node_info = session.query(Lbaas_f5_vlans_pool_az).filter_by(node1=node1, node2=node2).first()
    node_dict = OrderedDict()
    node_dict['id'] = node_info.id
    node_dict['node1'] = node_info.node1
    node_dict['node2'] = node_info.node2
    node_dict['mac1'] = node_info.mac1
    node_dict['mac2'] = node_info.mac2
    node_dict['az'] = node_info.az
    node_dict['min_vlan'] = node_info.min_vlan
    node_dict['max_vlan'] = node_info.max_vlan
    node_dict['vrsg_id'] = node_info.vrsg_id
    node_dict['used'] = node_info.used
    node_dict['used_bandwidth'] = node_info.used_bandwidth
    node_dict['max_bandwidth'] = node_info.max_bandwidth
    node_dict['max_session'] = node_info.max_session
    node_dict['max_newsession'] = node_info.max_newsession
    node_dict['used_session'] = node_info.used_session
    node_dict['used_newsession'] = node_info.used_newsession
    node_dict['special'] = node_info.special
    return node_dict

def get_lb_listeners(lb_id):
    listeners_info = session.query(Lbaas_Listener).filter_by(loadbalancer_id=lb_id).all()

    listener_list = []
    for listener in listeners_info:
        listener_dict = OrderedDict()
        listener_dict['listener_id'] = listener.id
        listener_dict['listener_name'] = listener.name
        listener_dict['listener_description'] = listener.description
        listener_dict['listener_protocol'] = listener.protocol
        listener_dict['listener_protocol_port'] = listener.protocol_port
        listener_dict['listener_connection_limit'] = listener.connection_limit
        listener_dict['listener_loadbalancer_id'] = listener.loadbalancer_id
        listener_dict['listener_default_pool_id'] = listener.default_pool_id
        listener_dict['listener_admin_state_up'] = listener.admin_state_up
        listener_dict['listener_provisioning_status'] = listener.provisioning_status
        listener_dict['listener_default_tls_container_id'] = listener.default_tls_container_id
        listener_dict['listener_transparent'] = listener.transparent
        listener_dict['listener_mutual_authentication_up'] = listener.mutual_authentication_up
        listener_dict['listener_redirect_up'] = listener.redirect_up
        listener_dict['listener_redirect_protocol'] = listener.redirect_protocol
        listener_dict['listener_redirect_port'] = listener.redirect_port
        listener_dict['listener_http2'] = listener.http2
        listener_dict['listener_keepalive_timeout'] = listener.keepalive_timeout
        listener_dict['listener_tls_protocols'] = listener.tls_protocols
        listener_dict['listener_cipher_suites'] = listener.cipher_suites
        listener_dict['listener_project_id'] = listener.project_id
        listener_dict['listener_ca_container_id'] = listener.ca_container_id

        listener_list.append(listener_dict)
    return listener_list

def get_port_info(id):
    port_info = session.query(Ports).filter_by(id=id).first()
    port_ip_info = session.query(Ipallocations).filter_by(port_id=id).all()
    port_dict = OrderedDict()
    fixed_ips = []
    port_dict['id'] = id
    port_dict['name'] = port_info.name
    port_dict['project_id'] = port_info.project_id
    port_dict['mac_address'] = port_info.mac_address

    for i in range(0, len(port_ip_info)):
        fixed_ips.append(port_ip_info[i].ip_address)
        port_dict['fixed_ips'] = fixed_ips

    return port_dict

def get_lb_pools(lb_id):
    pool_info = session.query(Lbaas_Pools).filter_by(loadbalancer_id=lb_id).all()
    pool_list = []
    healthmonitor_list = []
    for pool in pool_info:
        pool_dict = OrderedDict()
        pool_dict['id'] = pool.id
        pool_dict['name'] = pool.name
        pool_dict['description'] = pool.description
        pool_dict['protocol'] = pool.protocol
        pool_dict['lb_algorithm'] = pool.lb_algorithm
        pool_dict['admin_state_up'] = pool.admin_state_up
        pool_dict['provisioning_status'] = pool.provisioning_status
        pool_dict['operating_status'] = pool.operating_status
        pool_dict['loadbalancer_id'] = pool.loadbalancer_id
        pool_dict['healthmonitor_id'] = pool.healthmonitor_id
        pool_dict['project_id'] = pool.project_id
        healthmonitor_id = pool.healthmonitor_id
        pool_list.append(pool_dict)
        healthmonitor_list.append(healthmonitor_id)
    return pool_list, healthmonitor_list

def get_lb_members(lb_id):
    pool_list, a = get_lb_pools(lb_id)
    member_list = []
    for i in pool_list:
        member_info = session.query(Lbaas_members).filter_by(pool_id=i.get('id')).all()
        for member in member_info:
            member_dict = OrderedDict()
            member_dict['id'] = member.id
            member_dict['name'] = member.name
            member_dict['pool_id'] = member.pool_id
            member_dict['subnet_id'] = member.subnet_id
            member_dict['address'] = member.address
            member_dict['protocol_port'] = member.protocol_port
            member_dict['weight'] = member.weight
            member_dict['admin_state_up'] = member.admin_state_up
            member_dict['provisioning_status'] = member.provisioning_status
            member_dict['operating_status'] = member.operating_status
            member_dict['project_id'] = member.project_id
            member_list.append(member_dict)
    return member_list

def get_lb_healthmonitors(lb_id):
    a, healthmonitor_list = get_lb_pools(lb_id)
    hm_list = []
    for hm in healthmonitor_list:
        hm_info = session.query(Lbaas_healthmonitors).filter_by(id=hm).all()
        for hm in hm_info:
            hm_dict = OrderedDict()
            hm_dict['id'] = hm.id
            hm_dict['name'] = hm.name
            hm_dict['type'] = hm.type
            hm_dict['delay'] = hm.delay
            hm_dict['timeout'] = hm.timeout
            hm_dict['max_retries'] = hm.max_retries
            hm_dict['http_method'] = hm.http_method
            hm_dict['url_path'] = hm.url_path
            hm_dict['expected_codes'] = hm.expected_codes
            hm_dict['admin_state_up'] = hm.admin_state_up
            hm_dict['provisioning_status'] = hm.provisioning_status
            hm_dict['max_retries_down'] = hm.max_retries_down
            hm_dict['project_id'] = hm.project_id

            hm_list.append(hm_dict)
    return hm_list

def get_lb_l7policies(lb_id):
    listener_list = get_lb_listeners(lb_id)
    l7policies_list = []
    for l in listener_list:
        l7policy_info = session.query(Lbaas_l7policies).filter_by(listener_id=l['listener_id']).all()
        for l7policy in l7policy_info:
            l7policy_dict = OrderedDict()
            l7policy_dict['id'] = l7policy.id
            l7policy_dict['name'] = l7policy.name
            l7policy_dict['description'] = l7policy.description
            l7policy_dict['listener_id'] = l7policy.listener_id
            l7policy_dict['action'] = l7policy.action
            l7policy_dict['redirect_pool_id'] = l7policy.redirect_pool_id
            l7policy_dict['redirect_url'] = l7policy.redirect_url
            l7policy_dict['position'] = l7policy.position
            l7policy_dict['provisioning_status'] = l7policy.provisioning_status
            l7policy_dict['admin_state_up'] = l7policy.admin_state_up
            l7policy_dict['project_id'] = l7policy.project_id
            l7policies_list.append(l7policy_dict)
    return l7policies_list

def get_lb_l7rules(lb_id):
    l7policies_list = get_lb_l7policies(lb_id)
    l7rules_list = []
    for i in l7policies_list:
        l7rule_info = session.query(Lbaas_l7rules).filter_by(l7policy_id=i['id']).all()
        for l7rule in l7rule_info:
            l7rule_dict = OrderedDict()
            l7rule_dict['id'] = l7rule.id
            l7rule_dict['l7policy_id'] = l7rule.l7policy_id
            l7rule_dict['type'] = l7rule.type
            l7rule_dict['compare_type'] = l7rule.compare_type
            l7rule_dict['invert'] = l7rule.invert
            l7rule_dict['key'] = l7rule.key
            l7rule_dict['value'] = l7rule.value
            l7rule_dict['provisioning_status'] = l7rule.provisioning_status
            l7rule_dict['admin_state_up'] = l7rule.admin_state_up
            l7rule_dict['project_id'] = l7rule.project_id
            l7rules_list.append(l7rule_dict)
    return l7rules_list

def get_all_info(lb_id):
    lb_dict = get_lb_info(lb_id)
    listener_list = get_lb_listeners(lb_id)
    pool_list, b = get_lb_pools(lb_id)
    member_list = get_lb_members(lb_id)
    healthmonitor_list = get_lb_healthmonitors(lb_id)
    l7policy_list = get_lb_l7policies(lb_id)
    l7rule_list = get_lb_l7rules(lb_id)

    return lb_dict, listener_list, pool_list, member_list, healthmonitor_list, l7policy_list, l7rule_list

def get_lb_with_subnet(db_lb_dict, f5_node1, f5_node2):
    lb_list = session.query(F5_loadbalancers_az).filter_by(node1=f5_node1, node2=f5_node2).all()
    same_lb_list = []
    for l in lb_list:
        lb_id = l.neutron_id
        lb_info = session.query(Lbaas_Loadbalancers).filter_by(id=lb_id).first()
        if not lb_info:
            pass
        elif lb_id == db_lb_dict['lb_id']:
            pass
        else:
            subnet_id = lb_info.vip_subnet_id
            if subnet_id == db_lb_dict['vip_subnet_id']:
                same_lb_list.append(lb_info.id)
    if len(same_lb_list) >= 1:
        return False
    else:
        return True

def choose_new_vlan(old_node_dict, f5_node1, f5_node2):
    node_dict = get_f5_node_info(f5_node1, f5_node2)
    if old_node_dict['az'] == node_dict['az']:

        # 根据node_id 在 lbaas_f5_available_vlans_az 表中选个vlan
        vlan_info = session.query(Lbaas_F5_available_vlans_az).filter_by(vlanspool_id=node_dict['id']).first()
        # 从 lbaas_f5_available_vlans_az表 中删除所选vlan
        session.delete(vlan_info)
        session.flush()
        return vlan_info.vlan

def create_lb(lb_id, db_lb_dict, f5_node1, f5_node2):
    lb_dict = {
        'availability_zone_hints': None,
        'name': db_lb_dict['lb_name'],
        'provisioning_status': db_lb_dict['lb_provisioning_status'],
        'tenant_id': db_lb_dict['project_id'],
        'description': db_lb_dict['description'],
        'admin_state_up': db_lb_dict['admin_state_up'],
        'bandwidth': db_lb_dict['lb_bandwidth'],
        'flavor_id': None,
        'vip_subnet_id': db_lb_dict['vip_subnet_id'],
        'max_concurrency': db_lb_dict['max_concurrency'],
        'flavor': db_lb_dict['lb_flavor'],
        'project_id': db_lb_dict['project_id'],
        'id': lb_id,
        'operating_status': db_lb_dict['operating_status'],
        'new_connection': db_lb_dict['new_connection']
    }

    sdn_dict = {
        'loadbalancer_id': lb_id,
        'vlan': db_lb_dict['new_vlan'],
        'enable_session_flag': False,
        'user_id': db_lb_dict['project_id'],
        'f5_user': username,
        'f5_pwd': password,
        'gateway': [db_lb_dict['lb_subnet_gateway_ip']],
        'f5_vm': [f5_node1, f5_node2],
        'interface': inside_interface,
        'bandwidth': str(db_lb_dict['lb_bandwidth']),
        'self_ip': [{
                'ip': db_lb_dict['self_port1_ip'],
                'netmask': str(ipy.IP(db_lb_dict['lb_subnet_cidr']).netmask())
            },
                {'ip': db_lb_dict['self_port2_ip'],
                 'netmask': str(ipy.IP(db_lb_dict['lb_subnet_cidr']).netmask())
                 }],
        'vip_address': db_lb_dict['vip_address'],
        'snat_pool': [db_lb_dict['snat_port1_ip'],
                      db_lb_dict['snat_port2_ip']],
        'max_concurrency': 5000,
        'new_connection': 3000,
        'route_domains_id': db_lb_dict['new_vlan'],
        'float_mac': '',
        'stack_self_ip': [],
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
    }

    # 下发创建lb请求
    response_lb = f5_driver.loadbalancer.create_p({'loadbalancer': lb_dict}, sdn_dict)
    if response_lb['code'] != 200:
        print("create lb error!")
        print("delete new_self_port1:" + str(db_lb_dict['self_port1_id']))
        RestAPI().delete_port(db_lb_dict['self_port1_id'])
        print("delete new_self_port1:" + str(db_lb_dict['self_port2_id']))
        RestAPI().delete_port(db_lb_dict['self_port2_id'])
        raise F5Error(node1=f5_node1, node2=f5_node2, error=response_lb['message'])
    else:
        # 更新lbaas_loadbalancers 、 lbaas_f5_loadbalancers_az 表中lb 信息
        lb = session.query(Lbaas_Loadbalancers).filter_by(id=lb_id).first()
        lb.description = db_lb_dict['description']
        session.commit()
        lb_info = session.query(F5_loadbalancers_az).filter_by(neutron_id=lb_id).first()
        lb_info.node1 = f5_node1
        lb_info.node2 = f5_node2
        lb_info.self_port1 = db_lb_dict['self_port1_id']
        lb_info.self_port2 = db_lb_dict['self_port2_id']
        lb_info.vlan = db_lb_dict['new_vlan']
        lb_info.key = f5_node1 + db_lb_dict['new_az']
        session.commit()

        print("new_vlan: {} has update in database!".format(db_lb_dict['new_vlan']))
        print("new self_port1: {}, self_port2: {} has update in database!".format(db_lb_dict['self_port1_id'],
                                                                                  db_lb_dict['self_port2_id']))
        print("create lb: {}".format(response_lb))

def create_listener(lb_id, db_lb_dict, db_listener_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['new_vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['new_vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': 5000,
        'new_connection': 3000,
        'loadbalancer_id': lb_id,
        'certificate': {},
        'loadbalancer_state': db_lb_dict['admin_state_up'],
    }
    if len(db_listener_list) == 0:
        print("no listener needed to be created")
    else:
        for i in db_listener_list:
            listener_dict = {
                'protocol': i['listener_protocol'],
                'default_tls_container_ref': i['listener_default_tls_container_id'],
                'redirect_port': i['listener_redirect_port'],
                'redirect_protocol': i['listener_redirect_protocol'],
                'redirect_up': i['listener_redirect_up'],
                'cipher_suites': i['listener_cipher_suites'],
                'tls_protocols': i['listener_tls_protocols'],
                'keepalive_timeout': i['listener_keepalive_timeout'],
                'project_id': i['listener_project_id'],
                'description': i['listener_description'],
                'mutual_authentication_up': i['listener_mutual_authentication_up'],
                'protocol_port': i['listener_protocol_port'],
                'transparent': i['listener_transparent'],
                'default_pool_id': None,
                'name': i['listener_name'],
                'admin_state_up': i['listener_admin_state_up'],
                'tenant_id': i['listener_project_id'],
                'connection_limit': i['listener_connection_limit'],
                'http2': i['listener_http2'],
                'loadbalancer_id': i['listener_loadbalancer_id'],
                'ca_container_id': i['listener_ca_container_id'],
            }
            sdn_dict['listener_id'] = i['listener_id']
            response_listener = f5_driver.listener.create({'listener': listener_dict}, sdn_dict)
            if response_listener['code'] != 200:
                raise F5Error(node1=f5_node1, node2=f5_node2, error=response_listener['message'])
            else:
                print("create listener: {}".format(response_listener))

def create_pool(db_lb_dict, db_listener_list, db_pool_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['new_vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['new_vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': 5000,
        'new_connection': 3000
    }
    if len(db_pool_list) == 0:
        print('no pool needed to be created')
    else:
        for i in db_pool_list:
            pool_dict = {
                'lb_algorithm': i['lb_algorithm'],
                'listener_id': '',
                'protocol': i['protocol'],
                'name': i['name'],
                'admin_state_up': i['admin_state_up'],
                'tenant_id': i['project_id'],
                'provisioning_status': i['provisioning_status'],
                'listeners': [],
                'id': i['id'],
                'project_id': i['project_id'],
                'loadbalancer_id': i['loadbalancer_id'],
                'operating_status': i['operating_status'],
                'description': i['description']
            }
            sdn_dict['pool_id'] = i['id']
            sdn_dict['session_persistence'] = {}
            for j in db_listener_list:
                if i['protocol'] == j['listener_protocol']:
                    try:
                        pool_dict['listener_id'] = j['listener_id']
                        request_pool = f5_driver.pool.create({'pool': pool_dict}, sdn_dict)
                        print("create pool: {}".format(request_pool))
                    except Exception as e:
                        raise e

def create_member(db_lb_dict, db_member_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['new_vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['new_vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': 5000,
        'new_connection': 3000
    }
    if len(db_member_list) == 0:
        print('no member needed to be created')
    else:
        for i in db_member_list:
            member_dict = {
                'pool_id': i.get('pool_id'),
                'admin_state_up': i.get('admin_state_up'),
                'address': i.get('address'),
                'protocol_port': i.get('protocol_port'),
                'weight': i.get('weight'),
                'tenant_id': i.get('project_id')
            }
            sdn_dict['pool_id'] = i.get('pool_id')
            response_member = f5_driver.member.create({'member': member_dict}, sdn_dict)
            if response_member['code'] != 200:
                raise F5Error(node1=f5_node1, node2=f5_node2, error=response_member['message'])
            else:
                print("create member: {}".format(response_member))

def create_healthmonitor(lb_id, db_lb_dict, db_pool_list, db_healthmonitor_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['new_vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['new_vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': 5000,
        'new_connection': 3000
    }
    if len(db_healthmonitor_list) == 0:
        print('no healthmonitor needed to be created')
    else:
        for i in db_healthmonitor_list:
            for k in db_pool_list:
                healthmonitor_dict = {
                    'admin_state_up': i['admin_state_up'],
                    'delay': i['delay'],
                    'max_retries': i['max_retries'],
                    'timeout': i['timeout'],
                    'type': i['type'],
                    'expected_codes': i['expected_codes'],
                    'http_method': i['http_method'],
                    'url_path': i['url_path'],
                    'tenant_id': i['project_id'],
                }
                sdn_dict['monitor_id'] = i['id']
                if k['loadbalancer_id'] == lb_id and i['id'] == k['healthmonitor_id']:
                    request_healthmonitor = f5_driver.monitor.create({'healthmonitor': healthmonitor_dict}, sdn_dict)
                    if request_healthmonitor['code'] != 200:
                        raise F5Error(node1=f5_node1, node2=f5_node2, error=request_healthmonitor['message'])
                    else:
                        print("create healthmonitor: {}".format(request_healthmonitor))

def create_l7policy(db_lb_dict, db_l7policy_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan':db_lb_dict['new_vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['new_vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': 5000,
        'new_connection': 3000,
        'l7policy_list': []
    }
    if len(db_l7policy_list) == 0:
        print('no l7policy needed to be created')
    else:
        for i in db_l7policy_list:
            l7policy_dict = {
                'redirect_pool_id': i['redirect_pool_id'],
                'name': i['name'],
                'admin_state_up': i['admin_state_up'],
                'tenant_id': i['project_id'],
                'listener_id': i['listener_id'],
                'redirect_url': i['redirect_url'],
                'action': i['action'],
                'position': i['position'],
                'provisioning_status': i['provisioning_status'],
                'project_id': i['project_id'],
                'id': i['id'],
                'description': i['description']
            }
            sdn_dict['l7policy_id'] = i['id']
            request_l7policy = f5_driver.policy.create({'l7policy': l7policy_dict}, sdn_dict)
            if request_l7policy['code'] != 200:
                raise F5Error(node1=f5_node1, node2=f5_node2, error=request_l7policy['message'])
            else:
                print("create l7policy: {}".format(request_l7policy))

def create_l7rule(db_lb_dict, db_l7policy_list, db_l7rule_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['new_vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['new_vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': 5000,
        'new_connection': 3000
    }
    if len(db_l7rule_list) == 0:
        print('no rule needed to be created')
    else:
        for j in db_l7policy_list:
            l7policy_dict = {
                'redirect_pool_id': j['redirect_pool_id'],
                'name': j['name'],
                'admin_state_up': j['admin_state_up'],
                'tenant_id': j['project_id'],
                'listener_id': j['listener_id'],
                'redirect_url': j['redirect_url'],
                'action': j['action'],
                'position': j['position'],
                'id': j['id'],
                'description': j['description'],
                'listeners': [{'id': j['listener_id']}],
                'rules': [],
            }
            for i in db_l7rule_list:
                l7rule_dict = {
                    'compare_type': i['compare_type'],
                    'admin_state_up': i['admin_state_up'],
                    'tenant_id': i['project_id'],
                    'invert': i['invert'],
                    'provisioning_status': i['provisioning_status'],
                    'value': i['value'],
                    'key': i['key'],
                    'l7policy_id': i['l7policy_id'],
                    'project_id': i['project_id'],
                    'type': i['type'],
                    'id': i['id'],
                }
                if j['id'] == l7rule_dict['l7policy_id']:
                    l7policy_dict['rules'].append({'id': l7rule_dict['id']})
                    sdn_dict['l7policy_id'] = i['l7policy_id']
                    sdn_dict['rule_id'] = i['id']
                    sdn_dict['l7policy'] = l7policy_dict
                    request_l7rule = f5_driver.rule.create({'rule': l7rule_dict}, sdn_dict)
                    if request_l7rule['code'] != 200:
                        raise F5Error(node1=f5_node1, node2=f5_node2, error=request_l7rule['message'])
                    else:
                        print("create l7rule: {}".format(request_l7rule))

def delete_l7rule(db_lb_dict, db_l7policy_list, db_l7rule_list):
    sdn_dict = {
        'f5_vm': [db_lb_dict['node1'], db_lb_dict['node2']],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': db_lb_dict['max_concurrency'],
        'new_connection': db_lb_dict['new_connection']
    }

    if len(db_l7rule_list) == 0:
        print("No rule needs to be deleted")
    else:
        for j in db_l7policy_list:
            sdn_dict['l7policy_id'] = j.get('id')
            for i in db_l7rule_list:
                request_l7rule = f5_driver.rule.delete({'id': i.get('id')}, sdn_dict)
                print("delete l7rule: {}".format(request_l7rule))

def delete_l7policy(db_lb_dict, db_l7policy_list):
    sdn_dict = {
        'f5_vm': [db_lb_dict['node1'], db_lb_dict['node2']],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': db_lb_dict['max_concurrency'],
        'new_connection': db_lb_dict['new_connection'],
        'l7policy_list': []
    }

    if len(db_l7policy_list) == 0:
        print("No l7policy needs to be deleted")
    else:
        for i in db_l7policy_list:
            sdn_dict['listener_id'] = i.get('listener_id')
            sdn_dict['l7policy_list'].append({'l7policy_id': i['id'],
                                              'position': i['position'],
                                              'admin_state_up': i['admin_state_up']})
            request_l7policy = f5_driver.policy.delete({'id': i.get('id')}, sdn_dict)
            print("delete l7policy: {}".format(request_l7policy))

def delete_healthmonitor(db_lb_dict, db_healthmonitor_list, db_pool_list):
    sdn_dict = {
        'f5_vm': [db_lb_dict['node1'], db_lb_dict['node2']],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': db_lb_dict['max_concurrency'],
        'new_connection': db_lb_dict['new_connection']
    }

    if len(db_healthmonitor_list) == 0:
        print("No healthmonitor needs to be deleted")
    else:
        for i in db_healthmonitor_list:
            for j in db_pool_list:
                if j['loadbalancer_id'] == db_lb_dict['lb_id'] and i.get('id') == j.get('healthmonitor_id'):
                    sdn_dict['pool_id'] = j.get('id')
                    sdn_dict['type'] = i.get('type')
                    request_healthmonitor = f5_driver.monitor.delete({'id': i.get('id')}, sdn_dict)
                    print("delete healthmonitor: {}".format(request_healthmonitor))

def delete_member(db_lb_dict):
    sdn_dict = {
        'f5_vm': [db_lb_dict['node1'], db_lb_dict['node2']],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': db_lb_dict['max_concurrency'],
        'new_connection': db_lb_dict['new_connection']
    }

    if len(db_member_list) == 0:
        print("No member needs to be deleted")
    else:
        for i in db_member_list:
            sdn_dict['pool_id'] = i.get('pool_id')
            sdn_dict['address'] = i.get('address')
            sdn_dict['protocol_port'] = i.get('protocol_port')
            request_member = f5_driver.member.delete({'id': i.get('member_id')}, sdn_dict)
            print("delete member: {}".format(request_member))

def delete_pool(db_lb_dict, db_listener_list, db_pool_list):
    sdn_dict = {
        'f5_vm': [db_lb_dict['node1'], db_lb_dict['node2']],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': db_lb_dict['max_concurrency'],
        'new_connection': db_lb_dict['new_connection']
    }

    if len(db_pool_list) == 0:
        print("No pool needs to be deleted")
    else:
        for j in db_listener_list:
            sdn_dict['listener_id'] = j['listener_id']
            for i in db_pool_list:
                if j.get('listener_protocol') == i.get('protocol'):
                    request_pool = f5_driver.pool.delete({'id': i.get('id')}, sdn_dict)
                    print("delete pool: {}".format(request_pool))

def delete_listener(db_lb_dict, db_listener_list):
    sdn_dict = {
        'f5_vm': [db_lb_dict['node1'], db_lb_dict['node2']],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
        'vip_address': db_lb_dict['vip_address'],
        'max_concurrency': db_lb_dict['max_concurrency'],
        'new_connection': db_lb_dict['new_connection'],
        'loadbalancer_id': db_lb_dict['lb_id']
    }

    if len(db_listener_list) == 0:
        print("No listener needs to be deleted")
    else:
        for i in db_listener_list:
            sdn_dict['protocol'] = i['listener_protocol']
            request_listener = f5_driver.listener.delete({'id': i['listener_id']}, sdn_dict)
            print("delete listener: {}".format(request_listener))

def delete_lb(db_lb_dict):
    sdn_dict = {
        'f5_vm': [db_lb_dict['node1'], db_lb_dict['node2']],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
        'vip_address': None,
        'max_concurrency': db_lb_dict['max_concurrency'],
        'new_connection': db_lb_dict['new_connection'],
        'loadbalancer_id': db_lb_dict['lb_id'],
        'interface': inside_interface
    }

    request_lb = f5_driver.loadbalancer.delete({'id': db_lb_dict['lb_id']}, sdn_dict)
    print("delete lb: {}".format(request_lb))

def random_mac():
        mac = [0x52, 0x54, 0x00,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

def get_stack_subnet_list(subnet_id):
        subnet = session.query(models_v2.Subnet).filter_by(
            id=subnet_id
        ).first()
        subnets = session.query(models_v2.Subnet).filter_by(
            network_id=subnet['network_id']
        ).all()
        subnet_list = []
        subnet_list.append(subnet_id)
        for i in subnets:
            if i['ip_version'] != subnet['ip_version']:
                subnet_list.append(i['id'])
                return subnet_list
        return subnet_list

def create_port_db(session, port):
        p = port['port']
        port_id = p.get('id') or uuidutils.generate_uuid()
        mac_address = utils.get_random_mac(cfg.CONF.base_mac.split(':'))
        with session.begin(subtransactions=True):
            port_db = models_v2.Port(
                id=port_id,
                tenant_id=p['tenant_id'],
                project_id=p['project_id'],
                name=p['name'],
                network_id=p['network_id'],
                mac_address=mac_address,
                admin_state_up=False,
                status="DOWN",
                device_owner=p['device_owner'],
                device_id=p['device_id'])
            session.add(port_db)
            return port_db

def create_new_dummyfip(vip_port_id, az, tenant_id):
        dummyfip = session.query(NewarchDummyFip).filter_by(fixed_port_id=vip_port_id).first()
        if dummyfip:
            create_hardware_dummyfip(session,
                                     dummyfip.floating_ip_address,
                                     dummyfip.fixed_port_id,
                                     az,
                                     tenant_id)

def generate_dummy_port(session,name_prefix, dummy_id, device_owner,
                            az_name, tenant_id=None):
        dummy_port = None
        dummy_net = None
        try:
            network_name = name_prefix + 'network_' + str(dummy_id)
            net_dict = NetCreateDict(tenant_id,
                                     network_name, az_name)
            dummy_net = create_network_db(session, net_dict.net_dict)
            port_name = name_prefix + 'port_' + str(dummy_id)
            port_dict = PortCreateDict(tenant_id, port_name, dummy_net['id'],
                                       '', device_owner)
            dummy_port = create_port_db(session, port_dict.port_dict)
        except Exception as e:
            try:
                if dummy_port:
                    session.delete(dummy_port)
                if dummy_net:
                    session.delete(dummy_net)
            except Exception as ec:
                pass
            raise e
        return dummy_port

def get_net_mask(session, ip):
        cidr_db = session.query(models_v2.Subnet.cidr).join(
            models_v2.IPAllocation,
            models_v2.Subnet.id == models_v2.IPAllocation.subnet_id).filter(
            models_v2.IPAllocation.ip_address == ip).first()
        if cidr_db and cidr_db[0]:
            cidr = cidr_db[0]
            if '/' in cidr:
                net_mask = '/' + str(cidr.split('/')[1])
                return net_mask

def make_dummyfip_dict(floatingip):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['fixed_port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address'],
               'status': floatingip['status'],
               'dummy_fip_address': floatingip['floating_ip_address'],
               'dummy_network_id': floatingip['floating_network_id'],
               }
        return res

def create_dummyfloatingip(session, tenant_id, dummyfloatingip):
        external_port = None
        floatingip_db = None
        try:
            fip = dummyfloatingip['dummyfloatingip']
            fip_id = uuidutils.generate_uuid()

            f_net_id = fip['floating_network_id']

            # This external port is never exposed to the tenant.
            # it is used purely for internal system and admin use when
            # managing floating IPs.

            port = {'tenant_id': tenant_id,  # tenant intentionally not set
                    'network_id': f_net_id,
                    'admin_state_up': True,
                    'device_id': 'PENDING',
                    'device_owner': lib_constants.DEVICE_OWNER_DUMMYFLOATINGIP,
                    'name': ''}
            if fip.get('floating_ip_address'):
                port['fixed_ips'] = [{'ip_address': fip['floating_ip_address']}]

            if fip.get('subnet_id'):
                port['fixed_ips'] = [
                    {'subnet_id': fip['subnet_id']}]

            external_port = RestAPI().create_port(port)
            print('============ create new dummy port: {}============'.format(external_port['id']))

            external_ipv4_ips = [ip for ip in external_port['fixed_ips'] if netaddr.IPAddress(ip['ip_address']).version == 4]

            floating_fixed_ip = external_ipv4_ips[0]
            floating_ip_address = floating_fixed_ip['ip_address']
            floatingip_db = newarch_model.NuageDummyFip(id=fip_id,
                                                        tenant_id=fip['tenant_id'],
                                                        status=lib_constants.FLOATINGIP_STATUS_ACTIVE,
                                                        floating_network_id=fip['floating_network_id'],
                                                        floating_ip_address=floating_ip_address,
                                                        floating_port_id=external_port['id'],
                                                        description=fip.get('description'))

            session.add(floatingip_db)
            session.commit()
            floatingip_dict = make_dummyfip_dict(floatingip_db)
            return floatingip_dict
        except Exception as e:
            if external_port:
                try:
                    RestAPI().delete_port(external_port['id'])
                    session.commit()
                except Exception:
                    pass
            if floatingip_db:
                session.query(newarch_model.NuageDummyFip).filter(newarch_model.NuageDummyFip.id==fip_id).delete()
                session.commit()
            raise e

def resolve_dummy_config(file_path, dummy_configs):
        file = open(file_path, "rd")
        config_dict = json.load(file)
        if config_dict:
            if dummy_configs is None or dummy_configs == {}:
                dummy_configs.update(config_dict)
                return dummy_configs
            else:
                group_names = config_dict.keys()
                for group_name in group_names:
                    if group_name not in dummy_configs.keys():
                        dummy_configs[group_name] = config_dict[group_name]
                    else:
                        dummy_configs[group_name].update(config_dict[group_name])
                return dummy_configs
        return dummy_configs

def get_group_name_by_fip(session, fip):
        result = session.query(db_model.NewarchSubnetFortiGroup) \
            .join(models_v2.IPAllocation,
                  models_v2.IPAllocation.subnet_id == db_model.NewarchSubnetFortiGroup.subnet_info) \
            .join(l3_model.FloatingIP,
                  l3_model.FloatingIP.floating_network_id == models_v2.IPAllocation.network_id) \
            .filter(l3_model.FloatingIP.floating_ip_address == fip,
                    models_v2.IPAllocation.ip_address == fip,
                    db_model.NewarchSubnetFortiGroup.ip_version == 4).first()
        if result and 'group_vdom' in result:
            return result['group_vdom'].split('-')[0]

def check_network_has_free_ip(session, network_id):
        subnets = session.query(models_v2.Subnet).filter(
            models_v2.Subnet.network_id == network_id).all()
        if subnets:
            for subnet in subnets:
                if check_ip(session, subnet):
                    return True

def check_ip(session, subnet):
        result = session.query(models_v2.IPAllocationPool) \
            .filter_by(subnet_id=subnet.id).first()
        first_ip = result['first_ip']
        last_ip = result['last_ip']
        startip = ipaddress.ip_address(first_ip.decode('utf-8'))
        lastip = ipaddress.ip_address(last_ip.decode('utf-8'))
        num = 0
        while startip <= lastip:
            num += 1
            startip += 1
        used_num = session.query(models_v2.IPAllocation) \
            .filter_by(subnet_id=subnet.id).count()
        if used_num is None:
            used_num = 0
        if used_num >= num:
            return
        else:
            return num - used_num

def get_dummy_net(session, vip_port_id, az):
        group_dummy_az_nets = {}
        default_dummy_config = cfg.CONF.RESTPROXY.dummy_gw_id
        dummy_list_config = cfg.CONF.EXTENSIONRESTPROXY.dummy_gw_list
        if default_dummy_config:
            group_dummy_az_nets = resolve_dummy_config(default_dummy_config,
                                                            group_dummy_az_nets)
        if dummy_list_config:
            group_dummy_az_nets = resolve_dummy_config(dummy_list_config,
                                                            group_dummy_az_nets)
        fip_db = session.query(l3_model.FloatingIP).filter(
            l3_model.FloatingIP.fixed_port_id == vip_port_id).first()

        group_name = get_group_name_by_fip(session, fip_db.floating_ip_address)
        az_exter_net_ids = group_dummy_az_nets[group_name].get(az, {}).get('LB')
        start_index = random.randint(0, len(az_exter_net_ids) - 1)
        if az_exter_net_ids[start_index:]:
            for network_id in az_exter_net_ids[start_index:]:
                if check_network_has_free_ip(session, network_id):
                    return network_id
        if az_exter_net_ids[start_index - 1::-1]:
            for network_id in az_exter_net_ids[start_index - 1::-1]:
                if check_network_has_free_ip(session, network_id):
                    return network_id

def create_dummyfip_associate_dfip(session, port_id, tenant_id,
                                       vip_port_id, az):
        dummyfip_network_id = get_dummy_net(session, vip_port_id, az)
        dummyfip_data = {
            "dummyfloatingip": {
                "subnet_id": "",
                "tenant_id": tenant_id,
                "floating_network_id": dummyfip_network_id,
                "fixed_ip_address": "",
                "floating_ip_address": "",
                "project_id": tenant_id,
                "port_id": ""
            }
        }
        dummyfip = create_dummyfloatingip(session, tenant_id, dummyfip_data)
        dfip_qry = session.query(
            newarch_model.NuageDummyFip).filter_by(id=dummyfip['id']).one()
        dfip_qry.fixed_port_id = port_id
        session.commit()
        return dfip_qry

def add_lb_dummy_port(session, port_id, dummy_port_id1, dummy_fip1,
                          dummy_port_id2, dummy_fip2):
        lb_dummy_port_db = db_model.LbaasDummyPorts(port_id=port_id,
                                                    dummy_port_id1=dummy_port_id1,
                                                    dummy_fip1=dummy_fip1,
                                                    dummy_port_id2=dummy_port_id2,
                                                    dummy_fip2=dummy_fip2)
        session.add(lb_dummy_port_db)
        session.commit()

def create_hardware_dummyfip(session, dummy_fip_address, port_id,
                                 az, tenant_id):
        lb_dummy_port1 = generate_dummy_port(session, 'lb1_',
                                                  port_id,
                                                  lib_constants.DEVICE_OWNER_LOADBALANCERV2,
                                                  az,
                                                  tenant_id)
        lb_dummy_port2 = generate_dummy_port(session, 'lb2_',
                                                  port_id,
                                                  lib_constants.DEVICE_OWNER_LOADBALANCERV2,
                                                  az,
                                                  tenant_id)

        net_mask = get_net_mask(session, dummy_fip_address)
        try:
            if lb_dummy_port1:
                dummy_fip_db1 = create_dummyfip_associate_dfip(session, lb_dummy_port1['id'], tenant_id, port_id, az)
                lb_dummy_fip1 = str(dummy_fip_db1['floating_ip_address']) + net_mask

            if lb_dummy_port2:
                dummy_fip_db2 = create_dummyfip_associate_dfip(session, lb_dummy_port2['id'], tenant_id, port_id, az)
                lb_dummy_fip2 = str(dummy_fip_db2['floating_ip_address']) + net_mask
            add_lb_dummy_port(session, port_id, lb_dummy_port1['id'],
                                   lb_dummy_fip1, lb_dummy_port2['id'],
                                   lb_dummy_fip2)
        except Exception as e:
            print('create dummyport error:{}'.format(e.args))
            delete_port_db(session, 'lb1_', str(port_id))
            delete_port_db(session, 'lb2_', str(port_id))
            delete_network_db(session, 'lb1_', str(port_id))
            delete_network_db(session, 'lb2_', str(port_id))
            raise e

def delete_port_db(session, name_prefix, vip_port_id):
        port_name = name_prefix + 'port_' + vip_port_id
        port_qry = session.query(models_v2.Port)
        port_qry.filter_by(name=port_name).delete()
        session.commit()

def delete_network_db(session, name_prefix, vip_port_id):
        network_name = name_prefix + 'network_' + vip_port_id
        session.query(models_v2.Network).filter_by(name=network_name).delete()
        session.commit()

def create_network_db(session, net):
        n = net['network']
        args = {'tenant_id': n['tenant_id'],
                'id': n.get('id') or uuidutils.generate_uuid(),
                'name': n['name'],
                'mtu': n.get('mtu'),
                'vlan_transparent': n.get('vlan_transparent', None),
                'admin_state_up': n['admin_state_up'],
                'status': n.get('status', NET_STATUS_ACTIVE),
                'description': n.get('description'),
                'availability_zone_hints': n.get('availability_zone_hints')
                }
        network = models_v2.Network(**args)
        session.add(network)
        session.commit()
        return network

def fip_associate_lb_vip(lb_db, az, f5_node1, f5_node2):
        # create_new_dummyfip(lb_db['lb_vip_port_id'], az, lb_db['project_id'])
        dummy_fip_db = session.query(NewarchDummyFip).filter_by(fixed_port_id=lb_db['lb_vip_port_id']).first()
        if dummy_fip_db:
            print('============start fip associate lb vip============')
            max_concurrency = int(MigrateLb().flavor_dict[lb_db['lb_flavor']]['session'])
            new_connection = int(MigrateLb().flavor_dict[lb_db['lb_flavor']]['newsession'])
            sdn_dict = {
                'f5_vm': [f5_node1, f5_node2],
                'f5_user': username,
                'f5_pwd': password,
                'vip_subnet_id': [lb_db['vip_subnet_id']],
                'vlan': lb_db['new_vlan'],
                'user_id': lb_db['project_id'],
                'route_domains_id': lb_db['new_vlan'],
                'vip_address': lb_db['vip_address'],
                'max_concurrency': max_concurrency,
                'new_connection': new_connection
            }
            copy_sdn_dict = deepcopy(sdn_dict)
            copy_sdn_dict['wan_vlan'] = cfg.CONF.RESTPROXY.gw_vlan_tag_lb
            copy_sdn_dict['float_ip'] = dummy_fip_db.floating_ip_address

            copy_sdn_dict['interface'] = outside_interface
            copy_sdn_dict['vip_subnet_id'] = get_stack_subnet_list(lb_db['vip_subnet_id'])
            ipallocation = session.query(Ipallocations).filter_by(port_id=dummy_fip_db.floating_port_id).first()
            subnet = session.query(Subnets).filter_by(id=ipallocation.subnet_id).first()
            copy_sdn_dict['float_mac'] = random_mac()
            copy_sdn_dict['self_ip'] = [
                {
                    'ip': dummy_fip_db.floating_ip_address,
                    'netmask': str(ipy.IP(subnet.cidr).netmask())
                },
                {
                    'ip': dummy_fip_db.floating_ip_address,
                    'netmask': str(ipy.IP(subnet.cidr).netmask())
                 }
            ]
            response = f5_driver.floating.bind({'floating_id': dummy_fip_db.floating_port_id}, copy_sdn_dict)
            if response['code'] != 200:
                node1 = sdn_dict['f5_vm'][0]
                node2 = sdn_dict['f5_vm'][1]
                raise F5Error(node1=node1, node2=node2, error=response['message'])
            print('============end fip associate lb vip============')

def fip_disassociate_lb_vip(lb_db):
        dummy_fip_db = session.query(NewarchDummyFip).filter_by(fixed_port_id=lb_db['lb_vip_port_id']).first()
        if dummy_fip_db:
            print('============start fip disassociate lb vip============')
            max_concurrency = int(MigrateLb().flavor_dict[lb_db['lb_flavor']]['session'])
            new_connection = int(MigrateLb().flavor_dict[lb_db['lb_flavor']]['newsession'])
            sdn_dict = {
                'f5_vm': [lb_db['node1'], lb_db['node2']],
                'f5_user': username,
                'f5_pwd': password,
                'vip_subnet_id': [lb_db['vip_subnet_id']],
                'vlan': lb_db['vlan'],
                'user_id': lb_db['project_id'],
                'route_domains_id': lb_db['vlan'],
                'vip_address': lb_db['vip_address'],
                'max_concurrency': max_concurrency,
                'new_connection': new_connection
            }
            copy_sdn_dict = deepcopy(sdn_dict)
            copy_sdn_dict['wan_vlan'] = cfg.CONF.RESTPROXY.gw_vlan_tag_lb
            copy_sdn_dict['float_ip'] = dummy_fip_db.floating_ip_address
            copy_sdn_dict['interface'] = outside_interface

            response = f5_driver.floating.unbind({'floating_id': dummy_fip_db.floating_port_id}, copy_sdn_dict)
            if response['code'] != 200:
                node1 = sdn_dict['f5_vm'][0]
                node2 = sdn_dict['f5_vm'][1]
                raise F5Error(node1=node1, node2=node2, error=response['message'])
            print('============end fip disassociate lb vip============')

class MigrateLb(object):

    def __init__(self):
        cfg.CONF(default_config_files=['/etc/neutron/neutron.conf',
                                       '/etc/neutron/neutron_lbaas.conf',
                                       '/etc/neutron/plugin.ini',
                                       '/etc/neutron/f5_nfv.ini'])
        config.readfp(open(f5_nfv_file))
        self.username = config.get('F5', 'username')
        self.password = cfg.CONF.F5.password
        self.inside_interface = config.get('F5', 'inside_interface')
        self.outside_interface = config.get('F5', 'outside_interface')
        if config.has_option('F5', 'inside_interface_h'):
            self.inside_interface_h = config.get('F5', 'inside_interface_h')
        else:
            self.inside_interface_h = default_inside_interface_h
        if config.has_option('F5', 'outside_interface_h'):
            self.outside_interface_h = config.get('F5', 'outside_interface_h')
        else:
            self.outside_interface_h = default_outside_interface_h
        self.context = self.create_context()
        self._set_flavor_list()
        self._default_az_name = 'default'
        self._default_nuage = None
        self._nuageclient_dict = {}
        self.az_list = []
        self.vsd_ip = None
        self.vsd_ip_dict = {}
        self.cms_id = None
        self.cms_id_dict = {}
        self.init_nuageclient()
        self.neutron_rest = RestAPI()
        self.vtep_type = {}
        self._get_vtep_type_from_config_az_h(f5h_conf_file)
        self.nuageL3Plugin = None

    def _get_vtep_type_from_config_az_h(self, conf_file):
        with open(conf_file, 'rb') as f:
            _res = f.read()
        res = jsonutils.loads(_res)
        if res:
            for az in res['f5']:
                self.vtep_type[az['az']] = az['vtep_type']

    def create_context(self):
        engine = create_engine(cfg.CONF.database.connection)
        db_session = sessionmaker(bind=engine)
        session = db_session()
        return MyContext(session)

    def init_nuageclient(self):
        default_server = cfg.CONF.RESTPROXY.server
        self.vsd_ip = default_server
        self.cms_id = cfg.CONF.RESTPROXY.cms_id
        self._default_nuage = restproxy.RESTProxyServer(
            cfg.CONF.RESTPROXY.server,
            cfg.CONF.RESTPROXY.base_uri,
            cfg.CONF.RESTPROXY.serverssl,
            cfg.CONF.RESTPROXY.verify_cert,
            cfg.CONF.RESTPROXY.serverauth,
            cfg.CONF.RESTPROXY.auth_resource,
            cfg.CONF.RESTPROXY.organization,
            servertimeout=cfg.CONF.RESTPROXY.server_timeout,
            max_retries=cfg.CONF.RESTPROXY.server_max_retries)

        az_list = cfg.CONF.EXTENSIONRESTPROXY.availibility_zone_list
        vsd_ip_list = cfg.CONF.EXTENSIONRESTPROXY.server_list
        if az_list and vsd_ip_list:
            for index, value in enumerate(az_list):
                self.vsd_ip_dict[value] = vsd_ip_list[index]

        self.az_list = az_list
        cms_id_list = cfg.CONF.EXTENSIONRESTPROXY.cms_id_list
        if az_list and cms_id_list:
            for index, value in enumerate(az_list):
                self.cms_id_dict[value] = cms_id_list[index]

        for i in range(len(az_list)):
            cur_server = self._get_vsd_attr_from_cfg(cfg.CONF.EXTENSIONRESTPROXY.server_list, i, default_server)
            if cur_server == default_server:
                self._default_az_name = az_list[i]
                self._nuageclient_dict[az_list[i]] = self._default_nuage
            else:
                self._nuageclient_dict[az_list[i]] = restproxy.RESTProxyServer(
                    cur_server,
                    self._get_vsd_attr_from_cfg(cfg.CONF.EXTENSIONRESTPROXY.base_uri_list, i,
                                                cfg.CONF.RESTPROXY.base_uri),
                    cfg.CONF.RESTPROXY.serverssl,
                    self._get_vsd_attr_from_cfg(cfg.CONF.EXTENSIONRESTPROXY.verify_cert_list, i,
                                                cfg.CONF.RESTPROXY.verify_cert),
                    self._get_vsd_attr_from_cfg(cfg.CONF.EXTENSIONRESTPROXY.serverauth_list, i,
                                                cfg.CONF.RESTPROXY.serverauth),
                    self._get_vsd_attr_from_cfg(cfg.CONF.EXTENSIONRESTPROXY.auth_resource_list, i,
                                                cfg.CONF.RESTPROXY.auth_resource),
                    self._get_vsd_attr_from_cfg(cfg.CONF.EXTENSIONRESTPROXY.organization_list, i,
                                                cfg.CONF.RESTPROXY.organization),
                    servertimeout=cfg.CONF.RESTPROXY.server_timeout,
                    max_retries=cfg.CONF.RESTPROXY.server_max_retries)

    def _get_vsd_attr_from_cfg(self, vsd_attr_list, i, default):
        return vsd_attr_list[i] if i < len(vsd_attr_list) else default

    def get_nuagelient(self, az):
        return self._nuageclient_dict[az] if az in self._nuageclient_dict.keys() else self._default_nuage

    def _set_flavor_list(self):
        self.flavor_dict = {
            1: {'session': 5000, 'newsession': 3000},
            2: {'session': 50000, 'newsession': 5000},
            3: {'session': 100000, 'newsession': 10000},
            4: {'session': 200000, 'newsession': 20000},
            5: {'session': 500000, 'newsession': 50000},
            6: {'session': 1000000, 'newsession': 100000}
        }

    def get_vsd_config(self, lb_db, vlan, az):
        nuage_subnet = nuagedb.get_subnet_l2dom_by_id(self.context.session, lb_db['vip_subnet_id'])
        host_vports = self._get_subnet_host_vports(az, nuage_subnet['nuage_subnet_id'], vlan)
        hosts_info = []
        for host_vport in host_vports:
            host_interface = self.get_host_interface(host_vport, az)
            hosts_info.append({'host_vport': host_vport,
                               'host_interface': host_interface})
        return hosts_info

    def _get_subnet_host_vports(self, az, nuage_subnet_id, vlan):
        host_vports = []
        try:
            restproxy = self.get_nuagelient(az)
            restproxy.generate_nuage_auth()
            nuage_subnet = nuageextendlib.NuageExtendSubnet()
            response = restproxy.rest_call('GET', nuage_subnet.get_all_vports(id=nuage_subnet_id),
                                           nuage_subnet.extra_headers_vport_get_for_host())
        except Exception as e:
            LOG.info(str(e.message))
            return host_vports
        if not nuage_subnet.validate(response):
            return host_vports
        for vport in response[3]:
            if vport['type'] == 'HOST' and int(vport['VLAN']) == int(vlan):
                host_vports.append(deepcopy(vport))
        return host_vports

    def get_host_interface(self, host_vport, az):
        try:
            restproxy = self.get_nuagelient(az)
            nuage_vport = nuageextendlib.NuageExtendVPort()
            response = restproxy.rest_call(
                'GET', nuage_vport.post_host_interface(id=host_vport['ID']), '')
        except Exception as e:
            LOG.info (str(e.message))
            return None
        if not nuage_vport.validate(response):
            return None
        if len(response[3]) < 1:
            return None
        return response[3][0]

    def get_vips_on_vport(self, vport_id, az):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        req_params = {
            'vport_id': vport_id
        }
        nuage_vip = nuagelib.NuageVIP(create_params=req_params)
        response = restproxy.rest_call('GET',
                                       nuage_vip.get_resource_for_vport(),
                                       '')
        if not nuage_vip.validate(response):
            raise nuage_vip.get_rest_proxy_error()
        vips = nuage_vip.get_response_objlist(response)
        resp = []
        if vips:
            for vip in vips:
                ret = {
                    'vip': nuagelib.NuageVIP.get_ip_addr(vip),
                    'mac': nuagelib.NuageVIP.get_mac_addr(vip),
                    'vip_id': nuagelib.NuageVIP.get_vip_id(vip)
                }
                resp.append(ret)
        return resp

    def delete_host_vport_vip(self, vport_id, vips, az):
        nuage_vips = self.get_vips_on_vport(vport_id, az)
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        for nuage_vip in nuage_vips:
            if nuage_vip['vip'] in vips:
                req_params = {
                    'vip_id': nuage_vip['vip_id']
                }
                nuage_vip = nuagelib.NuageVIP(create_params=req_params)
                response = restproxy.rest_call(
                    'DELETE',
                    nuage_vip.delete_resource(), '')
                if not nuage_vip.validate(response):
                    raise nuage_vip.get_rest_proxy_error()

    def delete_host_vport_and_interface(self, host_vport, host_interface, az):
        try:
            restproxy = self.get_nuagelient(az)
            restproxy.generate_nuage_auth()
            nuage_vport = nuageextendlib.NuageExtendVPort()
            restproxy.rest_call('DELETE', nuage_vport.del_host_interface(id=host_interface['ID']), '')
            req_params = {
                'vport_id': host_vport['ID']
            }
            nuage_vport = nuageextendlib.NuageExtendVPort(create_params=req_params)
            restproxy.rest_call('DELETE', nuage_vport.delete_resource(), '')
        except Exception as e:
            raise e

    def delete_vlan(self, vlan_id, az):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        req_params = {
            'vlan_id': vlan_id
        }
        nuage_vlan = nuageextendlib.NuageExtendVlan(create_params=req_params)
        restproxy.rest_call(
            'DELETE', nuage_vlan.delete_vlan_resource(), '')

    def delete_old_vsd_config(self, db_lb_dict, az):  # snat_ips = []
        old_hosts_info = None
        snat_ips = []
        snat_ips.append(db_lb_dict['snat_port1_ip'])
        snat_ips.append(db_lb_dict['snat_port2_ip'])
        vips = deepcopy(snat_ips)
        vips.append(db_lb_dict['vip_address'])
        try:
            old_hosts_info = self.get_vsd_config(db_lb_dict, db_lb_dict['vlan'], az)
            for host_info in old_hosts_info:
                print('============start delete host vport============')
                self.delete_host_vport_and_interface(host_info['host_vport'],
                                                     host_info['host_interface'], az)
                self.delete_vlan(host_info['host_vport']['VLANID'], az)
                print('============end delete host vport============')
            return True
        except Exception as e:
            print('delete old vsd config error: {}'.format(e.args))

    def create_host_vport(self, nuage_subn_id, vlan_id, port_id, az, type=None):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        nuage_subnet = nuageextendlib.NuageExtendSubnet()
        params = {
            'vlan': vlan_id,
            'type': 'HOST',
            'name': 'host' + vlan_id,
        }
        if port_id is None:
            params['externalID'] = "asbextension"
        else:
            params['externalID'] = port_id
        post_date = nuage_subnet.vport_post_data(params, "cms_id")
        if type == 'lb':
            post_date['addressSpoofing'] = 'ENABLED'
        response = restproxy.rest_call('POST', nuage_subnet.vport_post(nuage_subn_id),
                                       post_date)
        if not nuage_subnet.validate(response):
            raise RESTProxyError(nuage_subnet.error_msg)
        return response[3][0]

    def create_host_vport_policy(self, context, router_id, host_vport, vtep_type, az):
        session = context.session
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid_and_az(session, router_id, az)
        nuage_domain_id = ent_rtr_mapping['nuage_router_id']
        netp_id = ent_rtr_mapping['net_partition_id']
        dummy_domain = nuagedb.get_ironic_vpc_with_az_and_router_id(session, az, router_id)
        if dummy_domain:
            nuage_domain_id = dummy_domain['dummy_vpc_id']
        subn_macro_id = self.create_network_macro(netp_id, '0.0.0.0/0', az)
        subn_macro_id_ipv6 = self.create_network_macro_ipv6(netp_id, '::/0', az)
        extra_id = FAKE_PORT_RULE_EXT_ID
        fake_port_policy = self.get_policygroup_by_extra_id(nuage_domain_id, extra_id, vtep_type, az)
        self.append_vport_to_policy_group(fake_port_policy, host_vport['ID'], az)
        self.ensure_fake_port_policy(nuage_domain_id, subn_macro_id,
                                     fake_port_policy, ACL_INGRESS_ID, az)
        self.ensure_fake_port_policy_ipv6(nuage_domain_id, subn_macro_id_ipv6,
                                          fake_port_policy, ACL_INGRESS_ID, az)

    def create_host_interface(self, vport_id, ip_address, mac_address, az, ip_address_v6=None):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        nuage_vport = nuageextendlib.NuageExtendVPort()
        data = {"MAC": mac_address}
        if ip_address is not None:
            data['IPAddress'] = ip_address
        if ip_address_v6 is not None:
            data['IPv6Address'] = ip_address_v6
        response = restproxy.rest_call(
            'POST', nuage_vport.post_host_interface(id=vport_id), data)
        if not nuage_vport.validate(response):
            raise RESTProxyError(nuage_vport.error_msg)
        return response[3][0]

    def create_host_vport_vip(self, host_vport_id, vip, new_mac, az):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        req_params = {
            'vport_id': host_vport_id
        }
        extra_params = {
            'vip': vip,        # snat port ip
            'subnet': '',
            'mac': new_mac,   # lbaas_f5_vlans_pool_az 表中的mac
            'IPType': 'IPV' + str(netaddr.IPAddress(vip).version)
        }
        nuage_vip = nuagelib.NuageVIP(create_params=req_params,
                                      extra_params=extra_params)
        restproxy.post(nuage_vip.get_resource_for_vport(),
                       nuage_vip.post_vip_data())

    def create_vlan(self, vrsg_port_id, vlan_tag, az, cms_id=None):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        req_params = {
            'port_id': vrsg_port_id
        }
        nuage_gw_port = nuagelib.NuageGatewayPort(create_params=req_params)
        response = restproxy.rest_call('POST', nuage_gw_port.post_vlan(),
                                       nuage_gw_port.post_vlan_data(cms_id, vlanid=vlan_tag))
        from eventlet import greenthread
        greenthread.sleep(2)
        if not nuage_gw_port.validate(response):
            raise RESTProxyError(nuage_gw_port.error_msg)
        return response[3][0]

    def get_lagport_vlan_list(self, lagport_id, az):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        cmd_str = '/vsgredundantports/%s/vlans' % lagport_id
        response = restproxy.rest_call('GET', cmd_str, '')
        return response[3]

    def add_redundencygroup_vlan(self, port_id, vlan, az):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        create_params = {
            "port_id": port_id,
            'personality': 'VSG'
        }
        nuage_gw_ports = NuageGatewayRedundantPort(create_params=create_params)
        vlan_info = {'value': vlan}
        response = restproxy.rest_call(
            'POST', nuage_gw_ports.post_vlan(), vlan_info)
        if not nuage_gw_ports.validate(response):
            raise RESTProxyError(nuage_gw_ports.error_msg)
        return response[3][0]

    def get_vlan(self, vrsg_id, vlan_id, az, vtep_type='vrsg'):
        res = {}
        response = None
        if ',' in vrsg_id:
            for v_id in vrsg_id.split(','):
                if vtep_type == 'vrsg':
                    response = self.get_vlans(v_id, az)
                elif vtep_type == '7850':
                    response = self.get_lagport_vlan_list(v_id, az)
                res[v_id] = response
        else:
            if vtep_type == 'vrsg':
                response = self.get_vlans(vrsg_id, az)
            elif vtep_type == '7850':
                response = self.get_lagport_vlan_list(vrsg_id, az)
            res[vrsg_id] = response
        rtn_res = {}
        if res:
            for (k, v) in res.items():
                for vlan in v:
                    if 'value' in vlan and vlan['value'] == vlan_id:
                        rtn_res[k] = vlan
        return rtn_res

    def get_vlans(self, vrsg_port_id, az):
        restproxy = self.get_nuagelient(az)
        restproxy.generate_nuage_auth()
        req_params = {
            'port_id': vrsg_port_id
        }
        nuage_gw_port = nuagelib.NuageGatewayPort(create_params=req_params)
        response = restproxy.rest_call(
            'GET', nuage_gw_port.post_vlan(), '')
        if not nuage_gw_port.validate(response):
            raise RESTProxyError(nuage_gw_port.error_msg)
        return response[3]

    def create_lb_service(self, vrsg_id, port, vlan_tag, nuage_subnet, vips, vtep_type, router_id, az):
        vlan_dict = self.get_vlan(vrsg_id, vlan_tag, az, vtep_type)
        vlan = vlan_dict.get(vrsg_id, None)
        if not vlan:
            if vtep_type == 'vrsg':
                vlan = self.create_vlan(vrsg_id, vlan_tag, az)
            if vtep_type == '7850':
                vlan = self.add_redundencygroup_vlan(vrsg_id, vlan_tag, az)
        interface_port = {
            'mac': port['mac_address'],
            'ip': port['fixed_ips']
        }
        ip_address = interface_port['ip'][0]
        ipv6_address = interface_port['ip'][1] if len(interface_port['ip']) > 1 else None
        if ':' in ip_address:
            ip_address, ipv6_address = ipv6_address, ip_address
        host_vport = self.create_host_vport(nuage_subnet['nuage_subnet_id'], vlan['ID'], port['id'], az, 'lb')
        self.create_host_interface(host_vport['ID'],
                                   ip_address,
                                   interface_port['mac'], az,
                                   ip_address_v6=ipv6_address)
        for vip in vips:
            self.create_host_vport_vip(host_vport['ID'], vip,
                                       port['mac_address'], az)
        if vtep_type == 'vrsg':
            self.create_host_vport_policy(self.context, router_id, host_vport, vtep_type, az)

    def create_new_vsd_config(self, lb_db, new_f5_vlan_db, vlan, no_same_subnet_lb,
                              self_port1, self_port2):
        router_id = lb_db['router_id']
        az = new_f5_vlan_db['az']
        if no_same_subnet_lb:
            print('============ start create host vport ============')
            snat_ips = []
            snat_ips.append(lb_db['snat_port1_ip'])
            snat_ips.append(lb_db['snat_port2_ip'])
            vips = deepcopy(snat_ips)
            vips.append(lb_db['vip_address'])
            vtep_type = self.vtep_type[az]
            nuage_subnet = nuagedb.get_subnet_l2dom_by_id(self.context.session, lb_db['vip_subnet_id'])
            self.create_lb_service(new_f5_vlan_db['vrsg_id'].split(',')[0], self_port1, vlan,
                                   nuage_subnet, vips, vtep_type, router_id, az)
            self.create_lb_service(new_f5_vlan_db['vrsg_id'].split(',')[1], self_port2, vlan,
                                   nuage_subnet, vips, vtep_type, router_id, az)
            print('============ end create host vport ============')
        else:
            print('============ start create host vport vip ============')
            vips = []
            vips.append(lb_db['vip_address'])
            new_hosts_info = self.get_vsd_config(lb_db, lb_db['new_vlan'], az)
            for host_info in new_hosts_info:
                for vip in vips:
                    self.create_host_vport_vip(host_info['host_vport']['ID'], vip,
                                               host_info['host_interface']['MAC'], az)
            print('============ end create host vport vip ============')

class RESTProxyBaseException(Exception):
    message = ("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(RESTProxyBaseException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            if self.use_fatal_exceptions():
                raise
            else:
                super(RESTProxyBaseException, self).__init__(self.message)

    if six.PY2:
        def __unicode__(self):
            return unicode(self.msg)  # noqa

    def __str__(self):
        return self.msg

    def use_fatal_exceptions(self):
        return False

class RESTProxyError(RESTProxyBaseException):
    message = ('Error in REST call to VSD: %(msg)s')

    def __init__(self, msg='', error_code=None, vsd_code=None):
        super(RESTProxyError, self).__init__(msg=msg)
        self.code = 0
        if error_code:
            self.code = error_code
        self.vsd_code = vsd_code

if __name__ == "__main__":
    lb_id = raw_input("please input lb_id:")
    f5_node1 = raw_input("please input f5_node1:")
    f5_node2 = raw_input("please input f5_node2:")
    valid_lb_node = check_lb_node(lb_id, f5_node1, f5_node2)

    vtep_type = None
    if valid_lb_node:
        db_lb_dict, db_listener_list, db_pool_list, db_member_list, db_healthmonitor_list, db_l7policy_list, db_l7rule_list \
            = get_all_info(lb_id)
        no_same_subnet_lb = get_lb_with_subnet(db_lb_dict, f5_node1, f5_node2)
        new_node_info = get_f5_node_info(f5_node1, f5_node2)
        old_node_info = get_f5_node_info(db_lb_dict['node1'], db_lb_dict['node2'])
        az = old_node_info['az']
        new_az = new_node_info['az']
        mac1 = new_node_info['mac1']
        mac2 = new_node_info['mac2']

        lb_dict = deepcopy(db_lb_dict)
        listener_list = deepcopy(db_listener_list)
        pool_list = deepcopy(db_pool_list)
        member_list = deepcopy(db_member_list)
        healthmonitor_list = deepcopy(db_healthmonitor_list)
        l7policy_list = deepcopy(db_l7policy_list)
        l7rule_list = deepcopy(db_l7rule_list)

        old_node1 = db_lb_dict['node1']
        old_node2 = db_lb_dict['node2']
        old_vlan = db_lb_dict['vlan']
        old_self_port1_id = db_lb_dict['self_port1_id']
        old_self_port2_id = db_lb_dict['self_port2_id']

        no_same_subnet_lb_old = get_lb_with_subnet(db_lb_dict, old_node1, old_node2)

        if no_same_subnet_lb:
            # 新F5 上分配新vlan
            old_node_dict = get_f5_node_info(db_lb_dict['node1'], db_lb_dict['node2'])
            vlan = choose_new_vlan(old_node_dict, f5_node1, f5_node2)
            lb_dict['new_vlan'] = vlan
            print("new_vlan: {}".format(vlan))

            # 创建新的 self_ip_port,并添加到表 lbaas_f5_loadbalancers_az 中
            port_data1 = {
                'tenant_id': db_lb_dict['project_id'],
                'name': 'F5-self-' + db_lb_dict['lb_id'],
                'network_id': db_lb_dict['lb_subnet_network'],
                'admin_state_up': False,
                'device_id': db_lb_dict['lb_id'],
                'device_owner': DEVICE_OWNER_LOADBALANCER,
                'fixed_ips': [{'subnet_id': db_lb_dict['vip_subnet_id']}],
                'mac_address': mac1
            }
            port_data2 = {
                'tenant_id': db_lb_dict['project_id'],
                'name': 'F5-self-' + db_lb_dict['lb_id'],
                'network_id': db_lb_dict['lb_subnet_network'],
                'admin_state_up': False,
                'device_id': db_lb_dict['lb_id'],
                'device_owner': DEVICE_OWNER_LOADBALANCER,
                'fixed_ips': [{'subnet_id': db_lb_dict['vip_subnet_id']}],
                'mac_address': mac2
            }
            self_port1_result = RestAPI().create_port(port_data1)
            self_port2_result = RestAPI().create_port(port_data2)
            self_port1_id = self_port1_result['id']
            self_port2_id = self_port2_result['id']
            self_port1_ip = self_port1_result['fixed_ips'][0]['ip_address']
            self_port2_ip = self_port2_result['fixed_ips'][0]['ip_address']
            print("new_self_port1_id: {} , new_self_port1_ip: {}".format(self_port1_id, self_port1_ip))
            print("new_self_port2_id: {} , new_self_port2_ip: {}".format(self_port2_id, self_port2_ip))

            lb_dict['new_az'] = new_node_info['az']
            lb_dict['self_port1_id'] = self_port1_id
            lb_dict['self_port2_id'] = self_port2_id
            lb_dict['self_port1_ip'] = self_port1_ip
            lb_dict['self_port2_ip'] = self_port2_ip
            lb_dict['self_port1_mac'] = mac1
            lb_dict['self_port2_mac'] = mac2
            lb_dict['description'] = 'SNAT pool:' + str(lb_dict['vip_address']) + ',' + str(
                lb_dict['self_port1_ip'] + ',' + str(
                    lb_dict['self_port2_ip'] + ',' + str(lb_dict['snat_port1_ip']) + ',' + str(lb_dict['snat_port2_ip'])))
            print("lb_description: {}".format(lb_dict['description']))

        else:
            # lb2 self_port 更新至与 lb1 self_port一致
            lb_list = session.query(F5_loadbalancers_az).filter_by(node1=f5_node1, node2=f5_node2).all()
            same_lb_list = []
            for l in lb_list:
                lb_info = session.query(Lbaas_Loadbalancers).filter_by(id=l.neutron_id).first()
                if not lb_info:
                    pass
                else:
                    if lb_info.vip_subnet_id == db_lb_dict['vip_subnet_id']:
                        print("same subnet lb: {}" .format(lb_info.id))
                        same_subnet_lb = session.query(F5_loadbalancers_az).filter_by(neutron_id=lb_info.id).first()
                        lb_dict['self_port1_id'] = same_subnet_lb.self_port1
                        lb_dict['self_port2_id'] = same_subnet_lb.self_port2

                        port1_info = session.query(Ipallocations).filter_by(port_id=same_subnet_lb.self_port1).first()
                        lb_dict['self_port1_ip'] = port1_info.ip_address
                        port2_info = session.query(Ipallocations).filter_by(port_id=same_subnet_lb.self_port2).first()
                        lb_dict['self_port2_ip'] = port2_info.ip_address

                        lb_dict['description'] = 'SNAT pool:' + str(lb_dict['vip_address']) + ',' + str(
                            lb_dict['self_port1_ip'] + ',' + str(lb_dict['self_port2_ip'] + ',' + str(
                                lb_dict['snat_port1_ip']) + ',' + str(lb_dict['snat_port2_ip'])))
                        lb_dict['new_vlan'] = same_subnet_lb.vlan

        # 创建新资源
        print("create new resources".center(120, "="))
        try:
            create_lb(lb_id, lb_dict, f5_node1, f5_node2)
            print('')
            create_listener(lb_id, lb_dict, listener_list, f5_node1, f5_node2)
            print('')
            create_pool(lb_dict, listener_list, pool_list, f5_node1, f5_node2)
            print('')
            create_member(lb_dict, member_list, f5_node1, f5_node2)
            print('')
            create_healthmonitor(lb_id, lb_dict, pool_list, healthmonitor_list, f5_node1, f5_node2)
            print('')
            create_l7policy(lb_dict, l7policy_list, f5_node1, f5_node2)
            print('')
            create_l7rule(lb_dict, l7policy_list, l7rule_list, f5_node1, f5_node2)
        except Exception as e:
            print("create resource failed!")
            raise e

        # 删除旧资源
        print("delete old resources".center(120, "="))
        fip_disassociate_lb_vip(db_lb_dict)
        print('')
        delete_l7rule(db_lb_dict, db_l7policy_list, db_l7rule_list)
        print('')
        delete_l7policy(db_lb_dict, db_l7policy_list)
        print('')
        delete_healthmonitor(db_lb_dict, db_healthmonitor_list, db_pool_list)
        print('')
        delete_member(db_lb_dict)
        print('')
        delete_pool(db_lb_dict, db_listener_list, db_pool_list)
        print('')
        delete_listener(db_lb_dict, db_listener_list)
        print('')
        delete_lb(db_lb_dict)
        print('')
        
        if no_same_subnet_lb_old:
            # 从vsd上删除老的 host vport 和 vlan
            print("old F5 does not exist same subnet lb, now start delete old host vport and vlan")
            MigrateLb().delete_old_vsd_config(db_lb_dict, az)
            print("end delete old host vport and vlan")

            # 删除老的 self_ip_port
            print("start delete old self_port")
            RestAPI().delete_port(old_self_port1_id)
            RestAPI().delete_port(old_self_port2_id)
            print("end delete old self_port")
        else:
            # 将vip从老的host vport上删除
            vips = []
            vips.append(db_lb_dict['vip_address'])
            print("old F5 exist same subnet lb, now start delete vip from old host vport!")
            old_hosts_info = MigrateLb().get_vsd_config(db_lb_dict, old_vlan, az)
            for host_info in old_hosts_info:
                print("old host vport {}".format(host_info['host_vport']['ID']))
                MigrateLb().delete_host_vport_vip(host_info['host_vport']['ID'], vips, az)
            print("end delete vip")

        # lb_vip 绑定 fip
        fip_associate_lb_vip(lb_dict, az, f5_node1, f5_node2)

        '''
        # 创建新的vsd资源
        print('================ start create new vsd config =================')
        new_f5_node_dict = get_f5_node_info(f5_node1, f5_node2)
        self_port1_dict = get_port_info(lb_dict['self_port1_id'])
        self_port2_dict = get_port_info(lb_dict['self_port2_id'])
        MigrateLb().create_new_vsd_config(lb_dict, new_f5_node_dict, lb_dict['new_vlan'], no_same_subnet_lb, self_port1_dict, self_port2_dict)
        print('================ end create new vsd config =================')
        '''