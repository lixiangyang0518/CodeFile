# _*_ coding:utf-8 _*_
from sqlalchemy import create_engine
from sqlalchemy import Column, String, Integer, Enum
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from collections import OrderedDict
from copy import deepcopy
from nuageextension.f5_lbaas import lbaas as f5_driver
from oslo_config import cfg
import sys
import random
import ConfigParser
import IPy as ipy

# 连接数据库
neutron_config = '/etc/neutron/neutron.conf'
config = ConfigParser.ConfigParser()
config.readfp(open(neutron_config))
conn = config.get('database', 'connection')
engine = create_engine(conn)
Session = sessionmaker(bind=engine)
session = Session()

opt_group = cfg.OptGroup('F5')
opts = [
    cfg.StrOpt('username'),
    cfg.StrOpt('password'),
]
cfg.CONF.register_group(opt_group)
cfg.CONF.register_opts(opts, group=opt_group)

# 获取 F5配置文件信息
f5_nfv_file = '/etc/neutron/f5_nfv.ini'
cfg.CONF(default_config_files=[f5_nfv_file])
config = ConfigParser.ConfigParser()
config.readfp(open(f5_nfv_file))
username = config.get('F5', 'username')
password = cfg.CONF.F5.password
inside_interface = config.get('F5', 'inside_interface')

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

class Lbaas_F5_snatpoolports_az(Base):
    __tablename__ = 'lbaas_f5_snatpoolports_az'
    loadbalancer_id =  Column(String(36), primary_key=True)
    port_id = Column(String(36), primary_key=True)

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
    lb_dict['self_port1'] = port1_info.ip_address
    lb_dict['self_port2'] = port2_info.ip_address
    lb_dict['vlan'] = self_port_info.vlan
    lb_dict['node1'] = self_port_info.node1
    lb_dict['node2'] = self_port_info.node2

    # 获取两个 snat port
    snat_port_info = session.query(Lbaas_F5_snatpoolports_az).filter_by(loadbalancer_id=lb_id).all()
    snat_port_list = []
    for i in snat_port_info:
        port_address = session.query(Ipallocations).filter_by(port_id=i.port_id).first()
        snat_port_list.append(port_address.ip_address)

    snat_port1 = ''.join(snat_port_list[0])
    snat_port2 = ''.join(snat_port_list[1])
    lb_dict['snat_port1'] = snat_port1
    lb_dict['snat_port2'] = snat_port2

    lb_dict['description'] = 'SNAT pool:' + str(l.vip_address) + ',' + str(lb_dict['self_port1'] + ',' + str(lb_dict['self_port2'] + ',' + snat_port1 + ',' + snat_port2))

    # 获取 subnet
    subnet_info = session.query(Subnets).filter_by(id=l.vip_subnet_id).first()
    lb_dict['lb_subnet_name'] = subnet_info.name
    lb_dict['lb_subnet_network'] = subnet_info.network_id
    lb_dict['lb_subnet_ip_version'] = subnet_info.ip_version
    lb_dict['lb_subnet_cidr'] = subnet_info.cidr
    lb_dict['lb_subnet_gateway_ip'] = subnet_info.gateway_ip

    return lb_dict

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
        'vlan': db_lb_dict['vlan'],
        'enable_session_flag': False,
        'user_id': db_lb_dict['project_id'],
        'f5_user': username,
        'f5_pwd': password,
        'gateway': [db_lb_dict['lb_subnet_gateway_ip']],
        'f5_vm': [f5_node1, f5_node2],
        'interface': inside_interface,
        'bandwidth': str(db_lb_dict['lb_bandwidth']),
        'self_ip': [{
                'ip': db_lb_dict['self_port1'],
                'netmask': str(ipy.IP(db_lb_dict['lb_subnet_cidr']).netmask())
            },
                {'ip': db_lb_dict['self_port2'],
                 'netmask': str(ipy.IP(db_lb_dict['lb_subnet_cidr']).netmask())
                 }],
        'vip_address': db_lb_dict['vip_address'],
        'snat_pool': [db_lb_dict['snat_port1'],
                      db_lb_dict['snat_port2']],
        'max_concurrency': 5000,
        'new_connection': 3000,
        'route_domains_id': db_lb_dict['vlan'],
        'float_mac': '',
        'stack_self_ip': [],
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
    }

    # 下发创建lb请求
    request_lb = f5_driver.loadbalancer.create_p({'loadbalancer': lb_dict}, sdn_dict)
    print("sdn_dict lb: %s" % sdn_dict)
    print("create lb: {}".format(request_lb))

def create_listener(lb_id, db_lb_dict, db_listener_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
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
            request_listener = f5_driver.listener.create({'listener': listener_dict}, sdn_dict)
            print("sdn_dict listener: %s" % sdn_dict)
            print("create listener: {}".format(request_listener))

def create_pool(db_lb_dict, db_listener_list, db_pool_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
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
                        print("pool_dict: %s" % pool_dict)
                        print("sdn_dict pool: %s" % sdn_dict)
                        print("create pool: {}".format(request_pool))
                    except Exception as e:
                        pass

def create_member(db_lb_dict, db_member_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
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
            request_member = f5_driver.member.create({'member': member_dict}, sdn_dict)
            print("sdn_dict member: %s" % sdn_dict)
            print("create member: {}".format(request_member))

def create_healthmonitor(lb_id, db_lb_dict, db_pool_list, db_healthmonitor_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
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
                    print("sdn_dict health: %s" % sdn_dict)
                    print("create healthmonitor: {}".format(request_healthmonitor))

def create_l7policy(db_lb_dict, db_l7policy_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan':db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
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
            print("sdn_dict l7policy: %s" % sdn_dict)
            print("create l7policy: {}".format(request_l7policy))

def create_l7rule(db_lb_dict, db_l7policy_list, db_l7rule_list, f5_node1, f5_node2):
    sdn_dict = {
        'f5_vm': [f5_node1, f5_node2],
        'f5_user': username,
        'f5_pwd': password,
        'vip_subnet_id': [db_lb_dict['vip_subnet_id']],
        'vlan': db_lb_dict['vlan'],
        'user_id': db_lb_dict['project_id'],
        'route_domains_id': db_lb_dict['vlan'],
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
                    print("sdn_dict l7rule: %s" % sdn_dict)
                    print("create l7rule: {}".format(request_l7rule))

def random_mac():
    mac = [0x52, 0x54, 0x00,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

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
                print("sdn_dict l7rule: %s" % sdn_dict)
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
            print("sdn_dict l7policy: %s" % sdn_dict)
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
                    print("sdn_dict heathm: %s" % sdn_dict)
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
            print("sdn_dict member: %s" % sdn_dict)
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
                    print("sdn_dict pool: %s" % sdn_dict)
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
            print("sdn_dict listener: %s" % sdn_dict)
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
    print("sdn_dict lb: %s" % sdn_dict)
    print("delete lb: {}".format(request_lb))

if __name__ == "__main__":

    lb_id = raw_input("please input lb_id:")
    f5_node1 = raw_input("please input f5_node1:")
    f5_node2 = raw_input("please input f5_node2:")
    valid_lb_node = check_lb_node(lb_id, f5_node1, f5_node2)
    # 获取lb 所有信息
    if valid_lb_node:
        db_lb_dict, db_listener_list, db_pool_list, db_member_list, db_healthmonitor_list, db_l7policy_list, db_l7rule_list \
            = get_all_info(lb_id)

        lb_dict = deepcopy(db_lb_dict)
        listener_list = deepcopy(db_listener_list)
        pool_list = deepcopy(db_pool_list)
        member_list = deepcopy(db_member_list)
        healthmonitor_list = deepcopy(db_healthmonitor_list)
        l7policy_list = deepcopy(db_l7policy_list)
        l7rule_list = deepcopy(db_l7rule_list)

        # 创建新资源
        print("create new resources".center(120, "="))
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

        # 删除旧资源
        print("delete old resources".center(120, "="))
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