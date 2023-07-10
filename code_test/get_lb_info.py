# _*_ coding:utf-8 _*_
from sqlalchemy import create_engine
from sqlalchemy import Column, String, Integer, Enum
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from oslo_config import cfg
import sys
import ConfigParser
import prettytable as pt     # 以表格形式输出

# 连接数据库
neutron_config = '/etc/neutron/neutron.conf'
config = ConfigParser.ConfigParser()
config.readfp(open(neutron_config))
conn = config.get('database', 'connection')
engine = create_engine(conn)
Session = sessionmaker(bind=engine)
session = Session()

# 数据表映射
Base = declarative_base()
class Lbaas_Loadbalancers(Base):
    __tablename__ = 'lbaas_loadbalancers'
    id = Column(String(36), primary_key=True, nullable=False, default=None)
    project_id = Column(String(255), nullable=True, default=None)
    name = Column(String(255), nullable=True, default=None)
    description = Column(String(11600), nullable=True, default=None)
    vip_port_id = Column(String(36), nullable=True, default=None)
    vip_subnet_id = Column(String(36), nullable=False, default=None)
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

def get_listeners(lb_id):
    listeners_info = session.query(Lbaas_Listener).filter_by(loadbalancer_id=lb_id).all()

    listener_list = []
    tb = pt.PrettyTable()
    tb.field_names = ['project_id', 'listener_id', 'listener_name']
    for listener in listeners_info:
        listeners = []
        listener_id = listener.id
        listener_name = listener.name
        project_id = listener.project_id

        listeners.append(project_id)
        listeners.append(listener_id)
        listeners.append(listener_name)
        listener_list.append(listener_id)

        tb.add_row(listeners)
    return tb, listener_list

def get_pools(lb_id):
    pool_info = session.query(Lbaas_Pools).filter_by(loadbalancer_id=lb_id).all()

    pool_list = []
    healthmonitor_list = []
    tb = pt.PrettyTable()
    tb.field_names = ['project_id', 'pool_id', 'healthmonitor_id', 'pool_name']
    for pool in pool_info:
        pools = []
        pool_id = pool.id
        pool_name = pool.name
        project_id = pool.project_id
        healthmonitor_id = pool.healthmonitor_id

        pools.append(project_id)
        pools.append(pool_id)
        pools.append(healthmonitor_id)
        pools.append(pool_name)
        tb.add_row(pools)
        pool_list.append(pool_id)
        healthmonitor_list.append(healthmonitor_id)

    return tb, pool_list, healthmonitor_list

def get_members(lb_id):
    a,pool_list,c = get_pools(lb_id)
    tb = pt.PrettyTable()
    tb.field_names = ['project_id', 'pool_id', 'member_id', 'subnet_id', 'address', 'member_name']
    for pool in pool_list:
        member_info = session.query(Lbaas_members).filter_by(pool_id=pool).all()
        for member in member_info:
            members = []
            pool_id = member.pool_id
            member_id = member.id
            subnet_id = member.subnet_id
            address = member.address
            member_name = member.name
            project_id = member.project_id

            members.append(project_id)
            members.append(pool_id)
            members.append(member_id)
            members.append(subnet_id)
            members.append(address)
            members.append(member_name)
            tb.add_row(members)

    print(tb)

def get_healthmonitors(lb_id):
    a, b, healthmonitor_list = get_pools(lb_id)
    tb = pt.PrettyTable()
    tb.field_names = ['project_id', 'healthmonitor_id', 'healthmonitor_type', 'healthmonitor_name']
    for hm in healthmonitor_list:
        hm_info = session.query(Lbaas_healthmonitors).filter_by(id=hm).all()
        for hm in hm_info:
            hms = []
            healthmonitor_id = hm.id
            healthmonitor_type = hm.type
            healthmonitor_name = hm.name
            project_id = hm.project_id

            hms.append(project_id)
            hms.append(healthmonitor_id)
            hms.append(healthmonitor_type)
            hms.append(healthmonitor_name)
            tb.add_row(hms)

    print(tb)

def get_l7policies(lb_id):
    a, listener_list = get_listeners(lb_id)
    l7policies_list = []
    tb = pt.PrettyTable()
    tb.field_names = ['project_id', 'l7policy_id', 'listener_id', 'action', 'l7policy_name']
    for l in listener_list:
        l7policy_info = session.query(Lbaas_l7policies).filter_by(listener_id=l).all()
        for l7policy in l7policy_info:
            l7policies = []
            l7policy_id = l7policy.id
            listener_id = l7policy.listener_id
            action = l7policy.action
            l7policy_name = l7policy.name
            project_id = l7policy.project_id

            l7policies.append(project_id)
            l7policies.append(l7policy_id)
            l7policies.append(listener_id)
            l7policies.append(action)
            l7policies.append(l7policy_name)
            tb.add_row(l7policies)
            l7policies_list.append(l7policy_id)

    return tb, l7policies_list

def get_l7rules(lb_id):
    a, l7policies_list = get_l7policies(lb_id)
    tb = pt.PrettyTable()
    tb.field_names = ['project_id', 'l7rule_id', 'l7policy_id', 'type', 'compare_type', 'value']
    for l7policy in l7policies_list:
        l7rule_info = session.query(Lbaas_l7rules).filter_by(l7policy_id=l7policy).all()
        for l7rule in l7rule_info:
            l7rules = []
            project_id = l7rule.project_id
            l7rule_id = l7rule.id
            l7policy_id = l7rule.l7policy_id
            type = l7rule.type
            compare_type = l7rule.compare_type
            value = l7rule.value

            l7rules.append(project_id)
            l7rules.append(l7rule_id)
            l7rules.append(l7policy_id)
            l7rules.append(type)
            l7rules.append(compare_type)
            l7rules.append(value)
            tb.add_row(l7rules)
    print(tb)

def main():
    lb_id = sys.argv[1]
    print("")
    print("listeners:")
    a, b = get_listeners(lb_id)
    print(a)

    print("")
    print("pools:")
    a, b, c = get_pools(lb_id)
    print(a)

    print("")
    print("members:")
    get_members(lb_id)

    print("")
    print("healthmonitors:")
    get_healthmonitors(lb_id)

    print("")
    print("l7policies:")
    a, b = get_l7policies(lb_id)
    print(a)

    print("")
    print("l7rules:")
    get_l7rules(lb_id)

if __name__ == "__main__":
    main()