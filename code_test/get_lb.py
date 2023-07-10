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
# cfg.CONF(default_config_files=['/etc/neutron/neutron.conf'])
# engine = create_engine(cfg.CONF.database.connection)

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

class Subnet(Base):
    __tablename__ = 'subnets'
    id = Column(String(36),primary_key=True)
    project_id = Column(String(255))
    name = Column(String(255))
    network_id = Column(String(36))
    ip_version = Column(Integer)
    cidr = Column(String(64))
    gateway_ip = Column(String(64))
    enable_dhcp = Column(Integer)
    ipv6_ra_mode = Column(Enum('slaac','dhcpv6-stateful','dhcpv6-stateless'))
    ipv6_address_mode = Column(Enum('slaac','dhcpv6-stateful','dhcpv6-stateless'))
    subnetpool_id = Column(String(36))
    standard_attr_id = Column(Integer)
    segment_id = Column(String(36))
    path = Column(String(255))
    ip_frozen = Column(Integer)

class Network(Base):
    __tablename__ = 'networks'
    id = Column(String(36), primary_key=True)
    project_id = Column(String(255))
    name = Column(String(255))
    status = Column(String(16))
    admin_state_up = Column(Integer)
    vlan_transparent = Column(Integer)
    standard_attr_id = Column(Integer)
    availability_zone_hints = Column(String(255))
    mtu = Column(Integer)

class F5h_Node_Lb(Base):
    __tablename__ = 'newarch_f5h_node_lb'
    id = Column(Integer, primary_key=True)
    f5h_loadbalancer_id = Column(Integer)
    lb_id = Column(String(36))

class F5h_loadbalancers_az(Base):
    __tablename__ = 'lbaas_f5h_loadbalancers_az'
    id = Column(Integer,primary_key=True)
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

def get_lb_info():
    lb_id = raw_input("please input lb_id:")

    lb_info = session.query(Lbaas_Loadbalancers).filter_by(id=lb_id).first()
    loadbalancer_id = lb_info.id
    name = lb_info.name
    flavor = lb_info.flavor
    subnet_id = lb_info.vip_subnet_id

    subnet_info = session.query(Subnet).filter_by(id=subnet_id).first()
    network_id = subnet_info.network_id

    network_info = session.query(Network).filter_by(id=network_id).first()
    availability_zone_hints = network_info.availability_zone_hints
    az = availability_zone_hints[2:5]

    node_lb_info = session.query(F5h_Node_Lb).filter_by(lb_id=lb_id).first()
    f5h_loadbalancer_id = node_lb_info.f5h_loadbalancer_id

    f5h_loadbalancer_az_info = session.query(F5h_loadbalancers_az).filter_by(id=f5h_loadbalancer_id).first()
    lb_ip1 = f5h_loadbalancer_az_info.node1
    lb_ip2 = f5h_loadbalancer_az_info.node2
    vlan = f5h_loadbalancer_az_info.vlan

    tb = pt.PrettyTable()
    tb.field_names = ['loadbalancer_id', 'name', 'lb_ip1', 'lb_ip2', 'vlan', 'flavor', 'AZ']
    loadbalancer_info = []
    loadbalancer_info.append(loadbalancer_id)
    loadbalancer_info.append(name)
    loadbalancer_info.append(lb_ip1)
    loadbalancer_info.append(lb_ip2)
    loadbalancer_info.append(vlan)
    loadbalancer_info.append(flavor)
    loadbalancer_info.append(az)
    tb.add_row(loadbalancer_info)
    print(tb)
    # print("loadbalancer_id: "+str(loadbalancer_id)+", name: "+str(name)+ ", lb_ip1: "+str(lb_ip1)+", lb_ip2: "+str(lb_ip2)+", vlan: "+str(vlan)+ ", flavor: "+str(flavor)+", AZ: "+str(az))

if __name__ == "__main__":
    get_lb_info()