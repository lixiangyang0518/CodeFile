#!/usr/bin/env python
# coding=utf-8

import argparse
import time
import socket
import sys
import logging
from oslo_config import cfg
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, create_engine
from nuage_neutron.plugins.common import nuagedb
from neutron.db import models_v2
from neutron.db.models import l3 as l3_models
from neutron_lbaas.db.loadbalancer import models as lb_models
from nuageextension.newarch.db.models import db_model as nfv_db_model
from collections import OrderedDict

database = cfg.OptGroup(name='database',
                        title='group database Options')

opts = [
    cfg.StrOpt('connection',
               default='',
               help='item connection in group database.')
]

cfg.CONF.register_group(database)
cfg.CONF.register_opts(opts, group=database)

LOG = logging.getLogger(__name__)


def get_argparser():
    parser = argparse.ArgumentParser(description='neutron resources')
    # parser.add_argument('objs',
    #                     metavar='Object',
    #                     type=str,
    #                     nargs='+',
    #                     help='Object to scan, support type: {}, {}, {}, {}, {}, {}'
    #                     .format(SUBNET_OBJ, ROUTER_OBJ, PORT_OBJ, DUMMY_FlOATINGIP_OBJ, SECURITY_GROUP_OBJ,
    #                             PROJECT_OBJ))
    parser.add_argument('-n',
                        '--network',
                        dest='network',
                        type=str,
                        default='',
                        required=False,
                        help='show network relation resources')
    parser.add_argument('-s',
                        '--subnet',
                        dest='subnet',
                        type=str,
                        default='',
                        required=False,
                        help='show subnet relation resources')
    parser.add_argument('-r',
                        '--router',
                        dest='router',
                        type=str,
                        default='',
                        required=False,
                        help='show router relation resources')
    parser.add_argument('-p',
                        '--port',
                        dest='port',
                        type=str,
                        default='',
                        required=False,
                        help='show port relation resources')
    parser.add_argument('-lb',
                        '--loadbalancer',
                        dest='loadbalancer',
                        type=str,
                        default='',
                        required=False,
                        help='show loadbalancer relation resources')
    return parser


def MyPrint(log_str):
    print '[' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + ']' + log_str


class ShowResources(object):
    def __init__(self):
        cfg.CONF(
            default_config_files=['/etc/neutron/neutron.conf',
                                  '/etc/neutron/plugin.ini'])
        self.session = self.create_session()
        self.hostname = socket.gethostname()

    def create_session(self):
        engine = create_engine(cfg.CONF.database.connection)
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        return session

    def print_group(self, group, keyHeader, keyMaxLen):
        for item in group:
            if item:
                print '\r'
                for i, h in enumerate(keyHeader):
                    itemLen = keyMaxLen.get(h, str(h)) + 4
                    s = str(item[h]).center(itemLen, '-' if item[h] == '-' else ' ')
                    icon = '|'
                    if item[h] == '-':
                        icon = '+'
                    s = (icon if i == 0 else '') + s[1:len(s)] + icon
                    print s,
        print '\r'

    def output_info(self, info_list):
        if not info_list:
            LOG.debug('output_info->info_list->is None')
            return
        keyHeader = info_list[0].keys()
        keyMaxLen = {}
        for item in info_list:
            if item:
                for i, h in enumerate(keyHeader):
                    maxLen = max(len(h), len(str(item[h])))
                    if keyMaxLen.get(h, None):
                        maxLen = max(maxLen, keyMaxLen[h])
                    keyMaxLen[h] = maxLen
        tag = {}
        for i, h in enumerate(keyHeader):
            tag[h] = '-'
        info_list.insert(0, tag)
        info_list.append(tag)
        self.print_group([tag], keyHeader, keyMaxLen)
        for i, h in enumerate(keyHeader):
            itemLen = keyMaxLen.get(h, str(h)) + 4
            s = h.center(itemLen)
            s = ('|' if i == 0 else '') + s[1:len(s)] + '|'
            print s,
        self.print_group(info_list, keyHeader, keyMaxLen)

    def get_port_info(self, port_id):
        port_subnet = []
        port_router = []
        port_network = ''
        port_db = self.session.query(models_v2.Port).filter_by(id=port_id).first()
        if port_db:
            port_network = port_db['network_id']
            subnet_dbs = self.session.query(models_v2.IPAllocation).filter_by(port_id=port_id).all()
            if subnet_dbs:
                for subnet_db in subnet_dbs:
                    port_subnet.append(subnet_db['subnet_id'])
        if port_subnet:
            for subnet in port_subnet:
                router_id = nuagedb.get_router_id_by_subnet_id(self.session, subnet)
                if router_id:
                    port_router.append(router_id)
                    port_router = list(set(port_router))
        return port_network, port_subnet, port_router

    def get_router_subnet(self, router_id):
        subnet_ids = []
        subnets = nuagedb.get_subnet_id_by_router_id(self, router_id)
        for subnet in subnets:
            subnet_id = subnet['subnet_id']
            subnet_ids.append(subnet_id)
        return subnet_ids

    def get_net_router(self, net_id):
        network_db = self.session.query(models_v2.IPAllocation).filter_by(network_id=net_id).first()
        if network_db:
            subnet_id = network_db['subnet_id']
            router_id = nuagedb.get_router_id_by_subnet_id(self.session, subnet_id)
            if router_id:
                return router_id
            else:
                return None

    def get_subnet_router(self, subnet_id):
        router_id = nuagedb.get_router_id_by_subnet_id(self.session, subnet_id)
        return router_id

    def get_port_fip(self, port_id):
        fip_db = self.session.query(l3_models.FloatingIP).filter_by(fixed_port_id=port_id).first()
        if fip_db:
            port_fip = fip_db['floating_ip_address']
            return port_fip
        else:
            return None

    def get_fip_info(self, fip_ip):
        pass

    def get_lb_info(self,loadbalacer_id):
        lb_db = self.session.query(lb_models.LoadBalancer).filter_by(id=loadbalacer_id).first()
        if lb_db:
            vip_port = lb_db.vip_port_id
            lb_fip = self.get_port_fip(vip_port)
            vip_subnet_id = lb_db.vip_subnet_id
            lb_vip = lb_db.vip_address
            router_id = self.get_subnet_router(vip_subnet_id)
            if lb_db.provider.provider_name == 'f5hardware':
                lb_az_db = self.session.query(nfv_db_model.LbaasF5HLoadbalancerAZ).join(
                    nfv_db_model.NewarchF5HNodeLB, nfv_db_model.NewarchF5HNodeLB.lb_id == lb_db.id
                ).filter(
                    nfv_db_model.NewarchF5HNodeLB.f5h_loadbalancer_id == nfv_db_model.LbaasF5HLoadbalancerAZ.id).first()
                if lb_az_db:
                    vlan = lb_az_db.vlan
                    node1 = lb_az_db.node1
                    node2 = lb_az_db.node2
            else:
                lb_az_db = self.session.query(nfv_db_model.LbaasF5LoadbalancerAZ).filter_by(neutron_id=loadbalacer_id).first()
                if lb_az_db:
                    vlan = lb_az_db.vlan
                    node1 = lb_az_db.node1
                    node2 = lb_az_db.node2
            lb_info = OrderedDict()
            lb_info['project_id'] = lb_db.project_id
            lb_info['id'] = lb_db.id
            lb_info['vip'] = lb_vip
            lb_info['fip'] = lb_fip
            lb_info['subnet'] = vip_subnet_id
            lb_info['router'] = router_id
            lb_info['vlan'] = vlan if vlan else None
            lb_info['node1'] = node1 if node1 else None
            lb_info['node2'] = node2 if node2 else None
            return lb_info

    def list_port(self, port_id):
        port_network, port_subnet, port_router = self.get_port_info(port_id)
        port_fip = self.get_port_fip(port_id)

        list_info = []
        for obj in range(len(port_subnet)):
            info = OrderedDict()
            info['port_id'] = port_id
            info['network_id'] = port_network
            info['subnet_id'] = port_subnet[obj]
            info['router_id'] = port_router
            info['fip'] = port_fip
            list_info.append(info)
        if list_info:
            self.output_info(list_info)
        else:
            print ('port {} is empty'.format(port_id))

    def list_router(self, router_id):
        subnet_ids = self.get_router_subnet(router_id)
        list_info = []
        if subnet_ids:
            for obj in range(len(subnet_ids)):
                info = OrderedDict()
                info['router_id'] = router_id
                info['subnet_id'] = subnet_ids[obj]
                list_info.append(info)
            self.output_info(list_info)
        else:
            print ('No subnet interface router')

    def list_network(self, network_id):
        router_id = self.get_net_router(network_id)
        list_info = []
        if router_id:
            info = OrderedDict()
            info['router_id'] = router_id
            info['network_id'] = network_id
            list_info.append(info)
            self.output_info(list_info)
        else:
            print ('No router interface network')

    def list_subnet(self, subnet_id):
        router_id = self.get_subnet_router(subnet_id)
        list_info = []
        if router_id:
            info = OrderedDict()
            info['router_id'] = router_id
            info['subnet_id'] = subnet_id
            list_info.append(info)
            self.output_info(list_info)
        else:
            print ('No router interface subnet')

    def list_loadbalancer(self, loadbalancer_id):
        lb_info = self.get_lb_info(loadbalancer_id)
        list_info = []
        if lb_info:
            info = OrderedDict()
            info['porject'] = lb_info['project_id']
            info['node1'] = lb_info['node1']
            info['node2'] = lb_info['node2']
            info['lb_id'] = lb_info['id']
            info['vip'] = lb_info['vip']
            info['sunbnet'] = lb_info['subnet']
            info['vlan'] = lb_info['vlan']
            info['fip'] = lb_info['fip']
            info['router'] = lb_info['router']
            list_info.append(info)
            self.output_info(list_info)
        else:
            print ('No lb info in db')

    def list_fip(self, fip_ip):
        pass


def main():
    parser = get_argparser()
    args = parser.parse_args()

    if len(sys.argv) == 3:
        base = sys.argv[0]
        sys.argv = []
        sys.argv.append(base)
        sr = ShowResources()

        if args.port:
            port_id = args.port
            MyPrint('show port:{} info.'.format(args.port))
            sr.list_port(port_id)
        if args.router:
            router_id = args.router
            MyPrint('show router:{} info.'.format(args.router))
            sr.list_router(router_id)
        if args.network:
            network_id = args.network
            MyPrint('show network:{} info.'.format(args.network))
            sr.list_network(network_id)
        if args.subnet:
            subnet_id = args.subnet
            MyPrint('show subnet:{} info.'.format(args.subnet))
            sr.list_subnet(subnet_id)
        if args.loadbalancer:
            loadbalancer_id = args.loadbalancer
            MyPrint('show load balancer:{} info.'.format(args.loadbalancer))
            sr.list_loadbalancer(loadbalancer_id)
    else:
        print ('error')


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        MyPrint('some error happend:{}'.format(ex))
