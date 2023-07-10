# _*_ coding:utf-8 _*_

# test_list = []
# for i in range(0,2):
#     test_dict = {
#         'a': i
#     }
#     test_list.append(test_dict)
#
# for i in test_list:
#     a = i.get('a')
#     print a
#


from oslo_serialization import jsonutils
az_config_file = '/etc/neutron/f5_nfv_az.conf'
az_config_file_h = '/etc/neutron/f5h_nfv_az.conf'
node_ip_str = '10.0.170.151,10.0.170.156'
provider_name = 'nokia'
node_list_all = []
node_ip_list = []
if provider_name == 'nokia':
    config_file = az_config_file
elif provider_name == 'f5hardware':
    config_file = az_config_file_h
try:
    with open(config_file, 'rb') as f:
        _res = f.read()
    res = jsonutils.loads(_res)
    total_vlans = {}
    if not res:
        print total_vlans
    for vrsg in res['f5']:
        for nodes in vrsg['vrsg_node']:
            for node in nodes['nfv_node']:
                node_list = []
                node1 = node['node1']
                node2 = node['node2']
                node_list.append(node1)
                node_list.append(node2)
                node_list_all.append(node_list)
    print node_list_all
except Exception as e:
     print("got ERROR %s with init vlans config : %s" % (e, config_file))
for ips in node_ip_str.split(';'):
    node1 = ips.split(',')[0]
    node2 = ips.split(',')[1]
    node_ip_list.append(node1)
    node_ip_list.append(node2)

if node_ip_list in node_list_all:
    print("ok")
else:
    print("no")
print("==========driver_validate_f5_node_end==========")

