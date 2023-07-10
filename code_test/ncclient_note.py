# _*_ coding:utf-8 _*_

# 导包，从ncclient中导入manager
from ncclient import manager

# 常用方法
# 连接设备
nc = manager.connect(host=host,                       # 设备IP
                     port=port,                       # 设备端口
                     username=usernam,                # 用户名
                     password=password,               # 密码
                     hostkey_verify=False)            # ssh验证问题

print(nc.connected)                                   # 输出为“True”表示连接成功；"False"表示连接失败

# get_config 获取设备上的配置
reply = nc.get_config(source='candidate')             # source：指定需要查询的数据库名称（running:正在运行的数据库；candidate：备选数据库）

# edit_config 向设备下发配置
reply = nc.edit_config(target='candidate', config=fonfig_xml)   # target：指定需要配置的数据库，一般是对candidate数据库下发配置；config：配置的xml文件

# commit 将数据库配置文件提交，转化为设备新的当前运行的配置
reply = nc.commit()                                   # 若edit_config的target是‘candidate’数据库，则需要进行commit，才能在设备上运行；
                                                      # 若edit_config的target是‘running’数据库，不需要进行commit，会立即在设备上运行；

# discard_changes() 丢弃任何未commit的更改配置
reply = nc.discard_changes()                          # 若edit_config的target是‘candidate’数据库，且未进行commit，则可以丢弃所有未commit的配置


# Django项目中使用字典组装template_xml文件
# 导入loader
from django.template import loader

# 入参字典
param_dict = {
            'ne_ip': '',
            'vprn_id': '',
            'au': '',
            'rd': ''
        }

# 通过loader载入模板文件
template_xml = loader.get_template('xxx/xxx.xml')  # xxx/xxx.xml为template文件路径

# 渲染模板
template = template_xml.render(param_dict)         # 组装xml

# 下发配置
reply = nc.edit_config(target='candidate', config=template)
