from pprint import pprint
from collections import defaultdict
import yaml
import pynetbox
import requests
import subprocess
import re
import operator


def get_netbox():
    """
    Return Netbox API handler

    Returns:
        pynetbox.API -- Netbox API handler
    """

    nburl = "http://127.0.0.1:8000/"
    NETBOX_TOKEN = "0123456789abcdef0123456789abcdef01234567"
    session = requests.Session()
    session.verify = False  # https://pynetbox.readthedocs.io/en/latest/advanced.html#ssl-verification
    nb = pynetbox.api(url=nburl, token=NETBOX_TOKEN, threading=True)
    nb.http_session = session

    return nb


def get_object(nb: object, api_attr: str, param: dict):
    if api_attr == 'ipam.ip-addresses':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == 'plugins.bgp.bgpsession':
        respond = list(operator.attrgetter(api_attr)(nb).filter(**param))
        return respond
    elif api_attr == 'plugins.bgp.routing-policy':
        respond=list(operator.attrgetter(api_attr)(nb).all())
        return respond
    elif api_attr == 'dcim.interfaces':
        respond=list(operator.attrgetter(api_attr)(nb).filter(**param))
        return respond
    elif api_attr == 'plugins.bgp.prefix-list':
        respond=operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == "ipam.prefixes":
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == 'ipam.vlans':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == 'ipam.vrfs':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == 'ipam.l2vpn-terminations':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == 'ipam.l2vpns':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond


def build_peer_group(param: object):
    def handle_route_maps(session: str,rm: dict):
        import_policies,export_policies=None,None
        for k,v in rm.items():
            for key,values in v.items():
                if 'session_in' in values:
                    import_policies=values['session_in'] if values['session_in'] == session else None
                if 'session_out' in values:
                    export_policies=values['session_out']if values['session_out'] == session else None
        return {"in":import_policies,"out":export_policies}
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=str(param)))
    for k in respond:
        policies=handle_route_maps(str(k),param.config_context['routing-policies']['route-maps'])
        export_policies,import_policies=policies['out'],policies['in']
        # export_policies = str(k.export_policies[0]) if k.export_policies else None
        # import_policies = str(k.import_policies[0]) if k.import_policies else None
        if str(k) == 'ipv4-underlay-peers':
            password = list(filter(lambda x: str(k) in x,
                                   k.device.local_context_data['local-routing']['bgp']))[0][str(k)][0]['password']
            sub_ctx[str(k)] = dict(type=k.custom_field_data.BGP_address_family.lower(),
                                   password=password,
                                   maximum_routes=12000,
                                   send_community="all",
                                   )

        elif str(k) == 'evpn-overlay-peers':
            password = list(filter(lambda x: str(k) in x,
                                   k.device.local_context_data['local-routing']['bgp']))[0][str(k)][0]['password']
            sub_ctx[str(k)] = dict(type=k.custom_field_data.BGP_address_family.lower(),
                                   update_source=str(k.local_address.assigned_object),
                                   bfd=True,
                                   ebgp_multihop=3,
                                   password=password,
                                   send_community="all",
                                   maximum_routes=0
                                   )

        elif str(k)=='ipv4-mlag-peering':
            sub_ctx[str(k)] = dict(type=k.custom_field_data.BGP_address_family.lower(),
                                   maximum_routes=12000,
                                   send_community="all",
                                   remote_as=build_bgp_as(str(k.remote_as))
                                   )
        if k.custom_fields['BGP_next_hop_unchanged'] is True:
            sub_ctx[str(k)]['next_hop_unchanged'] = True
        if k.custom_fields['BGP_next_hop_self'] is True:
            sub_ctx[str(k)]['BGP_next_hop_self']=True
        if export_policies:
            sub_ctx[str(k)]['route_map_out'] = export_policies
        if import_policies:
            sub_ctx[str(k)]['route_map_in'] = import_policies
    return sub_ctx


def build_address_family_ipv4(param: str):
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=param))
    for k in respond:
        # if str(k.peer_group) == 'ipv4-underlay-peers':
        #     sub_ctx[str(k)] = dict(activate=True)
        # elif str(k.peer_group) == 'evpn-overlay-peers':
        #     sub_ctx[str(k)] = dict(activate=False)
        if k.custom_fields['BGP_address_family']=='Ipv4':
            sub_ctx[str(k)] = dict(activate=True)
        else:
            sub_ctx[str(k)] = dict(activate=False)
    return sub_ctx

def build_peer_neighbors(param: str):
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=param))
    for k in respond:
        sub_ctx[str(k.remote_address).split('/')[0]]={
            'peer_group': str(k.peer_group),
            'remote_as':build_bgp_as((str(k.remote_as))),
            'description':f"{str(k.custom_fields['BGP_remote_device']['name'])}_{str(k.remote_address.assigned_object)}"
        }
    return sub_ctx

def build_address_family_evpn(param: str):
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=param))
    for k in respond:
        # if str(k.peer_group) == 'evpn-overlay-peers':
        #     sub_ctx[str(k.peer_group)]={'activate': True}
        if k.custom_fields['BGP_address_family']=='Evpn':
            sub_ctx[str(k.peer_group)] = {'activate': True}
    return sub_ctx

def build_static_routes(param: object):
    sub_ctx = []
    respond = param.config_context['local-routing']['static-routes']['static']
    for k in respond:
        prefixe=dict(vrf=k['vrf'],
                    destination_address_prefix=k['prefix'],
                    gateway=k['next-hops'][0]['next-hop'],
                    metric=k['next-hops'][0]['metric']
                    )
        sub_ctx.append(prefixe)
    return sub_ctx

def build_local_users(param: object):
    sub_ctx = {}
    respond = param.config_context['system']['aaa']['authentication']['users']
    for k in respond:
        key=k.pop('username')
        sub_ctx[key]=k
    return sub_ctx

def build_vrfs_lists(param: str,role: str):
    sub_ctx = {}
    # respond = get_object(nb,'dcim.interfaces',dict(device=param, name='Vxlan1'))[0]
    # vrf_list=respond.custom_fields['evpn_l3vpn']
    sub_ctx['MGMT']=dict(ip_routing=False)
    # for data in vrf_list:
    #     # sub_ctx[data['name']]=dict(tenant= 'TBD',ip_routing=True)
    #     sub_ctx[data['name']]=dict(ip_routing=True)
    if role == 'leaf':
        interface = str(get_object(nb, 'dcim.interfaces', dict(device=param, name='Loopback0'))[0])
        addr = str(get_object(nb,'ipam.ip-addresses',dict(interface=interface,device=param))).split('/')[0]
        vrfs_list=list(operator.attrgetter('ipam.vrfs')(nb).all())
        for data in vrfs_list:
            if data.rd:
                if addr==data.rd.split(':')[0]:
                    sub_ctx[data['name']] = dict(ip_routing=True)
    return sub_ctx

def build_spanning_tree(param: object):
    sub_ctx = {}
    role=str(param.device_role).lower()
    if role == 'leaf':
        sub_ctx['mode']='rapid-pvst'
        sub_ctx['rapid_pvst_instances'] = {'1-4094': {'priority': 0}}
        respond=get_object(nb,'dcim.interfaces',dict(device=str(param),name='VLAN_DATABASE'))[0]
        if device.virtual_chassis:
            is_mlag= ",".join([str(vlan.vid) for vlan in respond.tagged_vlans if 'mlag' in str(vlan).lower()])
            sub_ctx['no_spanning_tree_vlan']=is_mlag
    elif role == 'spine':
        sub_ctx['mode'] = None
    return sub_ctx

def build_mgmt_api_http(param: object):
    sub_ctx = {}
    if str(device.primary_ip.vrf):
        vrf=str(device.primary_ip.vrf)
        sub_ctx['enable_vrfs'] = {vrf:{},'default':{}}
        sub_ctx['enable_https']= True
    return sub_ctx

def build_ethernet_interfaces(param: object):
    def build_trunk_vlans(param: list):
        vlanid_list=list()
        list(filter(lambda x: vlanid_list.append(str(x.vid)), param))
        vlans=",".join(vlanid_list)
        return vlans

    sub_ctx = {}
    interface_list = get_object(nb,'dcim.interfaces',dict(device=str(param)))
    for data in interface_list:
        interface=str(data).lower()
        if interface.startswith('ethernet'):
            if not data.connected_endpoints:
                continue
            addr=get_object(nb, 'ipam.ip-addresses',dict(device=str(param), interface=str(data)))
            is_lacp=data.lag
            if addr is not None:
                des=f'p2p_link_to_{str(data.connected_endpoints[0].device)}_{str(data.connected_endpoints[0])}'
                sub_ctx[str(data)]=dict(
                    peer=str(data.connected_endpoints[0].device),
                    peer_interface=str(data.connected_endpoints[0]),
                    peer_type=str(data.device.device_role),
                    description=des,
                    mtu=data.mtu,
                    type='routed',
                    shutdown=False if data.enabled==True else True,
                    ip_address=str(addr)
                )
            else:
                des=f'p2p_link_to_{str(data.connected_endpoints[0].device)}_{str(data.connected_endpoints[0])}'
                mode,vlans='access',1
                if data.mode:
                    xmode=str(data.mode).lower()
                    if xmode=='tagged (all)':
                        mode='trunk'
                        vlandatabase = list(filter(lambda x: str(x) == 'VLAN_DATABASE', interface_list))[0].tagged_vlans
                        vlans = build_trunk_vlans(vlandatabase)
                    elif xmode=='tagged':
                        if len(data.tagged_vlans) == 1:
                            mode='access'
                            vlans=data.tagged_vlans[0].vid
                        elif len(data.tagged_vlans) > 1:
                            mode='trunk'
                            vlans = build_trunk_vlans(data.tagged_vlans)
                    elif xmode=='access':
                        mode='access'
                        vlans = data.untagged_vlan.vid
                sub_ctx[str(data)]=dict(
                    peer=str(data.connected_endpoints[0].device),
                    peer_interface=str(data.connected_endpoints[0]),
                    peer_type=str(data.device.device_role),
                    description=des,
                    type='switched',
                    shutdown=False if data.enabled==True else True,
                    mode=mode,
                    vlans=vlans,
                    spanning_tree_bpdufilter= False,
                    spanning_tree_bpduguard= False
               )
            if is_lacp:
                id = re.search(r"\d+", str(is_lacp)).group()
                sub_ctx[str(data)]['channel_group'] = dict(id=int(id), mode='active')

    return sub_ctx

def build_loopback_interfaces(param: object):
    sub_ctx = {}
    interface_list = get_object(nb,'dcim.interfaces',dict(device=str(param)))
    for data in interface_list:
        interface=str(data).lower()
        if interface.startswith('loopback'):
            addr=str(get_object(nb, 'ipam.ip-addresses',dict(device=str(param), interface=str(data))))
            sub_ctx[str(data)]=dict(
                description=data.description,
                shutdown=False if data.enabled==True else True,
                ip_address=addr,
            )
    return sub_ctx

def build_prefix_lists(param: object):
    # TODO https://github.com/k01ek/netbox-bgp/issues/112
    sub_ctx,prefixes_list=list(),list()
    for k,v in param.config_context['routing-policies']['route-maps'].items():
        for seq,data in v.items():
            if 'prefix_lists' in data:
                prefixes_list.extend(data['prefix_lists'])
    for prefix_list in prefixes_list:
        for k,v in prefix_list.items():
            sequence = {}
            for key,values in v.items():
                action=" ".join(values.values())
                new_dict={key:{'action':action}}
                sequence.update(new_dict)
            sub_ctx.append(dict(name=k,sequence_numbers=sequence))
    return sub_ctx

def build_route_maps(param):
    # TODO https://github.com/k01ek/netbox-bgp/issues/112
    sub_ctx = {}
    #device_rt=device.custom_fields['BGP_route_map']
    #respond=str(get_object(nb,'plugins.bgp.routing-policy',dict(name=rt['name']))[0])
    #prefix_name=str(get_object(nb,'plugins.bgp.prefix-list',dict(name='pl-loopbacks-evpn-overlay')))
    for k, v in param.config_context['routing-policies']['route-maps'].items():
        data=dict(sequence_numbers={})
        for key,values in v.items():
            if key.isdigit():
                sequence = list()
                data['sequence_numbers'][key]={}
                if 'description' in values:
                    data['sequence_numbers'][key].update(dict(description=values['description']))
                if 'prefix_lists' in values:
                    sequence.extend([list(prefix_name.keys()) for prefix_name in values['prefix_lists']][0])
                else:
                    sequence.extend([values['statements']])
                data['sequence_numbers'][key].update({'type':values['action'], values['clause']:sequence})
                sub_ctx[k]=data
    return sub_ctx

def build_bfd(param: object):
    sub_ctx=param.config_context['local-routing']['router-bfd']
    return sub_ctx

def build_vlans_list(param: str):
    sub_ctx={}
    vlandatabase=get_object(nb,'dcim.interfaces',dict(device=param,name='VLAN_DATABASE'))[0]
    mode=str(vlandatabase.mode).lower()
    if vlandatabase.tagged_vlans:
        for vlan in vlandatabase.tagged_vlans:
            sub_ctx[vlan.vid]=dict(name=str(vlan))
    elif mode == 'tagged (all)':
        vlans=list(operator.attrgetter('ipam.vlans')(nb).filter(**dict(group=str(param))))
        for vlan in vlans:
            sub_ctx[vlan.vid]=dict(name=str(vlan))
    return sub_ctx

def build_vxlan_interfaces(param: object):
    def build_vlans_list(param: list):
        sub_ctx={}
        if param:
            for data in param:
                vlan=get_object(nb,'ipam.vlans',dict(id=data['id']))
                sub_ctx[str(vlan.vid)]=dict(vni=vlan.custom_fields['evpn_vni'])
        else:
            sub_ctx=None
        return sub_ctx

    def build_vrfs_list(param: list):
        sub_ctx={}
        if param:
            for data in param:
                vrf=get_object(nb,'ipam.vrfs',dict(id=data['id']))
                sub_ctx[str(vrf)] = dict(vni=vrf.custom_fields['evpn_vni'])
        else:
            sub_ctx=None
        return sub_ctx

    sub_ctx = {}
    interface_list = get_object(nb,'dcim.interfaces',dict(device=str(param),name='Vxlan1'))
    for data in interface_list:
        sub_ctx[str(data)]={
            'description':data.description,
            'vxlan':{
                'source_interface': str(data.parent),
                'udp_port': data.custom_fields['vxlan_udp_port'],
                'vlans':build_vlans_list(data.custom_fields['evpn_l2vpn']),
                'vrfs':build_vrfs_list(data.custom_fields['evpn_l3vpn'])
            }
        }
        if device.virtual_chassis:
            sub_ctx[str(data)]['vxlan']['virtual_router_encapsulation_mac_address']='mlag-system-id'
    return sub_ctx

def build_vlan_interfaces(param: object):
    sub_ctx = {}
    respond=get_object(nb,'dcim.interfaces',dict(device=str(param)))
    for data in respond:
        try:
            if isinstance(int(str(data)),int):
                addr=str(get_object(nb, 'ipam.ip-addresses',dict(device=str(param),
                                                                 interface=str(data)
                                                                 )
                                    )
                         )
                intvlan=f'Vlan{str(data)}'
                sub_ctx[intvlan]=dict(shutdown=False if data.enabled==True else True,ip_address=addr)

                respond = get_object(nb, 'dcim.interfaces', dict(device=str(param), name='VLAN_DATABASE'))[0]
                if respond:
                    is_mlag =[str(vlan.vid) for vlan in respond.tagged_vlans if 'mlag' in str(vlan).lower()]
                    if int(str(data)) in is_mlag:
                        sub_ctx[intvlan]['mtu'] =data.mtu
                    if int(str(data))==4093:
                        sub_ctx[intvlan]['no_autostate'] = True
                if data.vrf is not None:
                    sub_ctx[intvlan]['vrf']=str(data.vrf)
        except ValueError as e:
            pass
    return sub_ctx

def build_management_interfaces(device:object):
    sub_ctx={}
    addr=str(device.primary_ip)
    interface=str(operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(device=str(device),address=addr)).assigned_object)
    vrf=str(operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(device=str(device),address=addr)).vrf)
    sub_ctx[interface]=dict(shutdown=False,ip_address=addr,description="oob",gateway='172.100.100.1')
    if vrf:
        sub_ctx[interface]['vrf']=vrf
    return sub_ctx

def build_name_server(param:object):
    # pattern = re.compile(r"\d+.\d+.\d+.\d+")
    # cat = subprocess.Popen(["cat", "/etc/resolv.conf"], stdout=subprocess.PIPE)
    # grep = subprocess.Popen(["grep", "nameserver"], stdin=cat.stdout, stdout=subprocess.PIPE, encoding='utf-8')
    # result = [pattern.findall(line)[0] for line in list(grep.stdout)]
    sub_ctx = {'source':{'vrf':'default'},'nodes':[]}
    nameservers = param.config_context['system']['nameservers']['servers']
    for server in nameservers:
        sub_ctx['nodes'].append(server['address'])
    return sub_ctx

def build_ntp(param):
    sub_ctx={}
    sub_ctx=dict(local_interface={'name': 'TBD','vrf': 'default'},server=['tbd'])
    return sub_ctx

def generate_file(structured_config: defaultdict,device:str):
    import os
    file = f'clab-evpnlab-{device}.yml'
    folder = '/home/ec2-user/evpn-cicd-arista-containerlab/ansible-tinylab/intended/structured_configs/'
    if os.path.exists(folder) is True:
        target = folder+file
        with open(target,'w') as data:
            yaml_file = yaml.dump(ddict2dict(structured_config),data,allow_unicode=True,default_flow_style=False)
        if os.path.exists(target):
            print (f"{file} has been created")

def build_ip_virtual_router_mac_addr(device: object):
    interface=get_object(nb,'dcim.interfaces',dict(device=str(device),name='ip virtual-router mac-address'))
    mac=interface[0].mac_address if interface[0].mac_address else None
    #if mac:
    return mac
def build_redistribute_routes(device):
    sub_ctx=[]
    # respond=get_object(nb, 'plugins.bgp.routing-policy', param={})
    # for data in respond:
    #     sub_ctx={data.custom_fields['BGP_redistribute_ipv4']:{'route_map':[]}}
    respond=device.config_context['local-routing']['bgp']
    for k in respond:
        if 'parameters' in k:
            sub_ctx.append(k['parameters']['redistribute'])
    return sub_ctx

def build_l2vpns(param: object):
    sub_ctx=list()
    respond=get_object(nb,'dcim.interfaces',dict(device=str(param),name='Vxlan1'))[0]
    vlans=respond['custom_fields']['evpn_l2vpn']
    if vlans:
        for vlan in vlans:
            vlan_l2vpn_termination=get_object(nb,'ipam.vlans',dict(id=vlan['id']))['l2vpn_termination']
            l2term=get_object(nb,'ipam.l2vpn-terminations',dict(id=vlan_l2vpn_termination['id']))
            l2vpn=get_object(nb,'ipam.l2vpns',dict(id=l2term.l2vpn.id))
            sub_ctx.append({
                'id':l2term.assigned_object.vid,
                'rd':l2vpn.custom_fields['rd_vlan'],
                'route_targets':{'import':[str(x) for x in l2vpn.import_targets],
                                 'export':[str(x) for x in l2vpn.export_targets]
                                 },
                'redistribute_routes':[l2vpn.custom_fields['redistribute_l2vpn']]
            }
            )
    else:
        sub_ctx=None
    return sub_ctx

def build_l3vpns(param: object):
    def create_route_targets(data: object):
        sub_ctx={'export':{},'import':{}}
        if data.import_targets:
            for route_target in data.import_targets:
                address_family=route_target.custom_fields['address_family']
                sub_ctx['import'][address_family]=[]
            for route_target in data.import_targets:
                iaddress_family=route_target.custom_fields['address_family']
                sub_ctx['import'][iaddress_family].append(str(route_target))
        if data.export_targets:
            for route_target in data.export_targets:
                address_family=route_target.custom_fields['address_family']
                sub_ctx['export'][address_family]=[]
            for route_target in data.export_targets:
                eaddress_family=route_target.custom_fields['address_family']
                sub_ctx['export'][eaddress_family].append(str(route_target))
        return sub_ctx
    sub_ctx=list()
    respond=get_object(nb,'dcim.interfaces',dict(device=str(param),name='Vxlan1'))[0]
    vrfs=respond['custom_fields']['evpn_l3vpn']
    if vrfs:
        for vrf in vrfs:
            data=get_object(nb,'ipam.vrfs',dict(id=vrf['id']))
            sub_ctx.append(
                {
                'name':str(data),
                'rd':data.rd,
                'route_targets':create_route_targets(data),
                'router_id':str(get_object(nb, 'ipam.ip-addresses',dict(device=str(device),
                                                                        interface='Loopback0'))).split('/')[0],
                'redistribute_routes':data.custom_fields['redistribute_l3vpn']
            }
            )
    else:
        sub_ctx=None
    return sub_ctx

def build_po_interfaces(device: object):
    def build_trunk_vlans(param: list):
        vlanid_list=list()
        list(filter(lambda x: vlanid_list.append(str(x.vid)), param))
        vlans=",".join(vlanid_list)
        return vlans

    sub_ctx={}
    respond=(get_object(nb,'dcim.interfaces',dict(device=str(device))))
    Po_list=[intf for intf in respond if intf.type.value=='lag']
    for po in Po_list:
        sub_ctx[str(po)]=dict(description=po.description,shutdown=False if po.enabled==True else True,)
        addr = str(get_object(nb, 'ipam.ip-addresses', dict(device=str(device), interface=str(po))))
        if not addr:
            sub_ctx[str(po)]['type'] = 'routed'
            sub_ctx[str(po)]['ip_address']=addr
        elif po.tagged_vlans:
            sub_ctx[str(po)]['type']='switched'
            sub_ctx[str(po)]['vlans']=build_trunk_vlans(po.tagged_vlans)
            sub_ctx[str(po)]['mode']='trunk' if str(po.mode).lower()=='tagged' else None
    return sub_ctx

def build_mlag_conf(device: object):
    sub_ctx=dict()
    respond=get_object(nb,'dcim.interfaces',dict(device=str(device)))
    intfs=list()
    for x in respond:
        for d in x.tagged_vlans:
            if d.vid == 4094:
                intfs.append(x)
    if intfs:
        dev_neig=[x.connected_endpoints[0].device for x in intfs if x.connected_endpoints][0]
        intf=[x for x in intfs if x.count_ipaddresses==1][0]
        addr=str(get_object(nb,'ipam.ip-addresses',dict(device=str(dev_neig),interface=str(intf)))).split('/')[0]
        peer_link=[str(x.lag) for x in intfs if  x.lag
                   and x.count_ipaddresses==0 and str(x.connected_endpoints[0].device.device_role)=='leaf'][0]
        sub_ctx['domain_id']=str(device.virtual_chassis.domain)
        sub_ctx['local_interface']=f"Vlan{intf}"
        sub_ctx['peer_address']=addr
        sub_ctx['peer_link']=peer_link
        sub_ctx['reload_delay_mlag'] = 300
        sub_ctx['reload_delay_non_mlag'] = 300
        return sub_ctx

def build_bgp_as(asn :str):
    display = re.search(r"\d+\.\d", asn).group().split()[0]
    return display

def build_bgp_router_id(device: object):
    respond=str(get_object(nb, 'ipam.ip-addresses',dict(device=str(device),interface='Loopback0'))).split('/')[0]
    return respond

nb = get_netbox()

def ddict():
    return defaultdict(ddict)


def ddict2dict(d):
    for k, v in d.items():
        if isinstance(v, dict):
            d[k] = ddict2dict(v)
    return dict(d)



''' Get all devices object from netbox where device_role is not server value '''
devices_list = list(operator.attrgetter('dcim.devices')(nb).filter(**dict(role='leaf'))) + list(
    operator.attrgetter('dcim.devices')(nb).filter(**dict(role='spine')))
# devices_list = [operator.attrgetter('dcim.devices')(nb).get(**dict(name='leaf2'))]
for device in devices_list:
    structured_config = ddict()
    role=str(device.device_role)
    structured_config["router_bgp"]['as'] = build_bgp_as(device.custom_fields['evpn_asn']['display'])
    structured_config["router_bgp"]['router_id'] = build_bgp_router_id(device)
    structured_config["router_bgp"]['address_family_evpn']['peer_groups'] = build_address_family_evpn(str(device))
    structured_config["router_bgp"]['bgp_defaults'] = ["no bgp default ipv4-unicast",
                                                       "distance bgp 20 200 200",
                                                       "graceful-restart restart-time 300",
                                                       "graceful-restart",
                                                       "maximum-paths 4 ecmp 4",
                                                       "bgp asn notation asdot"
                                                       ]
    structured_config["router_bgp"]['peer_groups'] = build_peer_group(device)
    structured_config["router_bgp"]['address_family_ipv4']['peer_groups'] = build_address_family_ipv4(str(device))
    structured_config["router_bgp"]['neighbors'] = build_peer_neighbors(str(device))
    structured_config["router_bgp"]['redistribute_routes']= build_redistribute_routes(device)
    structured_config["static_routes"] = build_static_routes(device)
    structured_config["service_routing_protocols_model"] = "multi-agent"
    structured_config["ip_routing"] = True
    structured_config["local_users"]=build_local_users(device)
    structured_config["clock"]=device.site.time_zone
    structured_config["ethernet_interfaces"]= build_ethernet_interfaces(device)
    structured_config["loopback_interfaces"]=build_loopback_interfaces(device)
    structured_config["router_bfd"]=build_bfd(device)
    structured_config["ip_igmp_snooping"]["globally_enabled"] = True
    structured_config["port_channel_interfaces"]=build_po_interfaces(device)
    # structured_config["aaa_authorization"]=build_aaa_authorization(device)
    # structured_config["name_server"] = build_name_server(device)
    # structured_config["ip_domain_lookup"] =
    # structured_config["ntp"] = build_ntp(device)
    structured_config["management_interfaces"]=build_management_interfaces(device)
    structured_config["management_api_http"]=build_mgmt_api_http(device)
    structured_config["spanning_tree"] = build_spanning_tree(device)
    structured_config["vrfs"] = build_vrfs_lists(str(device),role)
    structured_config["prefix_lists"] = build_prefix_lists(device)
    structured_config["route_maps"] = build_route_maps(device)
    if role=='leaf':
        structured_config["vlan_internal_order"]["allocation"] = "ascending"
        structured_config["vlan_internal_order"]["range"]["beginning"] = 1006
        structured_config["vlan_internal_order"]["range"]["ending"] = 1199
        structured_config["vlans"]=build_vlans_list(str(device))
        structured_config["vxlan_interface"]=build_vxlan_interfaces(device)
        structured_config["vlan_interfaces"]=build_vlan_interfaces(device)
        structured_config["router_bgp"]['vlans']= build_l2vpns(device)
        structured_config["router_bgp"]['vrfs']= build_l3vpns(device)
        if device.virtual_chassis:
            structured_config["mlag_configuration"]=build_mlag_conf(device)
            structured_config["ip_virtual_router_mac_address"] = build_ip_virtual_router_mac_addr(device)
        # structured_config["virtual_source_nat_vrfs"]  # TODO
    generate_file(structured_config, str(device))