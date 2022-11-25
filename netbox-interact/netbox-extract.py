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
        respond=str(list(operator.attrgetter(api_attr)(nb).all())[0])
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
    elif api_attr == 'plugins.bgp.routing-policy':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == 'ipam.vlans':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond
    elif api_attr == 'ipam.vrfs':
        respond = operator.attrgetter(api_attr)(nb).get(**param)
        return respond

def build_peer_group(param: str):
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=param))
    for k in respond:
        if str(k) == 'ipv4-underlay-peers':
            password = list(filter(lambda x: str(k) in x,
                                   k.device.local_context_data['local-routing']['bgp']))[0][str(k)][0]['password']
            sub_ctx[str(k)] = dict(type=k.custom_field_data.BGP_address_family.lower(),
                                   password=password,
                                   maximum_routes=12000,
                                   send_community="all"
                                   )
        elif str(k) == 'evpn-overlay-peers':
            password = list(filter(lambda x: str(k) in x,
                                   k.device.local_context_data['local-routing']['bgp']))[0][str(k)][0]['password']
            sub_ctx[str(k)] = dict(type=k.custom_field_data.BGP_address_family.lower(),
                                   update_source=str(k.local_address.assigned_object),
                                   bfd=True,
                                   ebgp_multihop="",
                                   password=password,
                                   send_community="all",
                                   maximum_routes=12000
                                   )
    return sub_ctx


def build_address_family_ipv4(param: str):
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=param))
    for k in respond:
        if str(k.peer_group) == 'ipv4-underlay-peers':
            sub_ctx[str(k)] = dict(activate=True)
        elif str(k.peer_group) == 'evpn-overlay-peers':
            sub_ctx[str(k)] = dict(activate=False)
    return sub_ctx

def build_peer_neighbors(param: str):
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=param))
    for k in respond:
        sub_ctx[str(k.remote_address).split('/')[0]]={
            'peer_group': str(k.peer_group),
            'remote_as': str(k.remote_as),
            'description':f"{str(k.custom_fields['BGP_remote_device']['name'])}_{str(k.remote_address.assigned_object)}"
        }
    return sub_ctx

def build_address_family_evpn(param: str):
    sub_ctx = {}
    respond = get_object(nb, 'plugins.bgp.bgpsession', dict(device=param))
    for k in respond:
        if str(k.peer_group) == 'evpn-overlay-peers':
            sub_ctx[str(k.peer_group)]={'activate': True}
    return sub_ctx

def build_static_routes(param: object):
    sub_ctx = []
    respond = param.config_context['local-routing']['static-routes']['static']
    for k in respond:
        prefixe=dict(vrf='MGT',
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

def build_vrfs_lists(param: str):
    sub_ctx = {}
    respond = get_object(nb,'dcim.interfaces',dict(device=param, name='Vxlan1'))[0]
    vrf_list=respond.custom_fields['evpn_l3vpn']
    sub_ctx['MGMT']=dict(ip_routing=False)
    for data in vrf_list:
        sub_ctx[data['name']]=dict(tenant= 'TBD',ip_routing=True)
    return sub_ctx

def build_spanning_tree(param: object):
    sub_ctx = {}
    role=str(param.device_role).lower()
    if role == 'leaf':
        sub_ctx['mode']='rapid-pvst'
        sub_ctx['rapid_pvst_instances'] = {'1-4094': {'priority': 0}}
    elif role == 'spine':
        sub_ctx['mode'] = None
    return sub_ctx

def build_mgmt_api_http(param: object):
    sub_ctx = {}
    sub_ctx['enable_vrf']=dict(MGMT={},default={})
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
            addr=str(get_object(nb, 'ipam.ip-addresses',dict(device=str(param), interface=str(data))))
            is_lacp=data.lag
            if addr!='None':
                des=f'p2p_link_to_{str(data.connected_endpoints[0].device)}_{str(data.connected_endpoints[0])}'
                sub_ctx[str(data)]=dict(
                    peer=str(data.connected_endpoints[0].device),
                    peer_interface=str(data.connected_endpoints[0]),
                    peer_type=str(data.device.device_role),
                    description=des,
                    mtu=data.mtu,
                    type='routed',
                    shutdown=False if data.enabled==True else True,
                    ip_address=addr,
                    ztp='downstream'
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
                sub_ctx[str(data)] = dict(channel_group=dict(id=str(is_lacp).lower().split('po')[-1],
                                                             mode='active')
                                          )
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
    sub_ctx = {}
    role=str(param.device_role)
    if role=='leaf':
        respond=get_object(nb,'plugins.bgp.prefix-list',dict(name='pl-loopbacks-evpn-overlay'))
        loopback0_subnet=str(get_object(nb,"ipam.prefixes",dict(role="evpn-loopback")))
        loopback1_subnet = str(get_object(nb, "ipam.prefixes", dict(role="evpn-vtep")))
        sub_ctx[str(respond)]=dict(sequence_numbers={
            '10':{
                'action': f'permit {loopback0_subnet} eq 32'
            },
            '20':{
                'action': f'permit {loopback1_subnet} eq 32'
            }
                                                     }
        )
    else:
        sub_ctx=None
    return sub_ctx

def build_route_maps():
    # TODO https://github.com/k01ek/netbox-bgp/issues/112
    sub_ctx = {}
    respond=str(get_object(nb,'plugins.bgp.routing-policy',dict(name='rm-conn-2-bgp')))
    prefix_name=str(get_object(nb,'plugins.bgp.prefix-list',dict(name='pl-loopbacks-evpn-overlay')))
    sub_ctx[respond]=dict(sequence_numbers={
            '10':{
                'type': 'permit',
                'match':[
                    f"ip address prefix-list {prefix_name}"
                ]
            }
                                                     }
        )
    return sub_ctx

def build_bfd(param: object):
    sub_ctx=param.config_context['local-routing']['router-bfd']
    return sub_ctx

def build_vlans_list(param: str):
    sub_ctx={}
    vlandatabase=get_object(nb,'dcim.interfaces',dict(device=param,name='VLAN_DATABASE'))[0]
    for vlan in vlandatabase.tagged_vlans:
        sub_ctx[vlan.vid]=dict(name=str(vlan))
    return sub_ctx

def build_vxlan_interfaces(param: object):
    def build_vlans_list(param: list):
        sub_ctx={}
        for data in param:
            vlan=get_object(nb,'ipam.vlans',dict(id=data['id']))
            sub_ctx[str(vlan.vid)]=dict(vni=vlan.custom_fields['evpn_vni'])
        return sub_ctx

    def build_vrfs_list(param: list):
        sub_ctx={}
        for data in param:
            vrf=get_object(nb,'ipam.vrfs',dict(id=data['id']))
            sub_ctx[str(vrf)] = dict(vni=vrf.custom_fields['evpn_vni'])
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
                'vrf':build_vrfs_list(data.custom_fields['evpn_l3vpn'])
            }
        }
    return sub_ctx

def build_vlan_interfaces(param: str):
    sub_ctx = {}
    interfaces_list=get_object(nb,'dcim.interfaces',dict(device=param))
    for data in interfaces_list:
        try:
            if int(str(data)):
                addr=str(get_object(nb, 'ipam.ip-addresses',dict(device=str(param), interface=str(data))))
                intvlan=f'Vl{str(data)}'
                sub_ctx[intvlan]=dict(shutdown=False if data.enabled==True else True,ip_address=addr)
                if data.vrf is not None:
                    sub_ctx[intvlan]['vrf']=str(data.vrf)
        except ValueError as e:
            pass
    return sub_ctx

def build_name_server(param):
    sub_ctx = {'source':{'vrf':'default'},'nodes':[]}
    nameservers = param.config_context['system']['nameservers']['servers']
    for server in nameservers:
        sub_ctx['nodes'].append(server['address'])
    return sub_ctx

def build_ntp(param):
    sub_ctx={}
    sub_ctx=dict(local_interface={'name': 'TBD','vrf': 'default'},server=['tbd'])
    return sub_ctx

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
    print (str(device))
    role=str(device.device_role)
    structured_config["router_bgp"]['as'] = re.search(r"\d+", device.custom_fields['evpn_asn']['display']).group()
    structured_config["router_bgp"]['router_id'] = str(get_object(nb, 'ipam.ip-addresses',
                                                              dict(device=str(device),
                                                                   interface='Loopback0'))).split('/')[0]
    structured_config["router_bgp"]['address_family_evpn']['peer_groups'] = build_address_family_evpn(str(device))
    structured_config["router_bgp"]['bgp_defaults'] = ["no bgp default ipv4-unicast",
                                                       "distance bgp 20 200 200",
                                                       "graceful-restart restart-time 300",
                                                       "graceful-restart",
                                                       "maximum-paths 4 ecmp 4"
                                                       ]
    structured_config["router_bgp"]['peer_groups'] = build_peer_group(str(device))
    structured_config["router_bgp"]['address_family_ipv4']['peer_groups'] = build_address_family_ipv4(str(device))
    structured_config["router_bgp"]['neighbors'] = build_peer_neighbors(str(device))
    structured_config["static_routes"] = build_static_routes(device)
    structured_config["service_routing_protocols_model"] = "multi-agent"
    structured_config["ip_routing"] = True
    structured_config["local_users"]=build_local_users(device)
    structured_config["clock"]=device.site.time_zone
    structured_config["management_api_http"]=build_mgmt_api_http(device)
    structured_config["ethernet_interfaces"]= build_ethernet_interfaces(device)
    structured_config["loopback_interfaces"]=build_loopback_interfaces(device)
    structured_config["router_bfd"]=build_bfd(device)
    structured_config["ip_igmp_snooping"]["globally_enabled"] = True
    # structured_config["port_channel_interfaces"]=build_po_interfaces(device)
    # structured_config["aaa_authorization"]=build_aaa_authorization(device)
    structured_config["name_server"] = build_name_server(device)
    # structured_config["ip_domain_lookup"] =
    structured_config["ntp"] = build_ntp(device)
    # structured_config["management_interfaces"]
    structured_config["spanning_tree"] = build_spanning_tree(device)
    if role=='leaf':
        structured_config["router_bgp"]['redistribute_routes']['connected']['route_map'] = get_object(nb,
                                                                                                      'plugins.bgp.routing-policy',
                                                                                                      param={}
                                                                                                      )
        structured_config["vlan_internal_order"]["allocation"] = "ascending"
        structured_config["vlan_internal_order"]["range"]["beginning"] = 1006
        structured_config["vlan_internal_order"]["range"]["ending"] = 1199
        structured_config["vrfs"]=build_vrfs_lists(str(device))
        structured_config["prefix_lists"]=build_prefix_lists(device)
        structured_config["route_maps"]=build_route_maps()
        structured_config["vlans"]=build_vlans_list(str(device))
        structured_config["vxlan_interface"]=build_vxlan_interfaces(device)
        structured_config["vlan_interfaces"]=build_vlan_interfaces(device)
        structured_config["ip_virtual_router_mac_address"] = "00:00:00:00:00:01" #TODO
        # structured_config["virtual_source_nat_vrfs"]  # TODO

    output = yaml.dump(ddict2dict(structured_config), allow_unicode=True, default_flow_style=False)

    print(output)
