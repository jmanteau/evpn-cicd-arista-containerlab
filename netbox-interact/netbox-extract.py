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
        return str(respond)
    elif api_attr == 'plugins.bgp.bgpsession':
        respond = list(operator.attrgetter(api_attr)(nb).filter(**param))
        return respond
    elif api_attr == 'plugins.bgp.routing-policy':
        respond=str(list(operator.attrgetter(api_attr)(nb).all())[0])
        return respond
    elif api_attr == 'dcim.interfaces':
        respond=list(operator.attrgetter(api_attr)(nb).filter(**param))
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
                                   maximum_routes=0
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
    sub_ctx = {}
    interface_list = get_object(nb,'dcim.interfaces',dict(device=str(param)))
    for data in interface_list:
        interface=str(data).lower()
        if interface.startswith('ethernet'):
            addr=get_object(nb, 'ipam.ip-addresses',dict(device=str(param), interface=str(data)))
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
                sub_ctx[str(data)]=dict(
                    peer=str(data.connected_endpoints[0].device),
                    peer_interface=str(data.connected_endpoints[0]),
                    peer_type=str(data.device.device_role),
                    description=des,
                    type='switched',
                    shutdown=False if data.enabled==True else True,
                    mode='trunk',
                    vlans=[],
                    spanning_tree_bpdufilter= False,
                    spanning_tree_bpduguard= False,
                    channel_group=dict(id=2,mode='active')
               )
    return sub_ctx

def build_loopback_interfaces(param: object):
    sub_ctx = {}
    interface_list = get_object(nb,'dcim.interfaces',dict(device=str(param)))
    for data in interface_list:
        interface=str(data).lower()
        if interface.startswith('loopback'):
            addr=get_object(nb, 'ipam.ip-addresses',dict(device=str(param), interface=str(data)))
            sub_ctx[str(data)]=dict(
                description=data.description,
                shutdown=False if data.enabled==True else True,
                ip_address=addr,
            )
    return sub_ctx
nb = get_netbox()


def ddict():
    return defaultdict(ddict)


def ddict2dict(d):
    for k, v in d.items():
        if isinstance(v, dict):
            d[k] = ddict2dict(v)
    return dict(d)


structured_config = ddict()

''' Get all devices object from netbox where device_role is not server value '''
devices_list = list(operator.attrgetter('dcim.devices')(nb).filter(**dict(role='leaf'))) + list(
    operator.attrgetter('dcim.devices')(nb).filter(**dict(role='spine')))
rendered_dict = dict()
# TODO after units tests move to 'for' iteration
# for device in devices_list:
structured_config["router_bgp"]['as'] = re.search(r"\d+", devices_list[0].custom_fields['evpn_asn']['display']).group()
structured_config["router_bgp"]['router_id'] = get_object(nb, 'ipam.ip-addresses',
                                                          dict(device=str(devices_list[0]),
                                                               interface='Loopback0')).split('/')[0]
structured_config["router_bgp"]['bgp_defaults'] = ["no bgp default ipv4-unicast",
                                                   "distance bgp 20 200 200",
                                                   "graceful-restart restart-time 300",
                                                   "graceful-restart",
                                                   "maximum-paths 4 ecmp 4"
                                                   ]
structured_config["router_bgp"]['peer_groups'] = build_peer_group(str(devices_list[0]))
structured_config["router_bgp"]['address_family_ipv4']['peer_groups'] = build_address_family_ipv4(str(devices_list[0]))
structured_config["router_bgp"]['redistribute_routes']['connected']['route_map']=get_object(nb,
                                                                                            'plugins.bgp.routing-policy',
                                                                                            param={}
                                                                                            )
structured_config["router_bgp"]['neighbors'] = build_peer_neighbors(str(devices_list[0]))
structured_config["router_bgp"]['address_family_evpn']['peer_groups'] = build_address_family_evpn(str(devices_list[0]))
structured_config["static_routes"] = build_static_routes(devices_list[0])
structured_config["service_routing_protocols_model"] = "multi-agent"
structured_config["ip_routing"] = True
structured_config["vlan_internal_order"]["allocation"] = "ascending"
structured_config["vlan_internal_order"]["range"]["beginning"] = 1006
structured_config["vlan_internal_order"]["range"]["ending"] = 1199
structured_config["spanning_tree"] = build_spanning_tree(devices_list[0])
structured_config["local_users"]=build_local_users(devices_list[0])
structured_config["clock"]=devices_list[0].site.time_zone
# structured_config["vrfs"]  # TODO
structured_config["management_api_http"]=build_mgmt_api_http(devices_list[0])
structured_config["ethernet_interfaces"]= build_ethernet_interfaces(devices_list[0])
structured_config["loopback_interfaces"]=build_loopback_interfaces(devices_list[0])
structured_config["prefix_lists"]='todo'
# nameservers = devices_list[0].config_context['system']['nameservers']['servers']
# nameservers.sort(key=lambda x: x.get('order'))
# structured_config["name_server"] = nameservers

#
#

#
# structured_config["management_interfaces"]
#
#

#
#
# structured_config["vlan_interfaces"]  # TODO
#
# structured_config["vxlan_interface"]  # TODO
#
#
# structured_config["route_maps"]  # TODO
#
# structured_config["router_bfd"]  # TODO
#
# structured_config["vlans"]  # TODO
#
# structured_config["ip_igmp_snooping"]["globally_enabled"] = True
#
# structured_config["ip_virtual_router_mac_address"] = "00:00:00:00:00:01"
#
# structured_config["virtual_source_nat_vrfs"]  # TODO

output = yaml.dump(ddict2dict(structured_config), allow_unicode=True, default_flow_style=False)

print(output)
