
from pprint import pprint
from collections import defaultdict
import yaml
import pynetbox
import requests
import subprocess
import re

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
# TODO after units tests move to for iteration
devices_list=list(filter(lambda i: (i.device_role.slug!='server'),nb.dcim.devices.all()))
rendered_dict=dict()
# for device in devices_list:
structured_config["router_bgp"]= devices_list[0].custom_fields['evpn_asn']

routing_processes=devices_list[0].config_context['local-routing']
structured_config["static_routes"]= devices_list[0].config_context['local-routing']['static-routes']['static'][0]

structured_config["service_routing_protocols_model"]= "multi-agent"

structured_config["ip_routing"]= True

structured_config["vlan_internal_order"]["allocation"]= "ascending"
structured_config["vlan_internal_order"]["range"]["beginning"]= 1006
structured_config["vlan_internal_order"]["range"]["ending"]= 1199

nameservers=devices_list[0].config_context['system']['nameservers']['servers']
nameservers.sort(key=lambda x: x.get('order'))
structured_config["name_server"]=nameservers

structured_config["spanning_tree"]["mode"] = "mstp"
structured_config["spanning_tree"]["mst_instances"]["0"]["priority"] = 4096

users = devices_list[0].config_context['system']['aaa']['authentication']['users']
for userdata in users:
    user= userdata["username"]
    structured_config["local_users"][user]["privilege"]= userdata['privilege']
    structured_config["local_users"][user]["sha512_password"]= userdata['password']
    structured_config["local_users"][user]["role"]= userdata['role']

structured_config["vrfs"] #TODO

structured_config["management_interfaces"]

structured_config["management_api_http"] #TODO

interface_list=list(nb.dcim.interfaces.filter(device=devices_list[0]))
# structured_config["ethernet_interfaces"]={}
for interface in interface_list:
    if not interface['display'].lower().startswith('management'):
        intf,device_id = interface,devices_list[0].id
        try:
            structured_config["ethernet_interfaces"][intf.name]['address']=list(
                filter(
                    lambda i: (i.assigned_object.name == intf.name and i.assigned_object.device.id == device_id),nb.ipam.ip_addresses.all()
                )
            )[0].address
        except IndexError as e:
            structured_config["ethernet_interfaces"][intf.name]['address']=None
        if not interface['display'].lower().startswith('loopback'):
            structured_config["ethernet_interfaces"][intf.name]['mode'] = "routed" if structured_config["ethernet_interfaces"][intf.name]['address'] is not None else "switched"
        structured_config["ethernet_interfaces"][intf.name]['description']=intf['description']
        structured_config["ethernet_interfaces"][intf.name]['mtu']=intf['mtu']


structured_config["loopback_interfaces"] #TODO

structured_config["vlan_interfaces"] #TODO

structured_config["vxlan_interface"] #TODO

structured_config["prefix_lists"] #TODO

structured_config["route_maps"] #TODO

structured_config["router_bfd"] #TODO

structured_config["vlans"] #TODO

structured_config["ip_igmp_snooping"]["globally_enabled"]= True

structured_config["ip_virtual_router_mac_address"] = "00:00:00:00:00:01"

structured_config["virtual_source_nat_vrfs"] #TODO






output=yaml.dump(ddict2dict(structured_config), allow_unicode=True, default_flow_style=False) 

print(output)