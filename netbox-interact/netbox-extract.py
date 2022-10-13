
from pprint import pprint
from collections import defaultdict
import yaml
import pynetbox
import requests

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


structured_config["router_bgp"]= {} #TODO

structured_config["static_routes"]= {} #TODO

structured_config["service_routing_protocols_model"]= "multi-agent"

structured_config["ip_routing"]= True

structured_config["vlan_internal_order"]["allocation"]= "ascending"
structured_config["vlan_internal_order"]["range"]["beginning"]= 1006
structured_config["vlan_internal_order"]["range"]["ending"]= 1199

structured_config["name_server"] #TODO

structured_config["spanning_tree"]["mode"] = "mstp"
structured_config["spanning_tree"]["mst_instances"]["0"]["priority"] = 4096

userscf= nb.extras.config_contexts.get(name='local-users').data  # TODO Replace with config context attached to the devices
users= userscf["system"]["aaa"]["authentication"]["users"]
for userdata in users:
    user= userdata["username"]
    structured_config["local_users"][user]["privilege"]= userdata['privilege']
    structured_config["local_users"][user]["sha512_password"]= userdata['password']
    structured_config["local_users"][user]["role"]= userdata['role']


structured_config["vrfs"] #TODO

structured_config["management_interfaces"] #TODO

structured_config["management_api_http"] #TODO

structured_config["ethernet_interfaces"] #TODO

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