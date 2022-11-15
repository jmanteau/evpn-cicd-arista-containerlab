#!/usr/bin/env python3
import pynetbox
import requests
import urllib3
import yaml
import json
from collections import defaultdict
import re
from pathlib import Path
from ruamel.yaml import YAML
from pynetbox.core.query import RequestError
import json
import glob
import os.path
import operator

urllib3.disable_warnings()


def manual_call():

    HEADERS = {
        "Content-Type": "application/json;",
        "Authorization": f"Token {nb.token}",
    }
    ans = nb.http_session.get(f"{nb.base_url}/extras/custom-fields/6/", headers=HEADERS)
    ans.json()


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

HEADERS = {"Content-Type": "application/json;", "Authorization": f"Token {nb.token}"}


def provision_config_context():
    """
    Provision the config context based on the json file present in the config-contexts folder.
    Uses the json filename as config context name. Applies it to the roles leaf and spine.
    Limitation: Do not update the Config context if the content of the json file change.
    """

    for file in glob.glob("config-contexts/*.json"):
        with open(file) as json_data:
            ccdata = json.load(json_data)

            ccname = os.path.basename(file).split(".")[0]
            get_or_create(
                nb.extras.config_contexts,
                search="name",
                name=ccname,
                data=ccdata,
                roles=[role_leaf.id, role_spine.id],
            )


def create_devices(evpnlab):

    STATUS = {
        x["display_name"].lower(): i
        for i, x in enumerate(nb.dcim.devices.choices()["status"])
    }

    # Create Device with minimum: role, device type , site
    for node, kind in evpnlab["topology"]["nodes"].items():
        if node.startswith("h"):
            dev_type = devicetype_alpine
            dev_role = role_server
        elif node.startswith("leaf"):
            dev_type = devicetype_ceos
            dev_role = role_leaf
        elif node.startswith("spine"):
            dev_type = devicetype_ceos
            dev_role = role_spine

        newdev = get_or_create(
            nb.dcim.devices,
            search="name",
            name=node,
            site=site_palette.id,
            device_type=dev_type.id,
            device_role=dev_role.id,
        )
        if newdev.status is None:
            newdev.status = "active"
            newdev.tenant = tenant_rainbow
            newdev.save()

    # # Create interface. Add IPs

    # mapping = {
    #     "Interface LAN": "LAN1",
    #     "Interface VIP": "VIP",
    #     "Interface HA": "HA",
    #     "Interface MGMT": "MGMT",
    # }
    # intfs = [
    #     {"name": v, "form_factor": 0, "description": k, "device": newdev.id}
    #     for k, v in mapping.items()
    # ]
    # for k, v in mapping.items():
    #     intf_data = {
    #         "name": v,
    #         "type": "1000base-t",
    #         "description": k,
    #         "device": newdev.id,
    #     }
    #     print(intf_data)
    #     intf = nb.dcim.interfaces.create(intf_data)
    #     if k in dev:
    #         if dev[k] and not str(dev[k]).startswith("na"):
    #             if "VIP" in k:
    #                 ip_data = {
    #                     "address": f"{dev[k]}/32",
    #                     "interface": intf.id,
    #                     "role": "vip",
    #                 }

    #             else:
    #                 ip_data = {"address": f"{dev[k]}/32", "interface": intf.id}
    #             print(ip_data)
    #             intip = nb.ipam.ip_addresses.create(ip_data)

    #             # Assign Primary IP to device
    #             # At this list last, override LAN1 if IP is set
    #             if k == "Interface MGMT":
    #                 if dev[k]:
    #                     newdev.primary_ip4 = {"address": intip.address}
    #                     newdev.save()

    #             if k == "Interface LAN":
    #                 if dev[k]:
    #                     newdev.primary_ip4 = {"address": intip.address}
    #                     newdev.save()


with open("../evpnlab-tiny.yml") as fh:
    evpnlab = yaml.load(fh, Loader=yaml.FullLoader)


def get_or_create(concept, search="slug", **kwargs):
    """Get or Create a Netbox object

    Args:
        concept: the netbox class handler (nb.dcim.manufacturers, nb.tenancy.tenants, etc) to be used
        kwargs: the argument to pass for the object creation. Must contains the slug (for the get)

    Returns:
        object: The getted or created Netbox object
    """
    print(kwargs)
    if search == "slug":
        nb_object = (
            tmp
            if (tmp := concept.get(slug=kwargs[search])) is not None
            else concept.create(**kwargs)
        )
    elif search == "prefix":
        nb_object = (
            tmp
            if (tmp := concept.get(prefix=kwargs[search])) is not None
            else concept.create(**kwargs)
        )
    elif search == "name":
        nb_object = (
            tmp
            if (tmp := concept.get(name=kwargs[search])) is not None
            else concept.create(**kwargs)
        )
    elif search == "intf":
        nb_object = (
            tmp
            if (tmp := concept.get(name=kwargs["name"], device_id=kwargs["device"]))
            is not None
            else concept.create(kwargs)
        )
    elif search == "vlan":
        nb_object = (
            tmp
            if (tmp := concept.get(vid=kwargs["vid"])) is not None
            else concept.create(kwargs)
        )
    elif search == "rd":
        nb_object = (
            tmp
            if (tmp := concept.get(rd=kwargs["rd"])) is not None
            else concept.create(kwargs)
        )
    return nb_object


def provision_orga():

    global tenant_rainbow
    tenant_rainbow = get_or_create(nb.tenancy.tenants, name="Rainbow", slug="rainbow")

    global site_palette
    site_palette = get_or_create(nb.dcim.sites, name="Palette", slug="palette")
    site_palette.tenant = tenant_rainbow
    site_palette.save()

    global role_spine
    role_spine = get_or_create(nb.dcim.device_roles, name="spine", slug="spine")
    global role_leaf
    role_leaf = get_or_create(nb.dcim.device_roles, name="leaf", slug="leaf")
    global role_server
    role_server = get_or_create(nb.dcim.device_roles, name="server", slug="server")
    global manuf_arista
    manuf_arista = get_or_create(nb.dcim.manufacturers, name="Arista", slug="arista")
    global manuf_linux
    manuf_linux = get_or_create(nb.dcim.manufacturers, name="Linux", slug="linux")


def provision_devices():

    process_yaml("devicetype-ceos-lab.yml")
    process_yaml("devicetype-alpine.yml")

    global devicetype_ceos
    devicetype_ceos = get_or_create(
        nb.dcim.device_types,
        model="cEOS-LAB",
        manufacturer=manuf_arista.id,
        slug="ceos-lab",
    )
    global devicetype_alpine
    devicetype_alpine = get_or_create(
        nb.dcim.device_types, model="Alpine", manufacturer=manuf_linux.id, slug="alpine"
    )

    # TODO import device library -> Manual creation for the moment
    # https://gist.github.com/AdamEldred/f83105446c6ceb1b13dccad661ade428

    create_devices(evpnlab)
    global spines
    spines = [x for x in nb.dcim.devices.filter(role="spine")]
    global leafs
    leafs = [x for x in nb.dcim.devices.filter(role="leaf")]


def provision_customfields():

    # cf_asn = get_or_create(
    #     nb.extras.custom_fields,
    #     search="name",
    #     name="evpn_asn",
    #     content_types=["dcim.device"],
    #     type="integer",
    #     label="EVPN ASN"
    # )
    cf_asn = get_or_create(
        nb.extras.custom_fields,
        search="name",
        name="evpn_asn",
        content_types=["dcim.device"],
        type="object",
        object_type="ipam.asn",
        label="EVPN ASN"
    )

    # Create Custom Fields VNI on VLAN / VRF
    cf_vni = get_or_create(
        nb.extras.custom_fields,
        search="name",
        name="evpn_vni",
        content_types=["ipam.vlan", "ipam.vrf"],
        type="integer",
        label="EVPN VNI"
    )

    cf_l2evpn = get_or_create(
        nb.extras.custom_fields,
        search="name",
        name="evpn_l2vpn",
        content_types=["dcim.interface"],
        type="multiobject",
        object_type="ipam.vlan",
        label="EVPN L2VPN"
    )

    cf_l3evpn = get_or_create(
        nb.extras.custom_fields,
        search="name",
        name="evpn_l3vpn",
        content_types=["dcim.interface"],
        type="multiobject",
        object_type="ipam.vrf",
        label="EVPN L3VPN"
    )

    cf_udp_port = get_or_create(
        nb.extras.custom_fields,
        search="name",
        name="vxlan_udp_port",
        content_types=["dcim.interface"],
        type="integer",
        label="VXLAN UDP-PORT"
    )


def provision_asns():

    def assign_spine_asn(grp: list,spine_asn: object) -> None:
        for device in grp:
            if device.custom_fields.get("evpn_asn") is None:
                device.custom_fields.update(dict(evpn_asn=spine_asn.id))
                device.save()

    #### ASN Creation and assignment ###

    leafrange = [*range(65100, 65199)]
    spinerange = [*range(65001, 65099)]
    rir = operator.attrgetter("ipam.rirs")(nb).get(**{'name': 'private-subnets'})
    for device in leafs:
        # if (asn := device.custom_fields.get("evpn_asn")) is not None:
        #     # print(f"leaf {asn}")
        #     leafrange.remove(asn)
        if device.custom_fields.get("evpn_asn") is not None:
            asn=device.custom_fields.get("evpn_asn")['asn']
            leafrange.remove(asn)

    for device in spines:
        # if (asn := device.custom_fields.get("evpn_asn")) is not None and asn not in spinerange:
        #     # print(f"spine {asn}")
        #     spinerange.remove(asn)
        if device.custom_fields.get("evpn_asn") is not None:
            asn=device.custom_fields.get("evpn_asn")['asn']
            if asn in spinerange:
                spinerange.remove(asn)

    for device in leafs:
        if device.custom_fields.get("evpn_asn") is None:
            xasn=leafrange.pop(0)
            operator.attrgetter('ipam.asns')(nb).create(dict(asn=xasn,rir=rir.id,description=str(device)))
            asn=operator.attrgetter("ipam.asns")(nb).get(**dict(asn=xasn))
            device.custom_fields.update(dict(evpn_asn=asn.id))
            device.save()

    # for device in spines:
    #     if device.custom_fields.get("evpn_asn") is None:
    #         device.custom_fields.update({"evpn_asn": spinerange.pop(0)})
    #         device.save()
    ##### merge spine per site for apply the same asn ####
    spine_grp=list()
    for device in spines:
        if device.custom_fields['evpn_asn'] is None:
            site=str(device.site)
            spine_grp.append(list(filter(lambda x: str(x.site) == site,spines)))
    import itertools
    spine_grp=[spine_grp for spine_grp,_ in itertools.groupby(spine_grp)]
    if spine_grp:
        for grp in spine_grp:
            spine_asn=spinerange.pop(0)
            operator.attrgetter('ipam.asns')(nb).create(dict(asn=spine_asn,rir=rir.id))
            asn = operator.attrgetter("ipam.asns")(nb).get(**dict(asn=spine_asn))
            assign_spine_asn(grp,asn)

    #### END OF ASN Creation and assignment ###

def provision_interfaces():
    evpn_loopback = get_or_create(
        nb.ipam.roles, name="evpn-loopback", slug="evpn-loopback"
    )
    evpn_underlay = get_or_create(
        nb.ipam.roles, name="evpn-underlay", slug="evpn-underlay"
    )
    global evpn_vtep
    evpn_vtep = get_or_create(nb.ipam.roles, name="evpn-vtep", slug="evpn-vtep")
    global role_data
    role_data = get_or_create(nb.ipam.roles, name="data", slug="data")

    prefix_loopback = get_or_create(
        nb.ipam.prefixes,
        search="prefix",
        prefix="192.168.255.0/24",
        is_pool=True,
        site=site_palette.id,
        role=evpn_loopback.id,
        tenant=tenant_rainbow.id,
    )
    prefix_underlay = get_or_create(
        nb.ipam.prefixes,
        search="prefix",
        prefix="172.31.255.0/24",
        is_pool=True,
        site=site_palette.id,
        role=evpn_underlay.id,
        tenant=tenant_rainbow.id,
    )
    prefix_vtep = get_or_create(
        nb.ipam.prefixes,
        search="prefix",
        prefix="192.168.254.0/24",
        is_pool=True,
        site=site_palette.id,
        role=evpn_vtep.id,
        tenant=tenant_rainbow.id,
    )


    def get_interface_data(raw_device_name, raw_intf_name):

        device = nb.dcim.devices.get(name=raw_device_name)
        if str(device.device_type) == "cEOS-LAB":
            # replace between containerlab naming and Netbox naming
            raw_intf_name = raw_intf_name.replace("eth", "Ethernet")
        return device, nb.dcim.interfaces.get(
            device=raw_device_name, name=raw_intf_name
        )

    for link in evpnlab["topology"]["links"]:
        left, right = link["endpoints"]
        left_device, left_intf = get_interface_data(*left.split(":"))
        right_device, right_intf = get_interface_data(*right.split(":"))

        # Attach cables
        print(left + "<->" + right)

        new_cable = (
            tmp
            if (
                tmp := nb.dcim.cables.get(
                    termination_a_id=left_intf.id,
                    termination_b_id=right_intf.id,
                )
            )
            is not None
            else nb.dcim.cables.create(
                dict(a_terminations=[
                    {
                        'object_type': 'dcim.interface',
                        'object_id': left_intf.id
                    }
                ], b_terminations=[
                    {
                        'object_type': 'dcim.interface',
                        'object_id': right_intf.id
                    }
                ])
            )
        )


        link_spine_leaf = all(
            [
                str(x.device_role) in ["spine", "leaf"]
                for x in [left_device, right_device]
            ]
        )
        not_ips_assigned = (
            nb.ipam.ip_addresses.get(interface_id=left_intf.id) is None
        ) or (nb.ipam.ip_addresses.get(interface_id=right_intf.id) is None)
        if link_spine_leaf and not_ips_assigned:
            new_prefix = prefix_underlay.available_prefixes.create(
                {
                    "prefix_length": 31,
                    "is_pool": True,
                    "tenant": tenant_rainbow.id,
                    "site": site_palette.id,
                }
            )
            print(new_prefix)
            left_ip = new_prefix.available_ips.create()
            print(left_ip)
            left_ip.assigned_object_id = left_intf.id
            left_ip.assigned_object_type = "dcim.interface"
            left_ip.save()
            right_ip = new_prefix.available_ips.create()
            print(right_ip)
            right_ip.assigned_object_id = right_intf.id
            right_ip.assigned_object_type = "dcim.interface"
            right_ip.save()
        ''' set mtu value for segment between spine and leaf '''
        if str(left_device.device_role) in ["spine", "leaf"] and left_intf.mtu is None:
            if str(right_device.device_role)!= "server":
                left_intf.update(dict(mtu='9000'))
        if str(right_device.device_role) in ["spine", "leaf"] and right_intf.mtu is None:
            if str(left_device.device_role)!= "server":
                right_intf.update(dict(mtu='9000'))

    for device in leafs + spines:

        def assign_ip(lo):
            if lo.count_ipaddresses < 1:
                loip = ippool.available_ips.create()
                loip.assigned_object_id = lo.id
                loip.assigned_object_type = "dcim.interface"
                loip.save()

        loop_list = [
            ("Loopback0", "EVPN Overlay Peering", prefix_loopback),
            ("Loopback1", "VTEP VXLAN Tunnel Source", prefix_vtep),
            ("Vxlan1", "EVPN L2+L3VPN Assignment", None),
        ]
        for intf_name, description, ippool in loop_list:
            intf_data = {
                "name": intf_name,
                "type": "virtual",
                "description": description,
                "device": device.id,
            }
            if intf_name == "Loopback0":
                lo = get_or_create(nb.dcim.interfaces, search="intf", **intf_data)
                assign_ip(lo)
            # Only leaf have EVPN related interfaces
            elif (intf_name in ("Loopback1", "Vxlan1")) and (
                str(device.device_role) == "leaf"
            ):
                lo = get_or_create(nb.dcim.interfaces, search="intf", **intf_data)
                if intf_name == "Loopback1":
                    assign_ip(lo)
                if str(intf_name).lower() == "vxlan1":
                    is_loopback1= list(operator.attrgetter('dcim.interfaces')(nb).filter(**{'device':str(device),
                                                                                                   'name':'Loopback1'})
                                              )[0]
                    if is_loopback1 is not None:
                        is_vxlan=list(operator.attrgetter('dcim.interfaces')(nb).filter(**{'device':str(device),
                                                                                           'name':str(intf_name)}))[0]
                        is_vxlan.update({'parent':is_loopback1})
                        is_vxlan.update({'custom_fields':{'vxlan_udp_port':4789}})


def provision_networks():

    # Create VLAN Group
    dc1 = get_or_create(
        nb.ipam.vlan_groups,
        name="evpn-dc1",
        slug="evpn-dc1",
        scope_type="dcim.site",
        scope_id=site_palette.id,
    )

    # Create Tags
    even_network = get_or_create(
        nb.extras.tags, name="evpn:even_network", slug="evpn-even_network"
    )
    odd_network = get_or_create(
        nb.extras.tags, name="evpn:odd_network", slug="evpn-odd_network"
    )
    onehundred = get_or_create(
        nb.extras.tags, name="evpn:onehundred", slug="evpn-onehundred"
    )
    twohundred = get_or_create(
        nb.extras.tags, name="evpn:twohundred", slug="evpn-twohundred"
    )

    # Create VLAN (add vni) / Assign tags to vlan
    vl110 = get_or_create(
        nb.ipam.vlans,
        search="vlan",
        name="Zone-A_1",
        vid=110,
        site=site_palette.id,
        group=dc1.id,
        tenant=tenant_rainbow.id,
        tags=[even_network.id, onehundred.id],
        custom_fields={"evpn_vni": 1010},
    )

    vl111 = get_or_create(
        nb.ipam.vlans,
        search="vlan",
        name="Zone-A_2",
        vid=111,
        site=site_palette.id,
        group=dc1.id,
        tenant=tenant_rainbow.id,
        tags=[odd_network.id, onehundred.id],
        custom_fields={"evpn_vni": 1011},
    )

    vl210 = get_or_create(
        nb.ipam.vlans,
        search="vlan",
        name="Zone-B_0",
        vid=210,
        site=site_palette.id,
        group=dc1.id,
        tenant=tenant_rainbow.id,
        tags=[even_network.id, twohundred.id],
        custom_fields={"evpn_vni": 2010},
    )

    vl211 = get_or_create(
        nb.ipam.vlans,
        search="vlan",
        name="Zone-B_1",
        vid=211,
        site=site_palette.id,
        group=dc1.id,
        tenant=tenant_rainbow.id,
        tags=[odd_network.id, twohundred.id],
        custom_fields={"evpn_vni": 2011},
    )

    # Create VRF
    vrfa = get_or_create(
        nb.ipam.vrfs,
        search="rd",
        name="Zone-A",
        rd="192.168.255.0:10",
        tenant=tenant_rainbow.id,
        custom_fields={"evpn_vni": 10},
    )

    vrfb = get_or_create(
        nb.ipam.vrfs,
        search="name",
        name="Zone-B",
        rd="192.168.255.0:20",
        tenant=tenant_rainbow.id,
        custom_fields={"evpn_vni": 20},
    )

    # Create Prefix
    prefix1 = get_or_create(
        nb.ipam.prefixes,
        search="prefix",
        prefix="10.1.10.0/24",
        vrf=vrfa.id,
        vlan=vl110.id,
        site=site_palette.id,
        role=role_data.id,
        tenant=tenant_rainbow.id,
    )

    prefix2 = get_or_create(
        nb.ipam.prefixes,
        search="prefix",
        prefix="10.1.11.0/25",
        vrf=vrfa.id,
        vlan=vl111.id,
        site=site_palette.id,
        role=role_data.id,
        tenant=tenant_rainbow.id,
    )

    prefix3 = get_or_create(
        nb.ipam.prefixes,
        search="prefix",
        prefix="10.2.10.0/26",
        vrf=vrfb.id,
        vlan=vl210.id,
        site=site_palette.id,
        role=role_data.id,
        tenant=tenant_rainbow.id,
    )

    prefix4 = get_or_create(
        nb.ipam.prefixes,
        search="prefix",
        prefix="10.2.11.0/27",
        vrf=vrfa.id,
        vlan=vl211.id,
        site=site_palette.id,
        role=role_data.id,
        tenant=tenant_rainbow.id,
    )

    for leaf in leafs:
        vxlan1 = nb.dcim.interfaces.get(device=leaf, name="Vxlan1")
        cf_evpn_assignment_append(vxlan1, "evpn_l2vpn", vl110)
        cf_evpn_assignment_append(vxlan1, "evpn_l2vpn", vl210)
        cf_evpn_assignment_append(vxlan1, "evpn_l3vpn", vrfa)
        cf_evpn_assignment_append(vxlan1, "evpn_l3vpn", vrfb)

    vlaninfts = {
        "leaf1": {"Vl110": "10.1.10.1", "Vl111": "10.1.11.1", "Vl210": "10.2.10.1"},
        "leaf2": {"Vl110": "10.1.10.1", "Vl210": "10.2.10.1", "Vl211": "10.2.11.1"},
    }


def provision_vlanintf():
    for node,params in evpnlab["topology"]["nodes"].items():
        if not 'leaf' in node:
            continue
        device=operator.attrgetter('dcim.devices')(nb).get(**dict(name=node))
        if device:
            vlans,evpnl2vpn,evpnl3vpn = list(),list(),list()
            intf_vlan = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=str(device), name='VLAN_DATABASE'))
            vlans.extend(list(operator.attrgetter('ipam.vlans')(nb).get(**dict(
                vid=str(x['id']))).id for x in params['vlans']
                              )
                         )
            intf_vlan.update({'tagged_vlans': vlans})
            intf_vxlan1 = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=str(device), name='Vxlan1'))
            evpnl2vpn.extend(x['id'] for x in intf_vxlan1.custom_fields['evpn_l2vpn'])
            evpnl3vpn.extend(x['id'] for x in intf_vxlan1.custom_fields['evpn_l2vpn'])
            intf_vxlan1.update({'tagged_vlans':evpnl2vpn})


def provision_bgp() -> None:

    def get_bgp_neighbor(inventory: list):
        '''

        '''
        bgp_tables=list()
        local_ctx = {}
        attr_nb="ipam.ip-addresses"
        for device in inventory:
            local_ctx[device['host']] = dict(bgp=[{'ipv4-underlay-peers': []},{'evpn-overlay-peers': []}])
        for device in inventory:
            for intf in device['interfaces']:
                if intf.cable is None:
                    continue
                rem_rolde_device=str(intf.connected_endpoints[0].device.device_role).lower()
                if rem_rolde_device != 'server':
                    intf_neighbor=str(intf.connected_endpoints[0])
                    rem_device=str(intf.connected_endpoints[0].device)
                    asn_neighbor=intf.connected_endpoints[0].device.custom_fields.get("evpn_asn")['asn']
                    peer_neighbor=(list(operator.attrgetter(attr_nb)(nb).filter(**{"device":rem_device,
                                                                                   "interface":intf_neighbor
                                                                                   })))
                    if 0 != len(peer_neighbor):
                        bgp_tables.append(dict(
                            device=device['host'],params=[{'p2p_int_local': str(intf), 'p2p_remote_int': intf_neighbor,
                                                           'p2p_remote_peer': str(peer_neighbor[0]).split('/')[0],
                                                           'p2p_remote_device': rem_device,
                                                           'p2p_remote_asn': asn_neighbor}]
                        )
                        )
                        param=dict(neighbor=str(peer_neighbor[0]).split('/')[0],remote_as=asn_neighbor)
                        local_ctx[device['host']]['bgp'][0]['ipv4-underlay-peers'].append(param)
        for device in inventory:
            for intf in device['interfaces']:
                if intf.cable is None :
                    continue
                rem_rolde_device=str(intf.connected_endpoints[0].device.device_role).lower()
                if rem_rolde_device != 'server':
                    rem_device=str(intf.connected_endpoints[0].device)
                    asn_neighbor = intf.connected_endpoints[0].device.custom_fields.get("evpn_asn")['asn']
                    peer_neighbor=list(operator.attrgetter(attr_nb)(nb).filter(**{"device":rem_device,
                                                                                  "interface":"Loopback0"}
                                                                               ))
                    if 'server' != str(intf.connected_endpoints[0].device.device_role):
                        bgp_tables.append(dict(
                            device=device['host'], params=[{'p2p_int_local': "Loopback0", 'p2p_remote_int': "Loopback0",
                                                            'p2p_remote_peer': str(peer_neighbor[0]).split('/')[0],
                                                            'p2p_remote_device': rem_device,
                                                            'p2p_remote_asn': asn_neighbor}]
                        )
                        )
                        param = dict(neighbor=str(peer_neighbor[0]).split('/')[0], remote_as=asn_neighbor)
                        local_ctx[device['host']]['bgp'][1]['evpn-overlay-peers'].append(param)

        return bgp_tables,local_ctx

    spines_lst=list(operator.attrgetter("dcim.devices")(nb).filter(**{'role':"spine"}))
    leafs_lst=list(operator.attrgetter("dcim.devices")(nb).filter(**{'role':"leaf"}))
    inventory,attr_nb,obj_nb=list(),"dcim.interfaces","device"
    for device in spines_lst+leafs_lst:
            inventory.append(dict(host=str(device),
                                  interfaces=list(operator.attrgetter(attr_nb)(nb).filter(**{obj_nb:str(device)}))))

    bgp_params=get_bgp_neighbor(inventory)
    for param in bgp_params[0]:
        print (param)

    for device in spines_lst+leafs_lst:
        bgp_param=bgp_params[1][str(device)]
        # if None == device.config_context['local-routing'].get('bgp'):
        config_ctx=device.config_context['local-routing']
        config_ctx.update(bgp_param)
        local_ctx={'local-routing':config_ctx}
        if config_ctx != local_ctx['local-routing']:
            device.update({'local_context_data':local_ctx})

def provision_rir_aggregates():
    import slugify
    slug=slugify.slugify(text='private-subnets')
    if operator.attrgetter('ipam.rirs')(nb).get(name='private-subnets') is None:
        operator.attrgetter("ipam.rirs")(nb).create({'name': 'private-subnets',
                                                     'slug': slug,
                                                     'is_private': True}
                                                     )


def provision_all():

    # provision_customfields()
    #
    # provision_orga()
    #
    # provision_config_context()
    #
    # provision_devices()
    #
    # provision_rir_aggregates()
    #
    # provision_asns()
    #
    # provision_interfaces()
    #
    # provision_networks()
    #
    # provision_bgp()

    provision_vlanintf()




def cf_evpn_assignment_append(interface, cf_evpname, ressource):

    HEADERS = {
        "Content-Type": "application/json;",
        "Authorization": f"Token {nb.token}",
    }

    # TODO Read current CF dict and modify it.
    reqdata = dict()
    reqdata["custom_fields"] = dict()
    reqdata["custom_fields"][cf_evpname] = list()
    reqdata["custom_fields"][cf_evpname].append(ressource.id)

    ans = nb.http_session.patch(
        f"{nb.base_url}/dcim/interfaces/{interface.id}/",
        headers=HEADERS,
        data=json.dumps(dict(reqdata)),
    )
    ans.json()


def get_shell():
    import ipdb

    ipdb.set_trace()


### Device type YAML import https://gist.github.com/rlaneyjr/87917f4e9a66d129c392b2353469b34b

TEMPLATE_LIST = [
    "console-ports",
    "console-server-ports",
    "power-ports",
    "power-outlets",
    "interfaces",
    "front-ports",
    "rear-ports",
    "device-bays",
]


class ManufacturerLookupError(BaseException):
    """
    Custom exception class
    """


class ManufacturerCreateError(BaseException):
    """
    Custom exception class
    """


class DeviceTypeValidationError(BaseException):
    """
    Custom exception class
    """


class DeviceTypeLookupError(BaseException):
    """
    Custom exception class
    """


class DeviceTypeCreateError(BaseException):
    """
    Custom exception class
    """


class TemplateCreationError(BaseException):
    """
    Custom exception class
    """


class TemplateProcessError(BaseException):
    """
    Custom exception class
    """


def slugify(s):
    """
    Converts dirty strings into something URL-friendly.
    FYI - Ordering is important.
    """
    s = s.lower()
    # Replace these items with underscore first
    for c in [" ", "-", ".", "/"]:
        s = s.replace(c, "_")
    # Remove non-word characters
    s = re.sub(r"\W", "", s)
    # Replace underscore with space to eliminate space seperated underscores
    s = s.replace("_", " ")
    # Replace 2 or more spaces with single space
    s = re.sub(r"\s+", " ", s)
    # Remove any leading or trailing spaces
    s = s.strip()
    # Finally replace spaces with a dash
    s = s.replace(" ", "-")
    return s


def get_yamls(yaml_file_path):
    """
    Finds all yaml files from the given path.
    """
    yamls = []
    yp = Path(yaml_file_path)
    for yf in yp.rglob("*.yaml"):
        yamls.append(yf)
    return yamls


def load_yaml(yaml_file: str):
    """
    Uses ruamel.yaml to load YAML files.
    Stolen from "https://github.com/netbox-community/netbox-docker"
    """
    yf = Path(yaml_file)
    if not yf.is_file():
        return None
    with yf.open("r") as stream:
        yaml = YAML(typ="safe")
        return yaml.load(stream)


def device_type_exists(device_type):
    """
    Runs multiple checks to see if the device type already exists in NetBox.
    """
    try:
        print(f"Checking if {device_type['model']} exists")
        _slug = slugify(device_type["model"])
        if nb.dcim.device_types.filter(model=device_type["model"]):
            print(f"Found device_type dict {device_type['model']}")
            return True
        elif nb.dcim.device_types.get(model=device_type["model"]):
            print(f"Found device_type name {device_type['model']}")
            return True
        elif nb.dcim.device_types.get(slug=device_type["slug"]):
            print(f"Found device_type slug {device_type['slug']}")
            return True
        elif nb.dcim.device_types.get(slug=_slug):
            print(f"Found device_type _slug {_slug}")
            return True
        else:
            return False
    except Exception as e:
        raise DeviceTypeLookupError(f"Error for {device_type}: {e}")


def get_or_create_manufacturer(man):
    """
    Try and get the manufacturer create it if it does not exist.
    """
    print(f"Checking if {man} exists")
    if not nb.dcim.manufacturers.get(name=man):
        print(f"Manufacturer: {man} does not exist")
        new_man = {"name": man, "slug": slugify(man)}
        print(f"Creating manufacturer with: {new_man}")
        nb.dcim.manufacturers.create(new_man)
    man_id = nb.dcim.manufacturers.get(name=man).id
    print(f"Found manufacturer {man} id: {str(man_id)}")
    return int(man_id)


def create_template(name, template):
    """
    Create a template.
    """
    try:
        if name == "console-ports":
            results = nb.dcim.console_port_templates.create(template)
        elif name == "console-server-ports":
            results = nb.dcim.console_server_port_templates.create(template)
        elif name == "power-ports":
            results = nb.dcim.power_port_templates.create(template)
        elif name == "power-outlets":
            results = nb.dcim.power_outlet_templates.create(template)
        elif name == "interfaces":
            results = nb.dcim.interface_templates.create(template)
        elif name == "front-ports":
            results = nb.dcim.front_port_templates.create(template)
        elif name == "rear-ports":
            results = nb.dcim.rear_port_templates.create(template)
        elif name == "device-bays":
            results = nb.dcim.device_bay_templates.create(template)
        print(f"Created new {name}: {results.name}")
        return results
    except RequestError:
        print(f"Already have {name}: {template}")
    except Exception as e:
        raise TemplateCreationError(
            f"Failed creating: {name}: {template}\nException: {e}"
        )


def process_templates(device_type):
    """
    Process the templates.
    """
    try:
        device_type_id = nb.dcim.device_types.get(model=device_type["model"]).id
    except:
        raise TemplateProcessError(
            f"Create device_type: {device_type['model']} before extracting \
            templates."
        )
    for name, data in device_type.items():
        if name in TEMPLATE_LIST:
            for item in data:
                item.update({"device_type": device_type_id})
                print(f"Creating template {name} with {item}")
                create_template(name, item)


def validate_device_data(device_type):
    """
    Validates and modifies data before inserting in NetBox.
    """
    if not isinstance(device_type, dict):
        raise DeviceTypeValidationError(
            f"Validation FAILED for {device_type}: \
                            {type(device_type)} is not a dict"
        )
    man = device_type["manufacturer"]
    man_id = get_or_create_manufacturer(man)
    device_type["manufacturer"] = man_id
    return device_type


def process_device_type(device_type):
    """
    Validates and verifies the device type before inserting in NetBox.
    """
    device_type = validate_device_data(device_type)
    does_exist = device_type_exists(device_type)
    if does_exist is False:
        print(f"Adding new device-type {device_type['model']}")
        nb.dcim.device_types.create(device_type)
    else:
        print(f"Already a device_type: {device_type['model']}")
    print(f"Checking for templates: {device_type['model']}")
    process_templates(device_type)


def process_yaml(yml_file):
    """
    Process a YAML file for importing to NetBox.
    """
    device_type = load_yaml(yml_file)
    process_device_type(device_type)


if __name__ == "__main__":
    # Execute when the module is not initialized from an import statement.
    provision_all()
