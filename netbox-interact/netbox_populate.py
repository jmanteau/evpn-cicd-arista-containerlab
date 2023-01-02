#!/usr/bin/env python3
import ipaddress
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
import slugify

urllib3.disable_warnings()


# TODO assign next-hop-self to ibgp-mlag-peer
# TODO fix route-target vrf assigns
# TODO refact l2vpn/terminations
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


def provision_config_context() -> None:
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
                operator.attrgetter('extras.config_contexts')(nb),
                search="name",
                name=ccname,
                data=ccdata,
                roles=[role_leaf.id, role_spine.id],
            )

def check_netbox_bgp_plugins():
    plugin = list(filter(lambda x: x['package'] == 'netbox_bgp', list(nb.plugins.installed_plugins())))
    return plugin

def create_devices(evpnlab) -> None:
    evpnlab = invok_evpnlab()
    STATUS = {
        x["display_name"].lower(): i
        for i, x in enumerate(operator.attrgetter('dcim.devices')(nb).choices()["status"])
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
            operator.attrgetter('dcim.devices')(nb),
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


def invok_evpnlab():
    with open("../evpnlab-tiny.yml") as fh:
        evpnlab = yaml.load(fh, Loader=yaml.FullLoader)
    return evpnlab


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
            if (tmp := concept.get(prefix=kwargs[search], vrf_id=kwargs['vrf'], vlan_id=kwargs['vlan'])) is not None
            else concept.create(**kwargs)
        )
    elif search == "management":
        nb_object = (
            tmp
            if (tmp := concept.get(prefix=kwargs['prefix'], vrf_id=kwargs['vrf'])) is not None
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
            if (tmp := concept.get(vid=kwargs["vid"], group_id=kwargs["group"])) is not None
            else concept.create(kwargs)
        )
    elif search == "rd":
        nb_object = (
            tmp
            if (tmp := concept.get(rd=kwargs["rd"])) is not None
            else concept.create(kwargs)
        )
    return nb_object


def provision_orga() -> None:
    global tenant_rainbow
    tenant_rainbow = get_or_create(operator.attrgetter('tenancy.tenants')(nb),
                                   name="Rainbow",
                                   slug="rainbow"
                                   )
    global site_palette
    site_palette = get_or_create(operator.attrgetter('dcim.sites')(nb),
                                 name="Palette",
                                 slug="palette",
                                 time_zone="Europe/Paris"
                                 )
    site_palette.tenant = tenant_rainbow
    site_palette.save()

    global role_spine
    role_spine = get_or_create(operator.attrgetter('dcim.device_roles')(nb), name="spine", slug="spine")
    global role_leaf
    role_leaf = get_or_create(operator.attrgetter('dcim.device_roles')(nb), name="leaf", slug="leaf")
    global role_server
    role_server = get_or_create(operator.attrgetter('dcim.device_roles')(nb), name="server", slug="server")
    global manuf_arista
    manuf_arista = get_or_create(operator.attrgetter('dcim.manufacturers')(nb), name="Arista", slug="arista")
    global manuf_linux
    manuf_linux = get_or_create(operator.attrgetter('dcim.manufacturers')(nb), name="Linux", slug="linux")


def provision_devices() -> None:
    process_yaml("devicetype-ceos-lab.yml")
    process_yaml("devicetype-alpine.yml")
    evpnlab = invok_evpnlab()
    global devicetype_ceos
    devicetype_ceos = get_or_create(operator.attrgetter('dcim.device_types')(nb),
                                    model="cEOS-LAB",
                                    manufacturer=manuf_arista.id,
                                    slug="ceos-lab",
                                    )
    global devicetype_alpine
    devicetype_alpine = get_or_create(operator.attrgetter('dcim.device_types')(nb),
                                      model="Alpine",
                                      manufacturer=manuf_linux.id,
                                      slug="alpine"
                                      )

    # TODO import device library -> Manual creation for the moment
    # https://gist.github.com/AdamEldred/f83105446c6ceb1b13dccad661ade428

    create_devices(evpnlab)
    global spines
    spines = list(operator.attrgetter('dcim.devices')(nb).filter(role="spine"))
    global leafs
    leafs = list(operator.attrgetter('dcim.devices')(nb).filter(role="leaf"))


def provision_customfields() -> None:
    # Create ASN information for each device
    cf_asn = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="evpn_asn",
        description="Autonomous System Number",
        content_types=["dcim.device"],
        type="object",
        object_type="ipam.asn",
        label="ASN"
    )

    cf_l2_rd_vlan = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="rd_vlan",
        description="Route distinguisher (ASN:VNI)",
        content_types=["ipam.l2vpn"],
        type="text",
        label="Route distinguisher"
    )
    cf_l2vpn_vlan = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="evpn_vlans",
        description="assigned vlans",
        content_types=["ipam.routetarget"],
        type="multiobject",
        object_type="ipam.vlan"
    )
    cf_address_family_type = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="address_family",
        content_types=["ipam.routetarget"],
        type="select",
        choices=["evpn", "vpn-ipv4", "vpn-ipv6"]
    )
    cf_l2_redistribute = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="redistribute_l2vpn",
        content_types=["ipam.l2vpn"],
        type="select",
        choices=["dot1x", "host-route", "igmp", "learned", "link-local", "router-mac", "static"]
    )
    cf_l3_redistribute = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="redistribute_l3vpn",
        content_types=["ipam.vrf"],
        type="multiselect",
        choices=["attached-host", "bgp", "connected", "dynamic", "isis", "ospf", "ospfv3", "rip", "static"]
    )
    # Create Custom Fields VNI on VLAN / VRF
    cf_vni = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="evpn_vni",
        description="VXLAN Network Identifier",
        content_types=["ipam.vlan", "ipam.vrf"],
        type="integer",
        label="EVPN VNI"
    )

    cf_l2evpn = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="evpn_l2vpn",
        description="EVPN Type-2",
        content_types=["dcim.interface"],
        type="multiobject",
        object_type="ipam.vlan",
        label="EVPN L2VPN"
    )

    cf_l3evpn = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="evpn_l3vpn",
        description="EVPN Type-5",
        content_types=["dcim.interface"],
        type="multiobject",
        object_type="ipam.vrf",
        label="EVPN L3VPN"
    )

    cf_udp_port = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="vxlan_udp_port",
        content_types=["dcim.interface"],
        type="integer",
        label="VXLAN UDP-PORT"
    )

    cf_vrf_device = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="vrf_device",
        description="where the vrf has been setup",
        content_types=["ipam.vrf"],
        type="object",
        object_type='dcim.device',
        label="device"
    )
    cf_l3vpn_vrf = get_or_create(
        operator.attrgetter('extras.custom-fields')(nb),
        search="name",
        name="evpn_vrf",
        description="assigned vrfs",
        content_types=["ipam.routetarget"],
        type="multiobject",
        object_type="ipam.vrf"
    )


def provision_asns() -> None:
    def assign_peer_device_asn(grp: list, asn: object) -> None:
        for device in grp:
            if device.custom_fields.get("evpn_ASN") is None:
                device.custom_fields.update(dict(evpn_asn=asn.id))
                device.save()
        site_asn_list=device.site.asns
        site_asn_list.append(asn.id)
        device.site.update(dict(asns=site_asn_list))

    def assign_standalone_device_asn(device: object, site_asnloc: dict) -> None:
        asn_site = site_asnloc[device.site.id]['asn']
        asn_device = f'{asn_site}.{device.id}'
        asndot = convertasdtoplain(asn_device)
        asn = (tmp
               if (tmp := operator.attrgetter('ipam.asns')(nb).get(**dict(asn=asndot))) is not None
               else operator.attrgetter("ipam.asns")(nb).create(**dict(asn=asndot, rir=rir.id))
               )
        if device.site.asns.__len__() > 0:
            asn_site_list = [x.id for x in device.site.asns]
            asn_site_list.append(asn.id)
        else:
            asn_site_list = [asn.id]
        device.site.update(dict(asns=asn_site_list))
        device.custom_fields.update(dict(evpn_asn=asn.id))
        device.save()

    def is_mlag():
        evpnlab = invok_evpnlab()
        topology = evpnlab["topology"]["links"]
        xsearch, x_wanted = list(), list()
        for i, d in enumerate(topology):
            x_len = len(d['endpoints'])
            for c in d['endpoints']:
                if 'leaf' in c:
                    xsearch.append(True)
                else:
                    xsearch.append(False)
                if len(xsearch) == x_len:
                    if all(xsearch):
                        x_wanted.append(topology[i])
                    xsearch = list()
        if x_wanted:
            for l in x_wanted:
                endpoints = l['endpoints']
                east, west = endpoints.pop(0).split(':')[0], endpoints.pop(0).split(':')[0]
                endpoints.append(east)
                endpoints.append(west)
            wanted = [mdict for n, mdict in enumerate(x_wanted) if mdict not in x_wanted[n + 1:]]
        return wanted

    def convertasdtoplain(asn: str):
        x,y=asn.split('.')
        plaintext=(int(x)*65536)+int(y)
        return plaintext

    def id_site():
        siterange = [*range(65001, 65199)]
        x_site = [x.id for x in list(operator.attrgetter('dcim.sites')(nb).all())]
        data={}
        for x in x_site:
            asn=siterange.pop(0)
            data[x]={'asn':asn}
        return data

    #### ASN Creation and assignment ###

    site_asnloc=id_site()

    #site_asnloc dict(id_site=dict(asn= int in range (65001,65199)
    mlag = is_mlag()
    rir = operator.attrgetter("ipam.rirs")(nb).get(**dict(name='private-subnets'))
    _leafs=list(operator.attrgetter('dcim.devices')(nb).filter(**dict(role='leaf')))
    _spines=list(operator.attrgetter('dcim.devices')(nb).filter(**dict(role='spine')))
    for device in _spines:
        if device.custom_fields.get("evpn_asn"):
            continue
        assign_standalone_device_asn(device,site_asnloc)
    if mlag:
        for peer in mlag:
            mlag_peer = list()
            xsearch = list()
            for device in _leafs:
                if str(device) not in peer['endpoints']:
                    assign_standalone_device_asn(device,site_asnloc)
                    pass
                else:
                    mlag_peer.append(device)
            for xdevice in mlag_peer:
                if xdevice.custom_fields.get("evpn_asn"):
                    xsearch.append(True)
                else:
                    xsearch.append(False)
            if not all(xsearch):
                asn_site = site_asnloc[xdevice.site.id]['asn']
                asn_device = f'{asn_site}.{xdevice.id}'
                asndot = convertasdtoplain(asn_device)
                operator.attrgetter('ipam.asns')(nb).create(dict(asn=asndot, rir=rir.id))
                asn = (tmp
                       if (tmp := operator.attrgetter('ipam.asns')(nb).get(**dict(asn=asndot))) is not None
                       else operator.attrgetter("ipam.asns")(nb).create(**dict(asn=asndot, rir=rir.id))
                       )
                assign_peer_device_asn(mlag_peer, asn)
    else:
        for device in _leafs:
            assign_standalone_device_asn(device,site_asnloc)

def provision_interfaces() -> None:
    def get_interface_data(raw_device_name, raw_intf_name):

        device = operator.attrgetter('dcim.devices')(nb).get(**dict(name=raw_device_name))
        if str(device.device_type) == "cEOS-LAB":
            # replace between containerlab naming and Netbox naming
            raw_intf_name = raw_intf_name.replace("eth", "Ethernet")
        return device, operator.attrgetter('dcim.interfaces')(nb).get(**dict(
            device=raw_device_name, name=raw_intf_name)
                                                                      )

    evpnlab = invok_evpnlab()
    for link in evpnlab["topology"]["links"]:
        print(f'endpoint: {link["endpoints"]}')
        left, right = link["endpoints"]
        left_device, left_intf = get_interface_data(*left.split(":"))
        right_device, right_intf = get_interface_data(*right.split(":"))

        # Attach cables
        print(left + "<->" + right)

        new_cable = (
            tmp
            if (
                   tmp := operator.attrgetter('dcim.cables')(nb).get(**dict(
                       termination_a_id=left_intf.id,
                       termination_b_id=right_intf.id,
                   )
                                                                     )
               )
               is not None
            else operator.attrgetter('dcim.cables')(nb).create(
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

        if not str(left_device.device_role) == str(right_device.device_role):
            link_spine_leaf = all(
                [
                    str(x.device_role) in ["spine", "leaf"]
                    for x in [left_device, right_device]
                ]
            )
            not_ips_assigned = (
                                       operator.attrgetter('ipam.ip_addresses')(nb).get(
                                           **dict(interface_id=left_intf.id)) is None
                               ) or (operator.attrgetter('ipam.ip_addresses')(nb).get(
                **dict(interface_id=right_intf.id)) is None)
            if link_spine_leaf and not_ips_assigned:
                prefix_underlay = operator.attrgetter('ipam.prefixes')(nb).get(**dict(role="evpn-underlay"))
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
            if str(right_device.device_role) != "server":
                left_intf.update(dict(mtu='9000'))
        if str(right_device.device_role) in ["spine", "leaf"] and right_intf.mtu is None:
            if str(left_device.device_role) != "server":
                right_intf.update(dict(mtu='9000'))

    prefix_loopback = operator.attrgetter('ipam.prefixes')(nb).get(**dict(role="evpn-loopback"))
    prefix_vtep = operator.attrgetter('ipam.prefixes')(nb).get(**dict(role="evpn-vtep"))
    loop_list = [
        ("Loopback0", "EVPN Overlay Peering", prefix_loopback),
        ("Loopback1", "VTEP VXLAN Tunnel Source", prefix_vtep),
        ("Vxlan1", "EVPN L2+L3VPN Assignment", None),
        ("VLAN_DATABASE", "vlans database", None)
    ]
    for device in leafs + spines:

        def assign_ip(interface: object, address: str) -> None:
            ipaddress = dict(address=address, assigned_object_type='dcim.interface', assigned_object_id=interface.id)
            operator.attrgetter('ipam.ip-addresses')(nb).create(ipaddress)

        for intf_name, description, ippool in loop_list:
            intf_data = {
                "name": intf_name,
                "type": "virtual",
                "description": description,
                "device": device.id,
            }
            if intf_name == "Loopback0":
                lo = get_or_create(operator.attrgetter('dcim.interfaces')(nb), search="intf", **intf_data)
                if not operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(device=device, interface=intf_name)):
                    childprefix = prefix_loopback.available_prefixes.create(dict(prefix_length=32,
                                                                        is_pool=True,
                                                                        tenant=tenant_rainbow.id,
                                                                        site=site_palette.id
                                                                        )
                                                                   )
                    prefix = childprefix.available_ips.list()[0]
                    assign_ip(lo, str(prefix))
            # Only leaf have EVPN related interfaces
            elif (intf_name in ("Loopback1", "Vxlan1", "VLAN_DATABASE")) and (
                    str(device.device_role) == "leaf"
            ):
                lo = get_or_create(operator.attrgetter('dcim.interfaces')(nb), search="intf", **intf_data)
                if intf_name == "Loopback1":
                    if not operator.attrgetter('ipam.ip-addresses')(nb).get(
                            **dict(device=device, interface=intf_name)):
                        childprefix = prefix_vtep.available_prefixes.create(dict(prefix_length=32,
                                                                                     is_pool=True,
                                                                                     tenant=tenant_rainbow.id,
                                                                                     site=site_palette.id
                                                                                     )
                                                                                )
                        prefix = childprefix.available_ips.list()[0]
                        assign_ip(lo, str(prefix))
                if str(intf_name).lower() == "vxlan1":
                    is_loopback1 = list(operator.attrgetter('dcim.interfaces')(nb).filter(**{'device': str(device),
                                                                                             'name': 'Loopback1'})
                                        )[0]
                    if is_loopback1 is not None:
                        is_vxlan = list(operator.attrgetter('dcim.interfaces')(nb).filter(**{'device': str(device),
                                                                                             'name': str(intf_name)}))[
                            0]
                        is_vxlan.update({'parent': is_loopback1})
                        is_vxlan.update({'custom_fields': {'vxlan_udp_port': 4789}})
                if intf_name == "VLAN_DATABASE":
                    intvlan = dict(device=device.id, name=intf_name, type="virtual")
                    vlandatabase = (
                        tmp
                        if (tmp := operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=device,
                                                                                         name="VLAN_DATABASE"))
                            ) is not None
                        else operator.attrgetter('dcim.interfaces')(nb).create(intvlan)
                    )


def provision_networks() -> None:
    networks_list = list()
    prefixes_list = list()
    vlangrp = list()
    role_list = list()
    for k, v in ipams.items():
        role_list.extend([x['role'] for x in v if x['role']])
        prefixes_list.extend(
            [dict(subnet=x['subnet'],
                  vlan=x['vlan'],
                  role=x['role'],
                  vrf=x['vrf'],
                  sites=site_palette.id,
                  tenant=tenant_rainbow.id,
                  device=k
                  ) for x in v if x['subnet'] and dict(subnet=x['subnet'], vlan=x['vlan'], role=x['role'], vrf=x['vrf'],
                                                       device=k)
             not in prefixes_list
             ]
        )
        if 'leaf' in k:
            vlangrp.append(k)
            networks_list.extend([dict(
                vlangrp=k,
                vlan=x['vlan'],
                role=x['role'],
                vrf=x['vrf'],
                vni=x['vni']) for x in v if x['vlan']['id']
            ]
            )
    # Create roles
    for data in set(role_list):
        role = get_or_create(
            operator.attrgetter('ipam.roles')(nb),
            name=data,
            slug=slugify.slugify(text=data)
        )

    # Create VLAN groups
    for data in vlangrp:
        vlangroups = get_or_create(
            operator.attrgetter('ipam.vlan_groups')(nb),
            name=data,
            slug=slugify.slugify(text=data),
            scope_type="dcim.site",
            scope_id=site_palette.id,
        )

    # Create VLAN (add vni) / Assign tags to vlan
    for data in networks_list:
        vlan = get_or_create(
            operator.attrgetter('ipam.vlans')(nb),
            search="vlan",
            name=data['vlan']['name'],
            vid=data['vlan']['id'],
            site=site_palette.id,
            group=operator.attrgetter('ipam.vlan_groups')(nb).get(**dict(name=data['vlangrp'])).id,
            tenant=tenant_rainbow.id,
            scope_id=site_palette.id,
            custom_fields={"evpn_vni": data['vni']},
        )
    # Create VRF
    for data in networks_list:
        if data['vrf']:
            device_id = operator.attrgetter('dcim.devices')(nb).get(**dict(name=data['vlangrp'])).id
            vrf = get_or_create(
                operator.attrgetter('ipam.vrfs')(nb),
                search='rd',
                name=data['vrf']['name'],
                tenant=tenant_rainbow.id,
                rd=f'{device_id}:{data["vrf"]["vni"]}',
                description=data['vlangrp'],
                custom_fields={"evpn_vni": data['vrf']['vni'], "vrf_device": device_id},
            )

    # Create Prefix
    for data in prefixes_list:
        vrf_id = None if not data['vrf'] else operator.attrgetter('ipam.vrfs')(nb).get(**dict(name=data['vrf']['name'],
                                                                                              description=data[
                                                                                                  'device'])
                                                                                       ).id
        vlan_id = None if not data['vlan']['id'] else operator.attrgetter('ipam.vlans')(nb).get(**dict(
            name=data['vlan']['name'],
            group=data['device']
        )).id
        role_id = operator.attrgetter('ipam.roles')(nb).get(**dict(name=data['role'])).id
        prefixes = get_or_create(
            operator.attrgetter('ipam.prefixes')(nb),
            search='prefix',
            prefix=data['subnet'],
            vrf=vrf_id,
            vlan=vlan_id,
            site=site_palette.id,
            role=role_id,
            tenant=tenant_rainbow.id,
        )


def provision_vlanintf() -> None:
    for node, params in ipams.items():
        vlans = list()
        if not 'leaf' in node:
            continue
        device_id = operator.attrgetter('dcim.devices')(nb).get(**dict(name=node)).id
        vlans.extend([data for data in params if data['vlan']['id']])
        for vlan in vlans:
            vid = vlan['vlan']['id']
            vlan_id = operator.attrgetter('ipam.vlans')(nb).get(**(dict(vid=vid, group=node))).id
            prefixe = operator.attrgetter('ipam.prefixes')(nb).get(**(dict(vlan_id=vlan_id))).available_ips.list()
            intvlan = dict(device=device_id,
                           name=vid,
                           type="virtual",
                           mode='tagged',
                           tagged_vlans=[vlan_id]
                           )
            if vlan['vrf']:
                vrf_name = vlan['vrf']['name']
                intvlan['vrf'] = operator.attrgetter('ipam.vrfs')(nb).get(**dict(name=vrf_name, description=node)).id
            nb_intvlan = (
                tmp
                if (tmp := operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=node,
                                                                                 name=vid))
                    ) is not None
                else operator.attrgetter('dcim.interfaces')(nb).create(intvlan)
            )
            intf = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=node, name=vid))
            if intf.count_ipaddresses==0:
                ipaddress = dict(address=str(prefixe[0]), assigned_object_type='dcim.interface',
                                 assigned_object_id=intf.id, tenant=tenant_rainbow.id)
                if 'vrf' in intvlan:
                    ipaddress['vrf'] = intvlan['vrf']
                nb_int = (
                    tmp
                    if (tmp := operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(address=str(prefixe[0]),
                                                                                       interface_id=str(intf.id)))
                        ) is not None
                    else operator.attrgetter('ipam.ip-addresses')(nb).create(ipaddress)
                )


def provision_bgp() -> None:
    '''https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2019/pdf/BRKSPG-2303.pdf'''
    '''https://github.com/openconfig/public/tree/master/release/models/bgp'''

    def create_session(data: dict) -> None:
        '''

        '''
        x_session = dict(
            name=data['group_peer'],
            site=operator.attrgetter('dcim.devices')(nb).get(**dict(name=data['device'])).site.id,
            device=operator.attrgetter('dcim.devices')(nb).get(**dict(name=data['device'])).id,
            local_as=operator.attrgetter('dcim.devices')(nb).get(**dict(name=data['device'])).custom_fields['evpn_asn']
            ['id'],
            remote_as=data['params']['p2p_remote_asn'],
            local_address=operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(
                interface=data['params']['p2p_int_local'], device=data['device'])).id,
            remote_address=operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(
                address=data['params']['p2p_remote_peer'])).id,
            status='active',
            peer_group=operator.attrgetter('plugins.bgp.bgppeergroup')(nb).get(**dict(
                name=data['group_peer'])).id,
            custom_fields=dict(
                BGP_remote_device=operator.attrgetter('dcim.devices')(nb).get(**dict(
                    name=data['params']['p2p_remote_device'])).id,
                BGP_address_family=data['group_peer'].split('-')[0].capitalize(),
                BGP_next_hop_self=False if 'next_hop_self' not in data['params'] else data['params']['next_hop_self'],
                BGP_next_hop_unchanged=False if 'next_hop_unchanged' not in data['params'] else data['params']['next_hop_unchanged']
            ))
        site = operator.attrgetter('dcim.devices')(nb).get(**dict(name=data['device'])).site
        local_address_id = x_session['local_address']
        remote_address_id = x_session['remote_address']
        BGP_remote_device = x_session['custom_fields']['BGP_remote_device']
        BGP_address_family = x_session['custom_fields']['BGP_address_family']
        BGP_next_hop_self = x_session['custom_fields']['BGP_next_hop_self']
        BGP_next_hop_unchanged = x_session['custom_fields']['BGP_next_hop_unchanged']
        session = (
            tmp
            if (tmp := operator.attrgetter('plugins.bgp.bgpsession')(nb).get(**{'name': data['group_peer'],
                                                                                'site': str(site),
                                                                                'device_id': x_session['device'],
                                                                                'local_as_id': x_session['local_as'],
                                                                                'remote_as_id': x_session['remote_as'],
                                                                                'local_address_id': local_address_id,
                                                                                'remote_address_id': remote_address_id,
                                                                                'status': 'active',
                                                                                'peer_group': x_session['peer_group'],
                                                                                'custom_fields':
                                                                                    {
                                                                                        'BGP_remote_device': BGP_remote_device,
                                                                                        'BGP_address_family': BGP_address_family,
                                                                                        'BGP_next_hop_self': BGP_next_hop_self,
                                                                                        'BGP_next_hop_unchanged':BGP_next_hop_unchanged
                                                                                        }
                                                                                }
                                                                             )
                ) is not None
            else operator.attrgetter('plugins.bgp.bgpsession')(nb).create(x_session)
        )

    def get_bgp_neighbor(inventory: list) -> None:
        '''

        '''

        def get_password():
            import random, string
            nb_digits = 3
            nb_spe_char = 2
            chars = string.ascii_letters + string.digits + string.punctuation
            password_lgth = 18
            password_list = list()
            for x in range(2):
                password_gen = ""
                for d in range(nb_digits):
                    password_gen += random.choice(string.digits)
                for s in range(nb_spe_char):
                    password_gen += random.choice(string.punctuation)
                for i in range(password_lgth - nb_digits - nb_spe_char):
                    password_gen += random.choice(string.ascii_letters)
                password_list.append(password_gen)
            return password_list

        def encrypt(group_peer: str, password: str):
            '''https://medium.com/@what_if/encrypting-decrypting-arista-bgp-bmp-ospf-passwords-ff2072460942'''
            from arista_encrypt import cbc_encrypt
            encrypted = cbc_encrypt(bytes(group_peer, 'utf-8'), bytes(password, 'utf-8'))
            return encrypted
        def get_asn(asn: str):
            display=re.search(r"\d+\.\d", asn).group().split()[0]
            return display

        bgp_tables = list()
        local_ctx = {}
        attr_nb = "ipam.ip-addresses"
        passwords = get_password()
        for device in inventory:
            local_ctx[device['host']] = dict(bgp=[{'ipv4-underlay-peers': []}, {'evpn-overlay-peers': []}])
            ipv4_peer_pwd = f"{[k for k, v in local_ctx[device['host']]['bgp'][0].items()][0]}_passwd"
            encrypt_ipv4_pwd = encrypt(ipv4_peer_pwd, passwords[0])
            evpn_peer_pwd = f"{[k for k, v in local_ctx[device['host']]['bgp'][1].items()][0]}_passwd"
            encrypt_evpn_peer_pwd = encrypt(evpn_peer_pwd, passwords[1])
            local_ctx[device['host']]['bgp'][0]['ipv4-underlay-peers'].append(dict(password=encrypt_ipv4_pwd.decode())
                                                                              )
            local_ctx[device['host']]['bgp'][1]['evpn-overlay-peers'].append(
                dict(password=encrypt_evpn_peer_pwd.decode())
            )
        for device in inventory:
            for intf in device['interfaces']:
                if intf.cable is None or intf.count_ipaddresses == 0:
                    continue
                rem_role_device = str(intf.connected_endpoints[0].device.device_role).lower()
                if rem_role_device != 'server':
                    intf_neighbor = str(intf.connected_endpoints[0])
                    rem_device = str(intf.connected_endpoints[0].device)
                    # asn=intf.connected_endpoints[0].device.custom_fields["evpn_asn"]['display']
                    asn_neighbor = intf.connected_endpoints[0].device.custom_fields["evpn_asn"]['id']
                    peer_neighbor = operator.attrgetter(attr_nb)(nb).get(**{"device": rem_device,
                                                                            "interface": intf_neighbor
                                                                            }
                                                                         )
                    network = ipaddress.ip_network(str(peer_neighbor), strict=False)
                    role = str(operator.attrgetter('ipam.prefixes')(nb).get(**dict(prefix=str(network))).role)
                    if peer_neighbor and role != 'mlag-keepalive':
                        bgp_tables.append(dict(
                            device=device['host'], params={'p2p_int_local': str(intf), 'p2p_remote_int': intf_neighbor,
                                                           'p2p_remote_peer': str(peer_neighbor),
                                                           'p2p_remote_device': rem_device,
                                                           'p2p_remote_asn': asn_neighbor,
                                                           },
                            group_peer='ipv4-underlay-peers'
                        )
                        )
                        # params=dict(neighbor=str(peer_neighbor).split('/')[0],remote_as=asn_neighbor)
                        # local_ctx[device['host']]['bgp'][0]['ipv4-underlay-peers'].append(params)
        for device in inventory:
            for intf in device['interfaces']:
                if intf.cable is None:
                    continue
                local_device_role = str(intf.device.device_role) in ['leaf']
                rem_device_role = str(intf.connected_endpoints[0].device.device_role) in ['server','leaf']
                # local_device_ip = intf.count_ipaddresses == 1
                # rem_device_ip = intf.count_ipaddresses == 1
                if not all([local_device_role,rem_device_role]):
                    rem_device = str(intf.connected_endpoints[0].device)
                    # asn=intf.connected_endpoints[0].device.custom_fields['evpn_asn']['display']
                    asn_neighbor = intf.connected_endpoints[0].device.custom_fields['evpn_asn']['id']
                    peer_neighbor = operator.attrgetter(attr_nb)(nb).get(**{"device": rem_device,
                                                                            "interface": "Loopback0"}
                                                                         )
                    next_hop_unchanged=all([str(intf.device.device_role)=='spine',
                                            str(intf.connected_endpoints[0].device.device_role)=='leaf']
                                           )
                    bgp_tables.append(dict(
                        device=device['host'], params={'p2p_int_local': "Loopback0", 'p2p_remote_int': "Loopback0",
                                                       'p2p_remote_peer': str(peer_neighbor),
                                                       'p2p_remote_device': rem_device,
                                                       'p2p_remote_asn': asn_neighbor,
                                                       'next_hop_unchanged':True if next_hop_unchanged is True else False
                                                       }
                            ,
                            group_peer='evpn-overlay-peers'
                        )
                        )
        for device in inventory:
            for intf in device['interfaces']:
                if 'mlag-ibgp' in [str(x) for x in intf.tagged_vlans] and intf.count_ipaddresses == 1:
                    mlagvlan = operator.attrgetter('ipam.vlans')(nb).get(**dict(vid=4094, group=str(device['host'])))
                    if mlagvlan:
                        peer_mlag = list(
                            operator.attrgetter('dcim.interfaces')(nb).filter(**dict(device=str(device['host']),
                                                                                     vlan_id=mlagvlan.id)
                                                                              )
                        )
                        rem_device = [x.connected_endpoints[0].device for x in peer_mlag if
                                      peer_mlag and x.connected_endpoints and str(
                                          x.connected_endpoints[0].device.device_role) == 'leaf'
                                      ][0]
                        intf_neighbor = [x for x in operator.attrgetter('dcim.interfaces')(nb).filter(**dict(
                            device=str(rem_device)))
                                         if
                                         'mlag-ibgp' in [str(x) for x in x.tagged_vlans] and x.count_ipaddresses == 1][
                            0]
                        # asn=rem_device.custom_fields['evpn_asn']['display']
                        asn_neighbor = rem_device.custom_fields['evpn_asn']['id']
                        peer_neighbor = operator.attrgetter(attr_nb)(nb).get(**{"device": str(rem_device),
                                                                                "interface": str(intf_neighbor)
                                                                                }
                                                                             )
                        if peer_neighbor:
                            bgp_tables.append(dict(device=device['host'], params={'p2p_int_local': str(intf),
                                                                                  'p2p_remote_int': intf_neighbor,
                                                                                  'p2p_remote_peer': str(peer_neighbor),
                                                                                  'p2p_remote_device': rem_device,
                                                                                  'p2p_remote_asn': asn_neighbor,
                                                                                  'next_hop_self': True
                                                                                  },
                                                   group_peer='ipv4-mlag-peering'
                                                   )
                                              )
        return bgp_tables, local_ctx

    bgp_plugins = check_netbox_bgp_plugins()
    spines_lst = list(operator.attrgetter("dcim.devices")(nb).filter(**{'role': "spine"}))
    leafs_lst = list(operator.attrgetter("dcim.devices")(nb).filter(**{'role': "leaf"}))
    inventory, attr_nb, obj_nb = list(), "dcim.interfaces", "device"
    for device in spines_lst + leafs_lst:
        inventory.append(dict(host=str(device),
                              interfaces=list(operator.attrgetter(attr_nb)(nb).filter(**{obj_nb: str(device)}))))

    bgp_params = get_bgp_neighbor(inventory)
    # for param in bgp_params[0]:
    #     print (param)

    for device in spines_lst + leafs_lst:
        bgp_param = bgp_params[1][str(device)]
        config_ctx = device.config_context['local-routing']
        config_ctx.update(bgp_param)
        local_ctx = {'local-routing': config_ctx}
        device.update({'local_context_data': local_ctx})
        '''bug object as customfield'''
        '''https://github.com/netbox-community/pynetbox/issues/457'''
    if bgp_plugins:

        cf_bgp_addr_family = get_or_create(
            operator.attrgetter('extras.custom_fields')(nb),
            search="name",
            name="BGP_address_family",
            content_types=["netbox_bgp.bgpsession"],
            type="select",
            label="Addr family",
            required=True,
            choices=['Ipv4', 'Vpnv4', 'Evpn', 'vrf']
        )

        cf_bgp_remote_device = get_or_create(
            operator.attrgetter('extras.custom_fields')(nb),
            search="name",
            name="BGP_remote_device",
            content_types=["netbox_bgp.bgpsession"],
            type="object",
            label="Remote Device",
            required=True,
            object_type='dcim.device'
        )

        cf_bgp_next_hop_self = get_or_create(
            operator.attrgetter('extras.custom_fields')(nb),
            search="name",
            name="BGP_next_hop_self",
            content_types=["netbox_bgp.bgpsession"],
            type="boolean",
            default=False,
            label="Next-hop-self",
            required=False
        )

        cf_bgp_next_hop_unchanged = get_or_create(
            operator.attrgetter('extras.custom_fields')(nb),
            search="name",
            name="BGP_next_hop_unchanged",
            content_types=["netbox_bgp.bgpsession"],
            type="boolean",
            default=False,
            label="Next-hop-unchanged",
            required=False
        )

        cf_bgp_redistribute = get_or_create(
            operator.attrgetter('extras.custom-fields')(nb),
            search="name",
            name="BGP_redistribute_ipv4",
            content_types=["netbox_bgp.routingpolicy"],
            type="select",
            choices=["attached-host", "bgp", "connected", "dynamic", "isis", "ospf", "ospfv3", "rip", "static"]
        )

        # cf_bgp_routemapin = get_or_create(
        #     operator.attrgetter('extras.custom-fields')(nb),
        #     search="name",
        #     name="BGP_routemapin",
        #     content_types=["netbox_bgp.bgpsession"],
        #     type="text",
        #     label="import route-maps",
        # )
        #
        # cf_bgp_routemapout = get_or_create(
        #     operator.attrgetter('extras.custom-fields')(nb),
        #     search="name",
        #     name="BGP_routemapout",
        #     content_types=["netbox_bgp.bgpsession"],
        #     type="text",
        #     label="export route-maps",
        # )

        if not operator.attrgetter('plugins.bgp.bgppeergroup')(nb).get(**dict(name='ipv4-underlay-peers')):
            operator.attrgetter('plugins.bgp.bgppeergroup')(nb).create(dict(name='ipv4-underlay-peers',
                                                                            description='ipv4-underlay-peers')
                                                                       )
        if not operator.attrgetter('plugins.bgp.bgppeergroup')(nb).get(**dict(name='evpn-overlay-peers')):
            operator.attrgetter('plugins.bgp.bgppeergroup')(nb).create(dict(name='evpn-overlay-peers',
                                                                            description='evpn-overlay-peers'))

        if not operator.attrgetter('plugins.bgp.bgppeergroup')(nb).get(**dict(name='ipv4-mlag-peering')):
            operator.attrgetter('plugins.bgp.bgppeergroup')(nb).create(dict(name='ipv4-mlag-peering',
                                                                            description='ipv4-mlag-peering'))

        for data in bgp_params[0]:
            create_session(data)
    # ###endpoint is missing, wait updates from repo
    # operator.attrgetter('plugins.bgp.prefix-list')(nb).create(dict(name='pl-loopbacks-evpn-overlay2',
    #                                                                description='pl-loopbacks-evpn-overlay',
    #                                                                family_id="")
    #                                                           )
    #
    # operator.attrgetter('plugins.bgp.routing-policy')(nb).create(dict(name='rm-conn-2-bgp', description='rm-conn-2-bgp')
    #                                                              )


def provision_rir_aggregates() -> None:
    process_json()
    rir_list = list()
    prefixes_list = list()
    for k, v in ipams.items():
        rir_list.extend([x['rir'] for x in v if x['rir']])
        prefixes_list.extend([dict(prefix=x['subnet'], rir=x['rir']) for x in v if x['subnet'] and
                              dict(prefix=x['subnet'], rir=x['rir']) not in prefixes_list]
                             )
    for data in set(rir_list):
        slug = slugify.slugify(text=data)
        if not operator.attrgetter('ipam.rirs')(nb).get(**dict(name=data)):
            operator.attrgetter("ipam.rirs")(nb).create({'name': data,
                                                         'slug': slug,
                                                         'is_private': True}
                                                        )
    tenant_id = operator.attrgetter('tenancy.tenants')(nb).get(**dict(name='Rainbow')).id
    for data in prefixes_list:
        rir_id = operator.attrgetter('ipam.rirs')(nb).get(**dict(name=data['rir'])).id
        aggregate = (
            tmp
            if (tmp := operator.attrgetter('ipam.aggregates')(nb).get(**dict(prefix=data['prefix'], rir_id=rir_id))
                ) is not None
            else operator.attrgetter('ipam.aggregates')(nb).create(dict(prefix=data['prefix'], rir=rir_id,
                                                                        tenant=tenant_id))
        )


def provision_management() -> None:
    evpnlab = invok_evpnlab()
    management = dict(name=evpnlab['mgmt']['network'], subnet=evpnlab['mgmt']['ipv4_subnet'])
    role = (
        tmp
        if (tmp := operator.attrgetter('ipam.roles')(nb).get(**dict(name=management['name']))
            ) is not None
        else operator.attrgetter('ipam.roles')(nb).create(dict(name=management['name'],
                                                               slug=slugify.slugify(text=management['name'])
                                                               ))
    )
    vrfMGMT = (
        tmp
        if (tmp := operator.attrgetter('ipam.vrfs')(nb).get(**dict(name='MGMT'))
            ) is not None
        else operator.attrgetter('ipam.vrfs')(nb).create(dict(name='MGMT'))
    )
    prefixe = get_or_create(
        operator.attrgetter('ipam.prefixes')(nb),
        search="management",
        prefix=management['subnet'],
        vrf=vrfMGMT.id,
        role=role.id,
    )
    for node, params in evpnlab["topology"]["nodes"].items():
        addr = f'{params["mgmt_ipv4"]}/{str(prefixe).split("/")[-1]}'
        name = 'Management0' if not node.startswith('h') else 'eth0'
        intf_id = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=node, name=name)).id
        ipaddress = dict(address=addr, assigned_object_type='dcim.interface', assigned_object_id=intf_id,
                         vrf=vrfMGMT.id
                         )
        Mgmtint = (
            tmp
            if (tmp := operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(address=addr,
                                                                               interface_id=str(intf_id)))
                ) is not None
            else operator.attrgetter('ipam.ip-addresses')(nb).create(ipaddress)
        )
        node = operator.attrgetter('dcim.devices')(nb).get(**dict(name=node))
        node.update(dict(primary_ip4=Mgmtint.id))


def provision_mlag() -> None:
    from generate_mac import generate_mac
    evpnlab = invok_evpnlab()
    ###virtual MAC for the MLAG
    root_vhwdaddress = generate_mac.vid_file_vendor('manuf', "Arista")
    for node in evpnlab["topology"]['nodes']:
        if 'leaf' in node:
            mlagvlan = operator.attrgetter('ipam.vlans')(nb).get(**dict(vid=4094, group=node))
            if mlagvlan:
                vhwdaddress = generate_mac.another_same_vid(root_vhwdaddress)
                host = operator.attrgetter('dcim.devices')(nb).get(**dict(name=node))
                interface = dict(device=host.id,
                                 name='ip virtual-router mac-address', enabled=True, type='virtual',
                                 mac_address=vhwdaddress)
                intf = operator.attrgetter('dcim.interfaces')(nb).get(
                    **dict(device=node, name='ip virtual-router mac-address')
                )
                if intf:
                    operator.attrgetter('dcim.interfaces')(nb).delete([intf.id])
                    operator.attrgetter('dcim.interfaces')(nb).create(interface)
                else:
                    operator.attrgetter('dcim.interfaces')(nb).create(interface)
                peer_mlag = list(
                    operator.attrgetter('dcim.interfaces')(nb).filter(**dict(device=node, vlan_id=mlagvlan.id)))
                target = [x for x in peer_mlag if
                          peer_mlag and x.connected_endpoints and str(
                              x.connected_endpoints[0].device.device_role) == 'leaf'
                          ]
                if target:
                    des=f'{str(target[0].device)}:{str(target[0])} to {str(target[0].connected_endpoints[0].device)}:{str(target[0].connected_endpoints[0])}'
                    data = dict(device=host.id,
                                name='Port-channel4094',
                                type="lag",
                                mode='tagged',
                                description=des,
                                mtu=target[0].mtu,
                                tagged_vlans=[mlagvlan.id]
                                )
                    intpo = (
                        tmp
                        if (tmp := operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=node,
                                                                                         name='Port-channel4094'))
                            ) is not None
                        else operator.attrgetter('dcim.interfaces')(nb).create(data)
                    )
                    if intpo:
                        for interface in target:
                            if not interface.lag:
                                lag_intf = dict(lag=intpo.id)
                                interface.update(lag_intf)
                if not host.virtual_chassis and interface.lag:
                    members = [host, interface.connected_endpoints[0].device]
                    vc_param = dict(name=f'vcmlag_{node}_{str(interface.connected_endpoints[0].device)}',
                                    domain='domain')
                    vcchassis = (
                        tmp
                        if (tmp := operator.attrgetter('dcim.virtual-chassis')(nb).get(**vc_param)
                            ) is not None
                        else operator.attrgetter('dcim.virtual-chassis')(nb).create(vc_param)
                    )
                    position = 1
                    for data in members:
                        data.update(dict(virtual_chassis=vcchassis.id, vc_position=position))
                        position += 1
                keepalive = [x for x in operator.attrgetter('dcim.interfaces')(nb).filter(**dict(device=node))
                             if x.connected_endpoints
                             and str(x.connected_endpoints[0].device.device_role) == 'leaf'
                             and not x.tagged_vlans
                             ]
                keepalive.extend([x.connected_endpoints[0] for x in keepalive])
                available_ips = operator.attrgetter('ipam.prefixes')(nb).get(**dict(role='mlag-keepalive')
                                                                             ).available_ips.list()
                if keepalive:
                    for data in keepalive:
                        if data.count_ipaddresses == 0:
                            ipaddress = dict(address=str(available_ips[0]),
                                             assigned_object_type='dcim.interface',
                                             assigned_object_id=data.id
                                             )
                            nb_int = (
                                tmp
                                if (tmp := operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(
                                    address=ipaddress['address'],
                                    interface_id=str(data.id)))) is not None
                                else operator.attrgetter('ipam.ip-addresses')(nb).create(ipaddress)
                            )
                tenant_id = operator.attrgetter('ipam.prefixes')(nb).get(**dict(role='mlag-keepalive')).tenant.id
                rir_id = operator.attrgetter('ipam.rirs')(nb).get(**dict(name='private-subnets')).id
                aggregate = (
                    tmp
                    if (tmp := operator.attrgetter('ipam.aggregates')(nb).get(**dict(prefix='10.255.253.0/24',
                                                                                     rir_id=rir_id))
                        ) is not None
                    else operator.attrgetter('ipam.aggregates')(nb).create(dict(prefix='10.255.253.0/24',
                                                                                rir=rir_id,
                                                                                tenant=tenant_id))
                )
                if aggregate:
                    role = get_or_create(
                        operator.attrgetter('ipam.roles')(nb),
                        name='mlag-ibgp',
                        slug=slugify.slugify(text='mlag-ibgp')
                    )
                vlan = get_or_create(
                    operator.attrgetter('ipam.vlans')(nb),
                    search="vlan",
                    name="mlag-ibgp",
                    vid=4093,
                    site=site_palette.id,
                    group=operator.attrgetter('ipam.vlan-groups')(nb).get(**dict(name=node)).id,
                    tenant=tenant_rainbow.id,
                    scope_id=site_palette.id,
                )
                if vlan:
                    interfaces = [x for x in peer_mlag if x.count_ipaddresses == 0]
                    if interfaces:
                        for target in interfaces:
                            if not vlan in target.tagged_vlans:
                                target.tagged_vlans.append(vlan.id)
                                target.save()
                    intvlan_param = dict(device=host.id,
                                         name=vlan.vid,
                                         type="virtual",
                                         mode='tagged',
                                         mtu=9000,
                                         tagged_vlans=[vlan.id]
                                         )
                    intvlan = (
                        tmp
                        if (tmp := operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=node,
                                                                                         name=vlan.vid))
                            ) is not None
                        else operator.attrgetter('dcim.interfaces')(nb).create(intvlan_param)
                    )
    role = operator.attrgetter('ipam.roles')(nb).get(**dict(name='mlag-ibgp'))
    subnet = (
        tmp
        if (tmp := operator.attrgetter('ipam.prefixes')(nb).get(**(dict(role=str(role))))) is not None
        else operator.attrgetter('ipam.prefixes')(nb).create(prefix=str(aggregate), role=role.id)
    )
    int4094 = list(operator.attrgetter('dcim.interfaces')(nb).filter(**dict(name='4094')))
    if int4094:
        for vlan in int4094:
            if not vlan.mtu or vlan != 9000:
                vlan.update(dict(mtu=9000))
    for node in evpnlab["topology"]['nodes']:
        if 'leaf' in node:
            mlagvlan = operator.attrgetter('ipam.vlans')(nb).get(**dict(vid=4094, group=node))
            if mlagvlan:
                peer_mlag = list(
                    operator.attrgetter('dcim.interfaces')(nb).filter(**dict(device=node, vlan_id=mlagvlan.id)))
                peer_intf = [x for x in peer_mlag if
                             peer_mlag and x.connected_endpoints and str(
                                 x.connected_endpoints[0].device.device_role) == 'leaf'
                             ]
                if subnet:
                    for data in peer_intf:
                        devices = list()
                        devices.append(data.device)
                        devices.append(data.connected_endpoints[0].device)
                        vl4093 = [operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=str(x),
                                                                                        name=4093)) for x in devices
                                  ]
                        if all([vl4093, vl4093.__len__() == 2, [True for x in vl4093 if x.count_ipaddresses == 0]]):
                            childprefix = subnet.available_prefixes.create(dict(prefix_length=31,
                                                                                is_pool=True,
                                                                                tenant=tenant_rainbow.id,
                                                                                site=site_palette.id
                                                                                )
                                                                           )

                            for x in vl4093:
                                prefix = operator.attrgetter('ipam.prefixes')(nb).get(**(dict(
                                    prefix=childprefix))).available_ips.list()
                                ipaddress = dict(address=str(prefix[0]), assigned_object_type='dcim.interface',
                                                 assigned_object_id=x.id)
                                operator.attrgetter('ipam.ip-addresses')(nb).create(ipaddress)


def provision_assign_vlans() -> None:
    for device in leafs:
        vlans = list(operator.attrgetter('ipam.vlans')(nb).filter(**dict(group=str(device))))
        vid_list = [data.id for data in vlans]
        vlandatabase = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=str(device), name='VLAN_DATABASE'))
        if not vlandatabase.tagged_vlans == vlans:
            vlandatabase.update(dict(mode='tagged', tagged_vlans=vid_list))
            vlandatabase.save()
        vxlan1 = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=str(device), name='Vxlan1'))
        param = list(filter(lambda x: x['evpn'] == True, ipams[str(device)]))
        l2vpn_id = [operator.attrgetter('ipam.vlans')(nb).get(**dict(vid=x['vlan']['id'], group=str(device))).id
                    for x in param if x['vlan']['id']
                    ]
        l3vpn_id = [operator.attrgetter('ipam.vrfs')(nb).get(**dict(name=x['vrf']['name'], description=str(device))).id
                    for x in param if x['vrf']
                    ]

        vxlan1.update(dict(custom_fields={'evpn_l2vpn': l2vpn_id,
                                          'evpn_l3vpn': l3vpn_id}
                           )
                      )
        vxlan1.save()
        interfaces_list = list(filter(lambda x: x['vlan']['interfaces'], ipams[str(device)]))
        taggedvlans_params = [dict(vid=x['vlan']['id'], interfaces=x['vlan']['interfaces']) for x in interfaces_list]
        for data in taggedvlans_params:
            vid_id = operator.attrgetter('ipam.vlans')(nb).get(**dict(vid=data['vid'], group=str(device))).id
            for intf in data['interfaces']:
                interface = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=str(device), name=intf))
                if interface:
                    interface.update(dict(mode='tagged', tagged_vlans=[vid_id]))
                    interface.save()


def provision_hosts() -> None:
    import os
    evpnlab = invok_evpnlab()
    hosts = list()
    directory = '/home/ec2-user/evpn-cicd-arista-containerlab/ansible-tinylab/host_vars'
    if os.path.exists(directory):
        files = os.listdir(directory)
        for file in files:
            if file.startswith('clab-evpnlab-h'):
                data = load_yaml(f"{directory}/{file}")
                for k, v in data['interfaces'].items():
                    host = dict(interface=k, device=file.split('-')[2].split('.')[0], address=v['ip_address'],
                                vlan=v['description'].split('Vlan')[-1])
                    hosts.append(host)
    for host in hosts:
        interface = host['interface']
        device = host['device']
        addr = host['address']
        intf = operator.attrgetter('dcim.interfaces')(nb).get(**dict(device=device, name=interface))
        ipaddress = dict(address=addr, assigned_object_type='dcim.interface', assigned_object_id=intf.id)
        intlocal = (
            tmp
            if (tmp := operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(address=addr,
                                                                               interface_id=str(intf.id)))
                ) is not None
            else operator.attrgetter('ipam.ip-addresses')(nb).create(ipaddress)
        )


def provision_overlay() -> None:
    def transform(d: dict):
        results = []
        for k, v in d.items():
            if isinstance(v, dict):
                for key, data in v.items():
                    if isinstance(data, list):
                        ndict = dict()
                        ndict[key] = data
                        results.append(ndict)
        return results

    def get_rt(rt_list: list, vlan_id: int):
        for x in rt_list:
            if x.custom_fields['evpn_vlans']:
                for y in x.custom_fields['evpn_vlans']:
                    if y['id'] == vlan_id:
                        return x.id

    _leafs=list(operator.attrgetter('dcim.devices')(nb).filter(**dict(role='leaf')))
    # update rd for vrfs
    vrfs_list = [x for x in list(operator.attrgetter('ipam.vrfs')(nb).all()) if x.rd]
    for vrf in vrfs_list:
        evpn_vni = vrf['custom_fields']['evpn_vni']
        lo0 = str(operator.attrgetter('ipam.ip-addresses')(nb).get(
            **dict(device_id=vrf['custom_fields']['vrf_device']['id'], interface='Loopback0'))).split('/')[0]
        rd = f'{lo0}:{evpn_vni}'
        if vrf.rd != rd:
            vrf.update(dict(rd=rd))
            vrf.save()
    # get evpn configurations
    data = list()
    for device in _leafs:
        vxlan1 = operator.attrgetter('dcim.interfaces')(nb).get(**dict(name='Vxlan1', device=str(device)))
        evpn_l2 = [operator.attrgetter('ipam.vlans')(nb).get(**dict(id=x['id']))
                   for x in vxlan1.custom_fields['evpn_l2vpn']]
        evpn_l3 = [operator.attrgetter('ipam.vrfs')(nb).get(**dict(id=x['id']))
                   for x in vxlan1.custom_fields['evpn_l3vpn']]
        asn = device.custom_fields['evpn_asn']['asn']
        data.append(dict(vxlan1=vxlan1, evpn_l2=evpn_l2, evpn_l3=evpn_l3, asn=asn, device=device))
    # route-targets
    id = [i for i in range(1, 11)]
    l2vpn_dico = dict()
    l3vpn_dico = dict()
    for xdata in data:
        for vlan in xdata['evpn_l2']:
            l2rt = dict(name=f'{vlan.vid}:{vlan.custom_fields["evpn_vni"]}')
            l2_evpn = (
                tmp
                if (tmp := operator.attrgetter('ipam.route-targets')(nb).get(**dict(name=l2rt['name']))) is not None
                else operator.attrgetter('ipam.route-targets')(nb).create(l2rt)
            )
            if str(l2_evpn) not in l2vpn_dico:
                l2vpn_dico[str(l2_evpn)] = []
            l2vpn_dico[str(l2_evpn)].append(vlan.id)
        for vrf in xdata['evpn_l3']:
            if str(vrf) in l3vpn_dico:
                xid = l3vpn_dico[str(vrf)]['id']
            else:
                l3vpn_dico[str(vrf)] = dict(id=id.pop(0))
                xid = l3vpn_dico[str(vrf)]['id']
            l3rt = dict(name=f'{xid}:{vrf.custom_fields["evpn_vni"]}',
                        custom_fields=dict(address_family='evpn')
                        )
            l3_vpn = (
                tmp
                if (tmp := operator.attrgetter('ipam.route-targets')(nb).get(**dict(name=l3rt['name']))) is not None
                else operator.attrgetter('ipam.route-targets')(nb).create(l3rt)
            )
            if not str(l3_vpn) in l3vpn_dico[str(vrf)]:
                l3vpn_dico[str(vrf)][str(l3_vpn)] = []
            l3vpn_dico[str(vrf)][str(l3_vpn)].append(vrf.id)
    for k, v in l2vpn_dico.items():
        target = operator.attrgetter('ipam.route-targets')(nb).get(**dict(name=k))
        if target:
            target.update(dict(custom_fields={'evpn_vlans': v}))
    for d in transform(l3vpn_dico):
        for k, v in d.items():
            target = operator.attrgetter('ipam.route-targets')(nb).get(**dict(name=k))
            target.update(dict(custom_fields={'evpn_vrf': v}))
            for id in v:
                vrf = operator.attrgetter('ipam.vrfs')(nb).get(**dict(id=id))
                vrf.update(dict(custom_fields={'redistribute_l3vpn': ['connected']},
                                import_targets=[target.id], export_targets=[target.id])
                           )
    # create l2vpns
    vxlan1 = list(operator.attrgetter('dcim.interfaces')(nb).filter(**dict(name='Vxlan1')))
    target_rt = list(operator.attrgetter('ipam.route-targets')(nb).all())
    for intf in vxlan1:
        vlans = [operator.attrgetter('ipam.vlans')(nb).get(id=x['id']) for x in intf.custom_fields['evpn_l2vpn']]
        for vlan in vlans:
            rt_param = get_rt(target_rt, vlan.id)
            rd_vlan = f'{intf.device.custom_fields["evpn_asn"]["asn"]}:{vlan.custom_fields["evpn_vni"]}'
            l2vpn_params = dict(identifier=vlan.custom_fields['evpn_vni'], name=f'{str(vlan)}-{str(intf.device)}',
                                slug=slugify.slugify(text=f'{str(vlan)}-{str(intf.device)}'), type="vxlan-evpn",
                                import_targets=[rt_param], export_targets=[rt_param],
                                custom_fields=dict(
                                    rd_vlan=rd_vlan,
                                    redistribute_l2vpn='learned')
                                )
            l2vpn = (
                tmp
                if (tmp := operator.attrgetter('ipam.l2vpns')(nb).get(**dict(name=l2vpn_params['name'],
                                                                             slug=l2vpn_params['slug'],
                                                                             type='vxlan-evpn'))) is not None
                else operator.attrgetter('ipam.l2vpns')(nb).create(l2vpn_params)
            )
            term_params = dict(l2vpn=l2vpn.id, assigned_object_type='ipam.vlan', assigned_object_id=vlan.id)
            term = (
                tmp
                if (tmp := operator.attrgetter('ipam.l2vpn-terminations')(nb).get(**dict(
                    l2vpn_id=term_params['l2vpn'],
                    vlan_id=term_params['assigned_object_id']))
                    ) is not None
                else operator.attrgetter('ipam.l2vpn-terminations')(nb).create(term_params)
            )


def provision_bgp_policies() -> None:
    #pending method, create PR to improve netbox_bgp
    def get_index():
        return [*range(10,200,10)]

    # prefix_dict={}
    _leafs=list(operator.attrgetter('dcim.devices')(nb).filter(**dict(role='leaf')))
    _spines=list(operator.attrgetter('dcim.devices')(nb).filter(**dict(role='spine')))
    for device in _leafs+_spines:
        # ip_addr_lo0,ip_addr_lo1=[operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(device=str(device),
        #                                                                                 interface='Loopback0')),
        # operator.attrgetter('ipam.ip-addresses')(nb).get(**dict(device=str(device),
        #                                                         interface='Loopback1'))]
        # prefix_dict['pl-loopback-evpn-overlay']=dict()
        # index=get_index()
        #
        # if ip_addr_lo0:
        #     prefix_dict['pl-loopback-evpn-overlay'][f'{index.pop(0)}']={'action':'permit',
        #                                                                 'statements':f'{str(ip_addr_lo0)} eq 32'}
        # if ip_addr_lo1:
        #     prefix_dict['pl-loopback-evpn-overlay'][f'{index.pop(0)}']={'action':'permit',
        #                                                                 'statements':f'{str(ip_addr_lo1)} eq 32'}

        local_ctx=device.local_context_data
        local_ctx['routing-policies']={'route-maps':{}}
        index=get_index()
        # local_ctx['routing-policies']['route-maps']['rm-conn-2-bgp']={f'{index.pop(0)}':{'action':'permit',
        #                                                                     'clause':'match',
        #                                                                     'prefix_lists':[prefix_dict]
        #                                                                     },
        #                                                               'redistribute':'connected',
        #                                                               }
        # parameters=all('parameters' in x for x in local_ctx['local-routing']['bgp'])
        for x in local_ctx['local-routing']['bgp']: parameters=True if 'parameters' in x else False
        if parameters is True:
            data=[dic for dic in local_ctx['local-routing']['bgp'] if 'parameters' in dic][0]
            connected=data['parameters']['redistribute']=='connected'
            if connected is False:
                idx=local_ctx['local-routing']['bgp'].index(data)
                local_ctx['local-routing']['bgp'][idx]['parameters'].update(dict(redistribute='connected'))
        else:
            local_ctx['local-routing']['bgp'].append({'parameters':{'redistribute':'connected'}
                                               }
                                                     )
        if device.virtual_chassis:
            index=get_index()
            local_ctx['routing-policies']['route-maps']['rm-mlag-peer-in']={f'{index.pop(0)}':{'action':'permit',
                                                                                  'clause':'set',
                                                                                  'statements':'origin incomplete',
                                                                                  'description':'prefer spines',
                                                                                  'session_in': 'ipv4-mlag-peering',
                                                                                  'session_out': None
                                                                                  },
                                                                            }
        device.update({'local_context_data':local_ctx})



def provision_all():
    provision_customfields()

    provision_orga()

    provision_config_context()

    provision_devices()

    provision_rir_aggregates()

    provision_asns()

    provision_networks()

    provision_management()

    provision_interfaces()

    provision_vlanintf()

    provision_assign_vlans()

    provision_hosts()

    provision_mlag()

    provision_bgp()

    provision_overlay()

    provision_bgp_policies()

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
        _slug = slugify.slugify(text=device_type["model"])
        if operator.attrgetter('dcim.device_types')(nb).filter(**dict(model=device_type["model"])):
            print(f"Found device_type dict {device_type['model']}")
            return True
        elif operator.attrgetter('dcim.device_types')(nb).get(**dict(model=device_type["model"])):
            print(f"Found device_type name {device_type['model']}")
            return True
        elif operator.attrgetter('dcim.device_types')(nb).get(**dict(model=device_type["model"])):
            print(f"Found device_type slug {device_type['slug']}")
            return True
        elif operator.attrgetter('dcim.device_types')(nb).get(**dict(slug=_slug)):
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
    if not operator.attrgetter('dcim.manufacturers')(nb).get(**dict(name=man)):
        print(f"Manufacturer: {man} does not exist")
        new_man = {"name": man, "slug": slugify.slugify(text=man)}
        print(f"Creating manufacturer with: {new_man}")
        operator.attrgetter('dcim.manufacturers')(nb).create(new_man)
    man_id = operator.attrgetter('dcim.manufacturers')(nb).get(**dict(name=man)).id
    print(f"Found manufacturer {man} id: {str(man_id)}")
    return int(man_id)


def create_template(name, template):
    """
    Create a template.
    """
    try:
        if name == "console-ports":
            results = operator.attrgetter('dcim.console_port_templates')(nb).create(template)
        elif name == "console-server-ports":
            results = operator.attrgetter('dcim.console_server_port_templates')(nb).create(template)
        elif name == "power-ports":
            results = operator.attrgetter('dcim.power_port_templates')(nb).create(template)
        elif name == "power-outlets":
            results = operator.attrgetter('dcim.power_outlet_templates')(nb).create(template)
        elif name == "interfaces":
            results = operator.attrgetter('dcim.interface_templates')(nb).create(template)
        elif name == "front-ports":
            results = operator.attrgetter('dcim.front_port_templates')(nb).create(template)
        elif name == "rear-ports":
            results = operator.attrgetter('dcim.rear_port_templates')(nb).create(template)
        elif name == "device-bays":
            results = operator.attrgetter('device_bay_templates')(nb).create(template)
        print(f"Created new {name}: {results.name}")
        return results
    except RequestError:
        print(f"Already have {name}: {template}")
    except Exception as e:
        raise TemplateCreationError(
            f"Failed creating: {name}: {template}\nException: {e}"
        )


def process_templates(device_type) -> None:
    """
    Process the templates.
    """
    try:
        device_type_id = operator.attrgetter('dcim.device_types')(nb).get(**dict(model=device_type["model"])).id
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


def process_device_type(device_type) -> None:
    """
    Validates and verifies the device type before inserting in NetBox.
    """
    device_type = validate_device_data(device_type)
    does_exist = device_type_exists(device_type)
    if does_exist is False:
        print(f"Adding new device-type {device_type['model']}")
        operator.attrgetter('dcim.device_types')(nb).create(device_type)
    else:
        print(f"Already a device_type: {device_type['model']}")
    print(f"Checking for templates: {device_type['model']}")
    process_templates(device_type)


def process_yaml(yml_file) -> None:
    """
    Process a YAML file for importing to NetBox.
    """
    device_type = load_yaml(yml_file)
    process_device_type(device_type)


def process_json() -> None:
    import os
    file = '/home/ec2-user/evpn-cicd-arista-containerlab/ipam.json'
    if os.path.exists(file):
        global ipams
        with open(file, 'r') as read_file:
            ipams = json.load(read_file)


if __name__ == "__main__":
    # Execute when the module is not initialized from an import statement.
    provision_all()
