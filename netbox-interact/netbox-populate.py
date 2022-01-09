import pynetbox
import requests
import urllib3
import yaml

urllib3.disable_warnings()


def get_netbox():
    """
    Return Netbox API handler

    Returns:
        pynetbox.API -- Netbox API handler
    """

    nburl = "http://0.0.0.0:8000/"
    NETBOX_TOKEN = "0123456789abcdef0123456789abcdef01234567"
    session = requests.Session()
    session.verify = False  # https://pynetbox.readthedocs.io/en/latest/advanced.html#ssl-verification
    nb = pynetbox.api(url=nburl, token=NETBOX_TOKEN, threading=True)
    nb.http_session = session

    return nb


nb = get_netbox()

STATUS = {
    x["display_name"].lower(): i
    for i, x in enumerate(nb.dcim.devices.choices()["status"])
}


def create_devices(evpnlab):

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


with open("evpnlab-tiny.yml") as fh:
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

    return nb_object


tenant_rainbow = get_or_create(nb.tenancy.tenants, name="Rainbow", slug="rainbow")

site_palette = get_or_create(nb.dcim.sites, name="Palette", slug="palette")
site_palette.tenant = tenant_rainbow
site_palette.save()


role_spine = get_or_create(nb.dcim.device_roles, name="spine", slug="spine")
role_leaf = get_or_create(nb.dcim.device_roles, name="leaf", slug="leaf")
role_server = get_or_create(nb.dcim.device_roles, name="server", slug="server")
manuf_arista = get_or_create(nb.dcim.manufacturers, name="Arista", slug="arista")
manuf_linux = get_or_create(nb.dcim.manufacturers, name="Linux", slug="linux")

devicetype_ceos = get_or_create(
    nb.dcim.device_types,
    model="cEOS-LAB",
    manufacturer=manuf_arista.id,
    slug="ceos-lab",
)
devicetype_alpine = get_or_create(
    nb.dcim.device_types, model="Alpine", manufacturer=manuf_linux.id, slug="alpine"
)


# TODO import device library
# https://gist.github.com/AdamEldred/f83105446c6ceb1b13dccad661ade428


create_devices(evpnlab)
spines = [x for x in nb.dcim.devices.filter(role="spine")]
leafs = [x for x in nb.dcim.devices.filter(role="leaf")]


#### ASN Creation and assignment ###

cf_asn = get_or_create(
    nb.extras.custom_fields,
    search="name",
    name="evpn_asn",
    content_types=["dcim.device"],
    type="integer",
    label="EVPN ASN",
)


leafrange = [*range(65100, 65199)]
spinerange = [*range(65001, 65099)]


for device in leafs:
    if (asn := device.custom_fields.get("evpn_asn")) is not None:
        print(asn)
        leafrange.remove(asn)

for device in spines:
    if (asn := device.custom_fields.get("evpn_asn")) is not None:
        spinerange.remove(asn)

for device in leafs:
    if device.custom_fields.get("evpn_asn") is None:
        device.custom_fields.update({"evpn_asn": leafrange.pop(0)})
        device.save()

for device in spines:
    if device.custom_fields.get("evpn_asn") is None:
        device.custom_fields.update({"evpn_asn": spinerange.pop(0)})
        device.save()

#### END OF ASN Creation and assignment ###


evpn_loopback = get_or_create(nb.ipam.roles, name="evpn-loopback", slug="evpn-loopback")
evpn_underlay = get_or_create(nb.ipam.roles, name="evpn-underlay", slug="evpn-underlay")
evpn_vtep = get_or_create(nb.ipam.roles, name="evpn-vtep", slug="evpn-vtep")

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
        raw_intf_name = raw_intf_name.replace("eth", "Eth")
    return device, nb.dcim.interfaces.get(device=raw_device_name, name=raw_intf_name)


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
                termination_a_type="dcim.interface",
                termination_a_id=left_intf.id,
                termination_b_type="dcim.interface",
                termination_b_id=right_intf.id,
            )
        )
        is not None
        else nb.dcim.cables.create(
            termination_a_type="dcim.interface",
            termination_a_id=left_intf.id,
            termination_b_type="dcim.interface",
            termination_b_id=right_intf.id,
        )
    )
    link_spine_leaf = all(
        [str(x.device_role) in ["spine", "leaf"] for x in [left_device, right_device]]
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


for device in leafs + spines:

    def assign_ip(lo):
        if lo.count_ipaddresses < 1:
            loip= ippool.available_ips.create()
            loip.assigned_object_id = lo.id
            loip.assigned_object_type = "dcim.interface"
            loip.save()

    loop_list = [
        ("Loopback0", "EVPN_Overlay_Peering",prefix_loopback),
        ("Loopback1", "VTEP_VXLAN_Tunnel_Source",prefix_vtep),
    ]
    for intf_name, description,ippool in loop_list:
        intf_data = {
            "name": intf_name,
            "type": "virtual",
            "description": description,
            "device": device.id,
        }
        if intf_name == "Loopback0":
            lo = get_or_create(nb.dcim.interfaces, search="intf", **intf_data)
            assign_ip(lo)
        elif (intf_name == "Loopback1") and (str(device.device_role) == "leaf"):
            lo = get_or_create(nb.dcim.interfaces, search="intf", **intf_data)
            assign_ip(lo)

# Create VLAN Group

# Create Tags