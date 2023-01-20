# DC1_FABRIC

# Table of Contents

- [Fabric Switches and Management IP](#fabric-switches-and-management-ip)
  - [Fabric Switches with inband Management IP](#fabric-switches-with-inband-management-ip)
- [Fabric Topology](#fabric-topology)
- [Fabric IP Allocation](#fabric-ip-allocation)
  - [Fabric Point-To-Point Links](#fabric-point-to-point-links)
  - [Point-To-Point Links Node Allocation](#point-to-point-links-node-allocation)
  - [Loopback Interfaces (BGP EVPN Peering)](#loopback-interfaces-bgp-evpn-peering)
  - [Loopback0 Interfaces Node Allocation](#loopback0-interfaces-node-allocation)
  - [VTEP Loopback VXLAN Tunnel Source Interfaces (VTEPs Only)](#vtep-loopback-vxlan-tunnel-source-interfaces-vteps-only)
  - [VTEP Loopback Node allocation](#vtep-loopback-node-allocation)

# Fabric Switches and Management IP

| POD | Type | Node | Management IP | Platform | Provisioned in CloudVision |
| --- | ---- | ---- | ------------- | -------- | -------------------------- |
| DC1_FABRIC | l3leaf | clab-evpnlab-leaf1 | 172.100.100.4/24 | cEOS-LAB | Provisioned |
| DC1_FABRIC | l3leaf | clab-evpnlab-leaf2 | 172.100.100.5/24 | cEOS-LAB | Provisioned |
| DC1_FABRIC | spine | clab-evpnlab-spine1 | 172.100.100.11/24 | cEOS-LAB | Provisioned |
| DC1_FABRIC | spine | clab-evpnlab-spine2 | 172.100.100.12/24 | cEOS-LAB | Provisioned |

> Provision status is based on Ansible inventory declaration and do not represent real status from CloudVision.

## Fabric Switches with inband Management IP
| POD | Type | Node | Management IP | Inband Interface |
| --- | ---- | ---- | ------------- | ---------------- |

# Fabric Topology

| Type | Node | Node Interface | Peer Type | Peer Node | Peer Interface |
| ---- | ---- | -------------- | --------- | ----------| -------------- |
| l3leaf | clab-evpnlab-leaf1 | Ethernet1 | spine | clab-evpnlab-spine1 | Ethernet1 |
| l3leaf | clab-evpnlab-leaf1 | Ethernet2 | spine | clab-evpnlab-spine2 | Ethernet1 |
| l3leaf | clab-evpnlab-leaf2 | Ethernet1 | spine | clab-evpnlab-spine1 | Ethernet2 |
| l3leaf | clab-evpnlab-leaf2 | Ethernet2 | spine | clab-evpnlab-spine2 | Ethernet2 |

# Fabric IP Allocation

## Fabric Point-To-Point Links

| Uplink IPv4 Pool | Available Addresses | Assigned addresses | Assigned Address % |
| ---------------- | ------------------- | ------------------ | ------------------ |
| 172.31.255.0/24 | 256 | 8 | 3.13 % |

## Point-To-Point Links Node Allocation

| Node | Node Interface | Node IP Address | Peer Node | Peer Interface | Peer IP Address |
| ---- | -------------- | --------------- | --------- | -------------- | --------------- |
| clab-evpnlab-leaf1 | Ethernet1 | 172.31.255.1/31 | clab-evpnlab-spine1 | Ethernet1 | 172.31.255.0/31 |
| clab-evpnlab-leaf1 | Ethernet2 | 172.31.255.3/31 | clab-evpnlab-spine2 | Ethernet1 | 172.31.255.2/31 |
| clab-evpnlab-leaf2 | Ethernet1 | 172.31.255.5/31 | clab-evpnlab-spine1 | Ethernet2 | 172.31.255.4/31 |
| clab-evpnlab-leaf2 | Ethernet2 | 172.31.255.7/31 | clab-evpnlab-spine2 | Ethernet2 | 172.31.255.6/31 |

## Loopback Interfaces (BGP EVPN Peering)

| Loopback Pool | Available Addresses | Assigned addresses | Assigned Address % |
| ------------- | ------------------- | ------------------ | ------------------ |
| 192.168.255.0/24 | 256 | 4 | 1.57 % |

## Loopback0 Interfaces Node Allocation

| POD | Node | Loopback0 |
| --- | ---- | --------- |
| DC1_FABRIC | clab-evpnlab-leaf1 | 192.168.255.30/32 |
| DC1_FABRIC | clab-evpnlab-leaf2 | 192.168.255.31/32 |
| DC1_FABRIC | clab-evpnlab-spine1 | 192.168.255.10/32 |
| DC1_FABRIC | clab-evpnlab-spine2 | 192.168.255.11/32 |

## VTEP Loopback VXLAN Tunnel Source Interfaces (VTEPs Only)

| VTEP Loopback Pool | Available Addresses | Assigned addresses | Assigned Address % |
| --------------------- | ------------------- | ------------------ | ------------------ |
| 192.168.254.0/24 | 256 | 2 | 0.79 % |

## VTEP Loopback Node allocation

| POD | Node | Loopback1 |
| --- | ---- | --------- |
| DC1_FABRIC | clab-evpnlab-leaf1 | 192.168.254.30/32 |
| DC1_FABRIC | clab-evpnlab-leaf2 | 192.168.254.31/32 |
