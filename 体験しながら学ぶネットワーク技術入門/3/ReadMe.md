Setup

```
tinet down -c /mnt/c/tinet/spec_03.yaml | sh -x
tinet up -c /mnt/c/tinet/spec_03.yaml | sh -x
tinet conf -c /mnt/c/tinet/spec_03.yaml | sh -x
tinet test -c /mnt/c/tinet/spec_03.yaml | sh -x
```

## IP

cl1

```
docker exec -it cl1 /bin/bash
root@cl1:/# ifconfig
net0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.11.1  netmask 255.255.255.0  broadcast 192.168.11.255
        inet6 fe80::c4ab:f7ff:fef5:b8ee  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:01:10:01  txqueuelen 1000  (Ethernet)
        RX packets 27  bytes 3046 (3.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1900 (1.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@cl1:/# ping 192.168.11.2 -c 2
PING 192.168.11.2 (192.168.11.2) 56(84) bytes of data.
64 bytes from 192.168.11.2: icmp_seq=1 ttl=64 time=0.610 ms
64 bytes from 192.168.11.2: icmp_seq=2 ttl=64 time=0.475 ms

--- 192.168.11.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1025ms
rtt min/avg/max/mdev = 0.475/0.542/0.610/0.067 ms
```

cl2

```
docker exec -it cl2 /bin/bash
root@cl2:/# ifconfig
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

net0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.11.2  netmask 255.255.255.0  broadcast 192.168.11.255
        inet6 fe80::c92:78ff:feee:7dcc  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:01:10:02  txqueuelen 1000  (Ethernet)
        RX packets 47  bytes 5422 (5.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 27  bytes 2962 (2.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@cl2:/# tcpdump -i net0 host 192.168.11.1 -w /tmp/tinet/ip.pcapng
```

## ICMP

```
root@UBUNTU:/mnt/c/Users/masami# docker exec -it cl1 /bin/bash
root@cl1:/# ifconfig net0
net0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.11.1  netmask 255.255.255.0  broadcast 192.168.11.255
        inet6 fe80::d89a:e2ff:fe2f:a5e5  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:01:10:01  txqueuelen 1000  (Ethernet)
        RX packets 34  bytes 3536 (3.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 17  bytes 1802 (1.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

```
root@UBUNTU:/mnt/c/Users/masami#  docker exec -it cl2 /bin/bash
root@cl2:/# ifconfig net0
net0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.11.2  netmask 255.255.255.0  broadcast 192.168.11.255
        inet6 fe80::ceb:afff:fe12:f00d  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:01:10:02  txqueuelen 1000  (Ethernet)
        RX packets 34  bytes 3536 (3.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 17  bytes 1802 (1.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@cl2:/# tcpdump -i net0 -w /tmp/tinet/icmp.pcapng icmp[7] == 1
tcpdump: listening on net0, link-type EN10MB (Ethernet), capture size 262144 bytes
```

```
root@cl1:/# ping 192.168.11.2 -c 2
PING 192.168.11.2 (192.168.11.2) 56(84) bytes of data.
64 bytes from 192.168.11.2: icmp_seq=1 ttl=64 time=0.766 ms
64 bytes from 192.168.11.2: icmp_seq=2 ttl=64 time=0.416 ms

--- 192.168.11.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1030ms
rtt min/avg/max/mdev = 0.416/0.591/0.766/0.175 ms
```

## static routing

```
root@UBUNTU:/mnt/c/Users/masami# docker exec -it fw1 /bin/bash
```

```
root@UBUNTU:/mnt/c/Users/masami# docker exec -it rt1 /bin/bash
root@rt1:/# ping 10.1.1.253 -c 2
ping: connect: Network is unreachable

root@rt1:/# vtysh

Hello, this is FRRouting (version 8.4.1).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

rt1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

C>* 10.1.1.244/30 is directly connected, net0, 00:05:50
C>* 192.168.11.0/24 is directly connected, net1, 00:05:50
rt1# configure terminal
rt1(config)# ip route 0.0.0.0/0 10.1.1.246
rt1(config)# exit

rt1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.1.1.246, net0, weight 1, 00:00:32
C>* 10.1.1.244/30 is directly connected, net0, 00:08:48
C>* 192.168.11.0/24 is directly connected, net1, 00:08:48

rt1# exit
root@rt1:/# ping 10.1.1.253 -c 2
PING 10.1.1.253 (10.1.1.253) 56(84) bytes of data.

--- 10.1.1.253 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1026ms
```

```
root@UBUNTU:/mnt/c/Users/masami# docker exec -it rt2 /bin/bash
root@rt2:/# vtysh

Hello, this is FRRouting (version 8.4.1).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

rt2# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

C>* 10.1.1.244/30 is directly connected, net0, 00:15:41
C>* 10.1.1.248/30 is directly connected, net1, 00:15:41
C>* 10.1.1.252/30 is directly connected, net2, 00:15:41
```

```
fw1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

C>* 10.1.1.252/30 is directly connected, net0, 00:16:44
C>* 172.16.1.0/24 is directly connected, net1, 00:16:43
fw1# configure terminal
fw1(config)# ip route 0.0.0.0/0 10.1.1.254
fw1(config)# exit
fw1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.1.1.254, net0, weight 1, 00:00:11
C>* 10.1.1.252/30 is directly connected, net0, 00:18:19
C>* 172.16.1.0/24 is directly connected, net1, 00:18:18
```

```
root@rt1:/# ping 10.1.1.253 -c 2
PING 10.1.1.253 (10.1.1.253) 56(84) bytes of data.
64 bytes from 10.1.1.253: icmp_seq=1 ttl=63 time=0.079 ms
64 bytes from 10.1.1.253: icmp_seq=2 ttl=63 time=0.102 ms

--- 10.1.1.253 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1047ms
rtt min/avg/max/mdev = 0.079/0.090/0.102/0.011 ms
root@rt1:/# traceroute 10.1.1.253
traceroute to 10.1.1.253 (10.1.1.253), 30 hops max, 60 byte packets
 1  10.1.1.246 (10.1.1.246)  0.061 ms  0.016 ms  0.015 ms
 2  10.1.1.253 (10.1.1.253)  0.028 ms  0.019 ms  0.016 ms
```

## dynamic routing

```
root@rt1:/# ping 10.1.2.53 -c 2
PING 10.1.2.53 (10.1.2.53) 56(84) bytes of data.
From 10.1.1.246 icmp_seq=1 Destination Net Unreachable
From 10.1.1.246 icmp_seq=2 Destination Net Unreachable

--- 10.1.2.53 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1060ms
```

```
root@rt2:/# vtysh
rt2# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

C>* 10.1.1.244/30 is directly connected, net0, 00:15:41
C>* 10.1.1.248/30 is directly connected, net1, 00:15:41
C>* 10.1.1.252/30 is directly connected, net2, 00:15:41

rt2# configure terminal
rt2(config)# router ospf
rt2(config-router)# network 10.1.1.246/32 area 0
rt2(config-router)# network 10.1.1.250/32 area 0
rt2(config-router)# network 10.1.1.254/32 area 0
rt2(config-router)# interface net0
rt2(config-if)# ip ospf passive
rt2(config-if)# interface net2
rt2(config-if)# ip ospf passive
rt2(config-if)# end

rt2# show ip ospf interface
net0 is up
  ifindex 2, MTU 1500 bytes, BW 10000 Mbit <UP,BROADCAST,RUNNING,MULTICAST>
  Internet Address 10.1.1.246/30, Broadcast 10.1.1.247, Area 0.0.0.0
  MTU mismatch detection: enabled
  Router ID 10.1.1.254, Network Type BROADCAST, Cost: 10
  Transmit Delay is 1 sec, State DR, Priority 1
  Designated Router (ID) 10.1.1.254 Interface Address 10.1.1.246/30
  No backup designated router on this network
  Multicast group memberships: <None>
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
    No Hellos (Passive interface)
  Neighbor Count is 0, Adjacent neighbor count is 0
net1 is up
  ifindex 3, MTU 1500 bytes, BW 10000 Mbit <UP,BROADCAST,RUNNING,MULTICAST>
  Internet Address 10.1.1.250/30, Broadcast 10.1.1.251, Area 0.0.0.0
  MTU mismatch detection: enabled
  Router ID 10.1.1.254, Network Type BROADCAST, Cost: 10
  Transmit Delay is 1 sec, State DR, Priority 1
  Designated Router (ID) 10.1.1.254 Interface Address 10.1.1.250/30
  No backup designated router on this network
  Multicast group memberships: OSPFAllRouters OSPFDesignatedRouters
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
    Hello due in 9.314s
  Neighbor Count is 0, Adjacent neighbor count is 0
net2 is up
  ifindex 4, MTU 1500 bytes, BW 10000 Mbit <UP,BROADCAST,RUNNING,MULTICAST>
  Internet Address 10.1.1.254/30, Broadcast 10.1.1.255, Area 0.0.0.0
  MTU mismatch detection: enabled
  Router ID 10.1.1.254, Network Type BROADCAST, Cost: 10
  Transmit Delay is 1 sec, State DR, Priority 1
  Designated Router (ID) 10.1.1.254 Interface Address 10.1.1.254/30
  No backup designated router on this network
  Multicast group memberships: <None>
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
    No Hellos (Passive interface)
  Neighbor Count is 0, Adjacent neighbor count is 0

rt2# show ip ospf neighbor

Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL

```

```
rt3# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

C>* 10.1.1.248/30 is directly connected, net0, 00:50:19
C>* 10.1.2.0/24 is directly connected, net1, 00:50:19
rt3# configure terminal
rt3(config)# router ospf
rt3(config-router)# network 10.1.1.249/32 area 0
rt3(config-router)# network 10.1.2.254/32 area 0
rt3(config-router)# interface net1
rt3(config-if)# ip ospf passive
rt3(config-if)# end

rt3# show ip ospf interface
net0 is up
  ifindex 2, MTU 1500 bytes, BW 10000 Mbit <UP,BROADCAST,RUNNING,MULTICAST>
  Internet Address 10.1.1.249/30, Broadcast 10.1.1.251, Area 0.0.0.0
  MTU mismatch detection: enabled
  Router ID 10.1.2.254, Network Type BROADCAST, Cost: 10
  Transmit Delay is 1 sec, State Backup, Priority 1
  Designated Router (ID) 10.1.1.254 Interface Address 10.1.1.250/30
  Backup Designated Router (ID) 10.1.2.254, Interface Address 10.1.1.249
  Multicast group memberships: OSPFAllRouters OSPFDesignatedRouters
  Timer intervals configured, Hello 10s, Dead 40s, Wait 40s, Retransmit 5
    Hello due in 0.579s
  Neighbor Count is 1, Adjacent neighbor count is 1

rt3# show ip ospf neighbor

Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL
10.1.1.254        1 Full/DR         2m03s             36.814s 10.1.1.250      net0:10.1.1.249                      0     0     0

rt3# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

O>* 10.1.1.244/30 [110/20] via 10.1.1.250, net0, weight 1, 00:02:14
O   10.1.1.248/30 [110/10] is directly connected, net0, weight 1, 00:02:24
C>* 10.1.1.248/30 is directly connected, net0, 00:21:01
O>* 10.1.1.252/30 [110/20] via 10.1.1.250, net0, weight 1, 00:02:14
O   10.1.2.0/24 [110/10] is directly connected, net1, weight 1, 00:01:41
C>* 10.1.2.0/24 is directly connected, net1, 00:21:01
```

```
root@rt1:/# ping 10.1.2.53 -c 2
PING 10.1.2.53 (10.1.2.53) 56(84) bytes of data.
From 10.1.1.246 icmp_seq=1 Destination Net Unreachable
From 10.1.1.246 icmp_seq=2 Destination Net Unreachable

--- 10.1.2.53 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1071ms
```

```
root@UBUNTU:/mnt/c/Users/masami#  docker exec -it ns1 /bin/bash
root@ns1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
10.1.2.0        0.0.0.0         255.255.255.0   U     0      0        0 net0
root@ns1:/# route add default gw 10.1.2.254
root@ns1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.1.2.254      0.0.0.0         UG    0      0        0 net0
10.1.2.0        0.0.0.0         255.255.255.0   U     0      0        0 net0
```

```
root@rt1:/# ping 10.1.2.53 -c 2
PING 10.1.2.53 (10.1.2.53) 56(84) bytes of data.
64 bytes from 10.1.2.53: icmp_seq=1 ttl=62 time=0.084 ms
64 bytes from 10.1.2.53: icmp_seq=2 ttl=62 time=0.098 ms

--- 10.1.2.53 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1048ms
rtt min/avg/max/mdev = 0.084/0.091/0.098/0.007 ms
root@rt1:/# traceroute 10.1.2.53
traceroute to 10.1.2.53 (10.1.2.53), 30 hops max, 60 byte packets
 1  10.1.1.246 (10.1.1.246)  0.066 ms  0.010 ms  0.044 ms
 2  10.1.1.249 (10.1.1.249)  0.046 ms  0.020 ms  0.023 ms
 3  10.1.2.53 (10.1.2.53)  0.040 ms  0.030 ms  0.026 ms
```

## NAT

```
root@ns1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.1.2.254      0.0.0.0         UG    0      0        0 net0
10.1.2.0        0.0.0.0         255.255.255.0   U     0      0        0 net0

```

```
rt3# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

O>* 10.1.1.244/30 [110/20] via 10.1.1.250, net0, weight 1, 00:02:14
O   10.1.1.248/30 [110/10] is directly connected, net0, weight 1, 00:02:24
C>* 10.1.1.248/30 is directly connected, net0, 00:21:01
O>* 10.1.1.252/30 [110/20] via 10.1.1.250, net0, weight 1, 00:02:14
O   10.1.2.0/24 [110/10] is directly connected, net1, weight 1, 00:01:41
C>* 10.1.2.0/24 is directly connected, net1, 00:21:01
```

```
rt2# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

O   10.1.1.244/30 [110/10] is directly connected, net0, weight 1, 01:21:17
C>* 10.1.1.244/30 is directly connected, net0, 01:36:42
O   10.1.1.248/30 [110/10] is directly connected, net1, weight 1, 01:21:13
C>* 10.1.1.248/30 is directly connected, net1, 01:36:42
O   10.1.1.252/30 [110/10] is directly connected, net2, weight 1, 01:21:03
C>* 10.1.1.252/30 is directly connected, net2, 01:36:41
O>* 10.1.2.0/24 [110/20] via 10.1.1.249, net1, weight 1, 01:17:20
rt2# configure terminal
rt2(config)# ip route 10.1.3.0/24 10.1.1.253
rt2(config)# router ospf
rt2(config-router)# redistribute static
```

```
rt3# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

O>* 10.1.1.244/30 [110/20] via 10.1.1.250, net0, weight 1, 01:20:34
O   10.1.1.248/30 [110/10] is directly connected, net0, weight 1, 01:20:44
C>* 10.1.1.248/30 is directly connected, net0, 01:39:21
O>* 10.1.1.252/30 [110/20] via 10.1.1.250, net0, weight 1, 01:20:34
O   10.1.2.0/24 [110/10] is directly connected, net1, weight 1, 01:20:01
C>* 10.1.2.0/24 is directly connected, net1, 01:39:21
O>* 10.1.3.0/24 [110/20] via 10.1.1.250, net0, weight 1, 00:01:18
```

```
fw1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.1.1.254, net0, weight 1, 01:31:26
C>* 10.1.1.252/30 is directly connected, net0, 01:41:23
C>* 172.16.1.0/24 is directly connected, net1, 01:41:23
fw1# configure terminal
fw1(config)# ip route 172.16.2.0/24 172.16.1.253
fw1(config)# exit
fw1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.1.1.254, net0, weight 1, 01:32:56
C>* 10.1.1.252/30 is directly connected, net0, 01:42:53
C>* 172.16.1.0/24 is directly connected, net1, 01:42:53
S>* 172.16.2.0/24 [1/0] via 172.16.1.253, net1, weight 1, 00:00:34
fw1# exit
```

```
root@UBUNTU:/mnt/c/Users/masami# docker exec -it lb1 /bin/bash
root@lb1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
172.16.1.0      0.0.0.0         255.255.255.0   U     0      0        0 net0
172.16.2.0      0.0.0.0         255.255.255.0   U     0      0        0 net0.2
root@lb1:/# route add default gw 172.16.1.254
root@lb1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.16.1.254    0.0.0.0         UG    0      0        0 net0
172.16.1.0      0.0.0.0         255.255.255.0   U     0      0        0 net0
172.16.2.0      0.0.0.0         255.255.255.0   U     0      0        0 net0.2
```

```
root@UBUNTU:/mnt/c/Users/masami#  docker exec -it sv1 /bin/bash
root@sv1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
172.16.2.0      0.0.0.0         255.255.255.0   U     0      0        0 net0
root@sv1:/# route add default gw 172.16.2.254
root@sv1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.16.2.254    0.0.0.0         UG    0      0        0 net0
172.16.2.0      0.0.0.0         255.255.255.0   U     0      0        0 net0

root@UBUNTU:/mnt/c/Users/masami# docker exec -it sv2 /bin/bash
root@sv2:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
172.16.2.0      0.0.0.0         255.255.255.0   U     0      0        0 net0
root@sv2:/# route add default gw 172.16.2.254
root@sv2:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.16.2.254    0.0.0.0         UG    0      0        0 net0
172.16.2.0      0.0.0.0         255.255.255.0   U     0      0        0 net0
```

```
root@fw1:/# iptables -t nat -A PREROUTING  -d 10.1.3.1 -j DNAT --to-destination 172.16.2.1
root@fw1:/# iptables -t nat -A PREROUTING  -d 10.1.3.2 -j DNAT --to-destination 172.16.2.2
root@fw1:/# iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination
DNAT       all  --  anywhere             10.1.3.1             to:172.16.2.1
DNAT       all  --  anywhere             10.1.3.2             to:172.16.2.2

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
```

```
root@ns1:/# ping 10.1.3.1 -c 1
PING 10.1.3.1 (10.1.3.1) 56(84) bytes of data.
64 bytes from 10.1.3.1: icmp_seq=1 ttl=60 time=1.48 ms

--- 10.1.3.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.482/1.482/1.482/0.000 ms
root@ns1:/# ping 10.1.3.2 -c 1
PING 10.1.3.2 (10.1.3.2) 56(84) bytes of data.
64 bytes from 10.1.3.2: icmp_seq=1 ttl=60 time=1.33 ms

--- 10.1.3.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.331/1.331/1.331/0.000 ms
```

```
root@fw1:/# tcpdump -ni any icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
20:57:12.984081 IP 10.1.2.53 > 10.1.3.1: ICMP echo request, id 20, seq 1, length 64
20:57:12.984213 IP 10.1.2.53 > 172.16.2.1: ICMP echo request, id 20, seq 1, length 64
20:57:12.985042 IP 172.16.2.1 > 10.1.2.53: ICMP echo reply, id 20, seq 1, length 64
20:57:12.985067 IP 10.1.3.1 > 10.1.2.53: ICMP echo reply, id 20, seq 1, length 64
20:57:31.601810 IP 10.1.2.53 > 10.1.3.2: ICMP echo request, id 21, seq 1, length 64
20:57:31.601911 IP 10.1.2.53 > 172.16.2.2: ICMP echo request, id 21, seq 1, length 64
20:57:31.602930 IP 172.16.2.2 > 10.1.2.53: ICMP echo reply, id 21, seq 1, length 64
20:57:31.602989 IP 10.1.3.2 > 10.1.2.53: ICMP echo reply, id 21, seq 1, length 64
```

## NAPT

```
root@UBUNTU:/mnt/c/Users/masami# docker exec -it cl1 /bin/bash
root@cl1:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.11.254  0.0.0.0         UG    0      0        0 net0
192.168.11.0    0.0.0.0         255.255.255.0   U     0      0        0 net0

root@UBUNTU:/mnt/c/Users/masami# docker exec -it cl3 /bin/bash
root@cl3:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
192.168.11.0    0.0.0.0         255.255.255.0   U     0      0        0 net0
root@cl3:/# route add default gw 192.168.11.254
root@cl3:/# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.11.254  0.0.0.0         UG    0      0        0 net0
192.168.11.0    0.0.0.0         255.255.255.0   U     0      0        0 net0
```

```
rt1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.1.1.246, net0, weight 1, 02:18:46
C>* 10.1.1.244/30 is directly connected, net0, 02:23:58
C>* 192.168.11.0/24 is directly connected, net1, 02:23:58
rt1# exit
root@rt1:/# iptables -t nat -A POSTROUTING -s 192.168.11.0/24 -j MASQUERADE

root@rt1:/# iptables -t nat -A POSTROUTING -s 192.168.11.0/24 -j MASQUERADE
root@rt1:/# iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
MASQUERADE  all  --  192.168.11.0/24      anywhere
```

```
root@cl1:/# ping 10.1.2.53 -c 1
PING 10.1.2.53 (10.1.2.53) 56(84) bytes of data.
64 bytes from 10.1.2.53: icmp_seq=1 ttl=61 time=0.768 ms

--- 10.1.2.53 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.768/0.768/0.768/0.000 ms

root@cl2:/# ping 10.1.2.53 -c 1
PING 10.1.2.53 (10.1.2.53) 56(84) bytes of data.
64 bytes from 10.1.2.53: icmp_seq=1 ttl=61 time=1.11 ms

--- 10.1.2.53 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.105/1.105/1.105/0.000 ms

root@cl3:/# ping 10.1.2.53 -c 1
PING 10.1.2.53 (10.1.2.53) 56(84) bytes of data.
64 bytes from 10.1.2.53: icmp_seq=1 ttl=61 time=1.40 ms

--- 10.1.2.53 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.398/1.398/1.398/0.000 ms
```

```
root@rt1:/# tcpdump -ni any icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
21:18:03.110399 IP 192.168.11.1 > 10.1.2.53: ICMP echo request, id 26, seq 1, length 64
21:18:03.110709 IP 10.1.1.245 > 10.1.2.53: ICMP echo request, id 26, seq 1, length 64
21:18:03.110747 IP 10.1.2.53 > 10.1.1.245: ICMP echo reply, id 26, seq 1, length 64
21:18:03.110755 IP 10.1.2.53 > 192.168.11.1: ICMP echo reply, id 26, seq 1, length 64
21:18:05.403179 IP 192.168.11.100 > 10.1.2.53: ICMP echo request, id 27, seq 1, length 64
21:18:05.413557 IP 10.1.1.245 > 10.1.2.53: ICMP echo request, id 27, seq 1, length 64
21:18:05.413661 IP 10.1.2.53 > 10.1.1.245: ICMP echo reply, id 27, seq 1, length 64
21:18:05.413676 IP 10.1.2.53 > 192.168.11.100: ICMP echo reply, id 27, seq 1, length 64
21:18:07.841074 IP 192.168.11.2 > 10.1.2.53: ICMP echo request, id 28, seq 1, length 64
21:18:07.841811 IP 10.1.1.245 > 10.1.2.53: ICMP echo request, id 28, seq 1, length 64
21:18:07.841902 IP 10.1.2.53 > 10.1.1.245: ICMP echo reply, id 28, seq 1, length 64
21:18:07.841913 IP 10.1.2.53 > 192.168.11.2: ICMP echo reply, id 28, seq 1, length 64
```
