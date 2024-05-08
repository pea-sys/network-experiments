Setup

```
tinet down -c /mnt/c/tinet/spec_04.yaml | sh -x
tinet up -c /mnt/c/tinet/spec_04.yaml | sh -x
tinet conf -c /mnt/c/tinet/spec_04.yaml | sh -x
tinet test -c /mnt/c/tinet/spec_04.yaml | sh -x
```

## UDP

```
#UDPサーバ起動
root@ns1:/# nc -ul 50000
#受信ポート確認
root@ns1:/# ss -lnup
State      Recv-Q     Send-Q         Local Address:Port          Peer Address:Port     Process
UNCONN     0          0                    0.0.0.0:50000              0.0.0.0:*         users:(("nc",pid=134,fd=3))
UNCONN     0          0                    0.0.0.0:53                 0.0.0.0:*         users:(("unbound",pid=110,fd=3))
#パケットキャプチャ準備
root@ns1:/# tcpdump -i net0 -w /tmp/tinet/udp.pcapng udp port 50000
tcpdump: listening on net0, link-type EN10MB (Ethernet), capture size 262144 bytes
#クライアントからUDP送信
root@cl1:/# nc -u 10.1.2.53 50000
Hello
```

サーバに受信データが表示される

```
root@ns1:/# nc -ul 50000
Hello
```

## TCP

```
#TCPセグメント受信準備
root@ns1:/# nc -l 60000 < /var/tmp/10KB
#LISTEN状態確認
root@ns1:/# ss -nltp
State     Recv-Q    Send-Q        Local Address:Port          Peer Address:Port    Process
LISTEN    0         256                 0.0.0.0:53                 0.0.0.0:*        users:(("unbound",pid=110,fd=4))
LISTEN    0         1                   0.0.0.0:60000              0.0.0.0:*        users:(("nc",pid=134,fd=3))
LISTEN    0         256               127.0.0.1:8953               0.0.0.0:*        users:(("unbound",pid=110,fd=5))
```

```
#パケットキャプチャ準備
root@ns1:/# tcpdump -i net0 -w /tmp/tinet/tcp.pcapng tcp port 60000
tcpdump: listening on net0, link-type EN10MB (Ethernet), capture size 262144 bytes
#クライアントからTCP送信
root@cl1:/# nc -v 10.1.2.53 60000 > /dev/null
Connection to 10.1.2.53 60000 port [tcp/*] succeeded!
```

## FW(UDP)

```
#fwからlbのDNSサーバーへのルート確保
root@fw1:/# vtysh

Hello, this is FRRouting (version 8.4.1).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

fw1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.1.1.254, net0, weight 1, 00:07:39
C>* 10.1.1.252/30 is directly connected, net0, 00:07:40
C>* 172.16.1.0/24 is directly connected, net1, 00:07:40
S>* 172.16.2.0/24 [1/0] via 172.16.1.253, net1, weight 1, 00:07:39
fw1# configure terminal
fw1(config)# ip route 172.16.3.0/24 172.16.1.253
fw1(config)# exit
fw1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.1.1.254, net0, weight 1, 00:10:35
C>* 10.1.1.252/30 is directly connected, net0, 00:10:36
C>* 172.16.1.0/24 is directly connected, net1, 00:10:36
S>* 172.16.2.0/24 [1/0] via 172.16.1.253, net1, weight 1, 00:10:35
S>* 172.16.3.0/24 [1/0] via 172.16.1.253, net1, weight 1, 00:00:08
fw1#exit

#静的NAT設定
root@fw1:/# iptables -t nat -A PREROUTING -d 10.1.3.53 -j DNAT --to 172.16.3.53
root@fw1:/# iptables -t nat -nL PREROUTING
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination
DNAT       all  --  0.0.0.0/0            10.1.3.1             to:172.16.2.1
DNAT       all  --  0.0.0.0/0            10.1.3.2             to:172.16.2.2
DNAT       all  --  0.0.0.0/0            10.1.3.53            to:172.16.3.53

#FWルール設定
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -p icmp -m icmp --icmp-type echo-request -j ACCEPT
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.53 -p udp -m udp --dport 53 -j ACCEPT
root@fw1:/# iptables -t filter -P FORWARD DROP
root@fw1:/# iptables -t filter -vnL FORWARD --line-numbers
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2        0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
```

```
#疎通確認
root@ns1:/# ping 10.1.3.1 -c 2
PING 10.1.3.1 (10.1.3.1) 56(84) bytes of data.
64 bytes from 10.1.3.1: icmp_seq=1 ttl=60 time=1.12 ms
64 bytes from 10.1.3.1: icmp_seq=2 ttl=60 time=0.514 ms

--- 10.1.3.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.514/0.818/1.123/0.304 ms
root@ns1:/# ping 10.1.3.2 -c 2
PING 10.1.3.2 (10.1.3.2) 56(84) bytes of data.
64 bytes from 10.1.3.2: icmp_seq=1 ttl=60 time=1.88 ms
64 bytes from 10.1.3.2: icmp_seq=2 ttl=60 time=0.688 ms

--- 10.1.3.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.688/1.286/1.884/0.598 ms
root@ns1:/# ping 10.1.3.53 -c 2
PING 10.1.3.53 (10.1.3.53) 56(84) bytes of data.
64 bytes from 10.1.3.53: icmp_seq=1 ttl=61 time=1.17 ms
64 bytes from 10.1.3.53: icmp_seq=2 ttl=61 time=0.865 ms

--- 10.1.3.53 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 0.865/1.018/1.172/0.153 ms
```

```
root@fw1:/# iptables -t filter -vnL FORWARD --line-numbers
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        3   252 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2        1    84 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
```

```
root@fw1:/# conntrack -L
icmp     1 15 src=10.1.2.53 dst=10.1.3.1 type=8 code=0 id=13 src=172.16.2.1 dst=10.1.2.53 type=0 code=0 id=13 mark=0 use=1
icmp     1 27 src=10.1.2.53 dst=10.1.3.53 type=8 code=0 id=15 src=172.16.3.53 dst=10.1.2.53 type=0 code=0 id=15 mark=0 use=1
icmp     1 18 src=10.1.2.53 dst=10.1.3.2 type=8 code=0 id=14 src=172.16.2.2 dst=10.1.2.53 type=0 code=0 id=14 mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 3 flow entries have been shown.
```

```
#ICMPコネクションエントリ確認
root@fw1:/# iptables -t filter -vnL FORWARD --line-numbers
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1       15  1260 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2        5   420 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
```

```
#UDP/53 DNSの確認
root@ns1:/# dig @10.1.3.53 www.example.com

; <<>> DiG 9.16.1-Ubuntu <<>> @10.1.3.53 www.example.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8936
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 60b5319d394286a401000000660bec2b723401a8f587457a (good)
;; QUESTION SECTION:
;www.example.com.               IN      A

;; ANSWER SECTION:
www.example.com.        300     IN      A       10.1.3.12

;; Query time: 10 msec
;; SERVER: 10.1.3.53#53(10.1.3.53)
;; WHEN: Tue Apr 02 20:29:47 JST 2024
;; MSG SIZE  rcvd: 88
```

```
root@fw1:/# iptables -t filter -vnL FORWARD --line-numbers
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1       16  1376 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2        5   420 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3        1    84 ACCEPT     udp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
```

```
root@fw1:/# conntrack -L -p udp
udp      17 26 src=10.1.2.53 dst=10.1.3.53 sport=37467 dport=53 src=172.16.3.53 dst=10.1.2.53 sport=53 dport=37467 mark=0 use=1
conntrack v1.4.5 (conntrack-tools): 1 flow entries have been shown.
```

```
#ドロップ確認
root@ns1:/# dig @10.1.3.53 www.example.com +tcp
;; Connection to 10.1.3.53#53(10.1.3.53) for www.example.com failed: timed out.
;; Connection to 10.1.3.53#53(10.1.3.53) for www.example.com failed: timed out.

; <<>> DiG 9.16.1-Ubuntu <<>> @10.1.3.53 www.example.com +tcp
; (1 server found)
;; global options: +cmd
;; connection timed out; no servers could be reached

;; Connection to 10.1.3.53#53(10.1.3.53) for www.example.com failed: timed out.
```

## FW(TCP)

```
#TCP/53を許可
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.53 -p tcp -m tcp --dport 53 -j ACCEPT
root@fw1:/# iptables -t filter -vnL FORWARD --line-numbers
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1       17  1492 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2        5   420 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3        2   168 ACCEPT     udp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
4        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW tcp dpt:53
```

```
#TCPパケットキャプチャ
root@fw1:/# conntrack -E
```

```
#TCPデータグラム送信
root@ns1:/# dig @10.1.3.53 www.example.com +tcp

; <<>> DiG 9.16.1-Ubuntu <<>> @10.1.3.53 www.example.com +tcp
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34916
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 9fc852ce2dd30f7001000000660bf28b3aff21a9a84bb1b7 (good)
;; QUESTION SECTION:
;www.example.com.               IN      A

;; ANSWER SECTION:
www.example.com.        300     IN      A       10.1.3.12

;; Query time: 9 msec
;; SERVER: 10.1.3.53#53(10.1.3.53)
;; WHEN: Tue Apr 02 20:56:59 JST 2024
;; MSG SIZE  rcvd: 88
```

```
root@fw1:/# conntrack -E
    [NEW] tcp      6 120 SYN_SENT src=10.1.2.53 dst=10.1.3.53 sport=56833 dport=53 [UNREPLIED] src=172.16.3.53 dst=10.1.2.53 sport=53 dport=56833
 [UPDATE] tcp      6 60 SYN_RECV src=10.1.2.53 dst=10.1.3.53 sport=56833 dport=53 src=172.16.3.53 dst=10.1.2.53 sport=53 dport=56833
 [UPDATE] tcp      6 432000 ESTABLISHED src=10.1.2.53 dst=10.1.3.53 sport=56833 dport=53 src=172.16.3.53 dst=10.1.2.53 sport=53 dport=56833 [ASSURED]
 [UPDATE] tcp      6 120 FIN_WAIT src=10.1.2.53 dst=10.1.3.53 sport=56833 dport=53 src=172.16.3.53 dst=10.1.2.53 sport=53 dport=56833 [ASSURED]
 [UPDATE] tcp      6 30 LAST_ACK src=10.1.2.53 dst=10.1.3.53 sport=56833 dport=53 src=172.16.3.53 dst=10.1.2.53 sport=53 dport=56833 [ASSURED]
 [UPDATE] tcp      6 120 TIME_WAIT src=10.1.2.53 dst=10.1.3.53 sport=56833 dport=53 src=172.16.3.53 dst=10.1.2.53 sport=53 dport=56833 [ASSURED]
```

```
root@fw1:/# iptables -t filter -vnL FORWARD --line-numbers
Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1       26  2116 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2        5   420 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3        2   168 ACCEPT     udp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
4        1    60 ACCEPT     tcp  --  *      *       0.0.0.0/0            172.16.3.53          ctstate NEW tcp dpt:53
```
