Setup

```
tinet down -c /mnt/c/tinet/spec_05.yaml | sh -x
tinet up -c /mnt/c/tinet/spec_05.yaml | sh -x
tinet conf -c /mnt/c/tinet/spec_05.yaml | sh -x
tinet test -c /mnt/c/tinet/spec_05.yaml | sh -x
```

## HTTP

```
#tcp/80のパケット受け入れ確認
root@sv1:/# ss -ltp
State          Recv-Q          Send-Q                   Local Address:Port                    Peer Address:Port
Process
LISTEN         0               511                         172.16.2.1:https                        0.0.0.0:*
 users:(("nginx",pid=172,fd=8),("nginx",pid=171,fd=8),("nginx",pid=170,fd=8),("nginx",pid=169,fd=8),("nginx",pid=168,fd=8))
LISTEN         0               511                         172.16.2.1:http                         0.0.0.0:*
 users:(("nginx",pid=172,fd=6),("nginx",pid=171,fd=6),("nginx",pid=170,fd=6),("nginx",pid=169,fd=6),("nginx",pid=168,fd=6))
LISTEN         0               511                         172.16.2.3:http                         0.0.0.0:*
#パケットキャプチャ準備
root@sv1:/# tcpdump -i net0 port 80 and host 172.16.1.254 -w /tmp/tinet/http.pcapng
tcpdump: listening on net0, link-type EN10MB (Ethernet), capture size 262144 bytes
```

```
#HTTPリクエスト
root@fw1:/# curl -v http://172.16.2.1/
*   Trying 172.16.2.1:80...
* TCP_NODELAY set
* Connected to 172.16.2.1 (172.16.2.1) port 80 (#0)
> GET / HTTP/1.1
> Host: 172.16.2.1
> User-Agent: curl/7.68.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Fri, 05 Apr 2024 12:30:22 GMT
< Content-Type: text/html
< Content-Length: 16
< Last-Modified: Fri, 05 Apr 2024 12:07:54 GMT
< Connection: keep-alive
< ETag: "660fe99a-10"
< Accept-Ranges: bytes
<
sv1.example.com
* Connection #0 to host 172.16.2.1 left intact
```

## SSL

```
#tcp/443のパケット受け入れ確認
root@sv1:/# ss -lntp
State           Recv-Q          Send-Q                   Local Address:Port                   Peer Address:Port
Process
LISTEN          0               511                         172.16.2.1:443                         0.0.0.0:*
 users:(("nginx",pid=175,fd=8),("nginx",pid=174,fd=8),("nginx",pid=173,fd=8),("nginx",pid=172,fd=8),("nginx",pid=171,fd=8))
LISTEN          0               511                         172.16.2.3:80                          0.0.0.0:*
 users:(("nginx",pid=175,fd=7),("nginx",pid=174,fd=7),("nginx",pid=173,fd=7),("nginx",pid=172,fd=7),("nginx",pid=171,fd=7))
LISTEN          0               511                         172.16.2.1:80                          0.0.0.0:*
 users:(("nginx",pid=175,fd=6),("nginx",pid=174,fd=6),("nginx",pid=173,fd=6),("nginx",pid=172,fd=6),("nginx",pid=171,fd=6))
#SSL設定確認
root@sv1:/# cat /etc/nginx/sites-available/default
server {
  listen 172.16.2.1:80;
  listen 172.16.2.1:443 ssl http2;
  listen 172.16.2.3:80;
  server_name sv1.example.com;
  ssl_certificate /etc/ssl/private/server.crt;
  ssl_certificate_key /etc/ssl/private/server.key;
  ssl_protocols TLSv1.2;
  ssl_dhparam /etc/ssl/dhparam.pem;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
  root /var/www/html;
  index index.html;
}
#サーバー証明書確認
root@sv1:/# openssl x509 -text -noout -in /etc/ssl/private/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            76:05:47:d0:09:41:66:40:99:32:21:09:9e:d1:e2:64:b5:d4:77:e1
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sv1.example.com, C = JP
        Validity
            Not Before: Apr  6 01:31:34 2024 GMT
            Not After : Mar 13 01:31:34 2124 GMT
        Subject: CN = sv1.example.com, C = JP
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:cf:9f:77:c1:2d:c8:0d:c6:e4:df:b0:bb:ee:ed:
                    53:0d:fc:c2:6c:97:66:9d:57:62:8b:69:45:26:5c:
                    dd:61:34:1e:28:45:51:76:33:fb:0e:c2:ac:af:fa:
                    0e:76:0f:3b:42:01:bd:75:a6:6c:b4:6b:a1:19:44:
                    21:85:cf:bf:c6:c4:1c:5a:48:82:7f:14:62:42:00:
                    ce:e9:b6:41:d4:ef:eb:36:3c:e5:0d:1e:c0:8d:23:
                    fb:95:78:7b:f6:2b:dc:8e:4c:58:d2:06:4e:de:68:
                    f5:88:aa:2f:e0:dd:fb:a8:6b:01:15:e4:d0:85:04:
                    14:c6:f3:27:6b:7e:4a:50:fa:1b:d7:e6:26:ed:63:
                    62:c9:ff:4d:03:bb:06:96:a6:02:f1:a1:af:e0:72:
                    25:fb:61:9a:dc:00:b0:70:79:51:b9:57:10:e7:ed:
                    78:fb:99:fe:59:d9:c0:3b:8b:c3:be:f4:46:73:98:
                    4b:6f:07:24:25:f8:f8:56:ed:46:ba:0b:09:69:a5:
                    d2:8f:f8:06:4b:5d:6c:8a:4c:1c:5b:31:27:5d:63:
                    0f:52:c0:1c:eb:9b:df:fa:45:56:a4:64:a9:7d:9d:
                    9f:cf:dc:47:c6:43:d2:4f:68:0c:a2:fe:b2:83:9c:
                    28:eb:3a:59:b0:0f:7b:97:94:5b:3e:54:0b:b8:fe:
                    aa:c3
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                23:62:79:61:42:23:BC:9F:3C:5A:4A:40:36:92:7A:AF:4D:9F:5C:CA
            X509v3 Authority Key Identifier:
                keyid:23:62:79:61:42:23:BC:9F:3C:5A:4A:40:36:92:7A:AF:4D:9F:5C:CA

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         b4:ec:ea:bc:ca:8a:6f:b0:ed:58:be:e4:71:51:4c:18:bb:b9:
         65:60:04:c1:d0:8e:3d:63:bc:54:31:a4:8a:a1:9b:d6:4d:d6:
         30:0a:09:f9:e5:0e:0c:21:95:de:99:f1:55:f2:7a:70:73:17:
         6d:f2:ff:32:6a:f7:ca:cd:fb:23:23:41:d2:01:7a:58:d3:ea:
         d1:8a:ae:fa:f2:96:8e:b2:2a:d8:fd:a5:6e:a6:ef:7c:b5:f3:
         2d:04:06:f0:61:32:9d:13:0b:79:73:94:1e:57:c4:d5:b8:0f:
         2b:26:3d:85:97:bc:89:ee:26:c4:3d:63:4a:fd:73:23:e7:d5:
         13:6b:31:f6:09:98:07:12:25:c3:80:d8:eb:b0:80:f4:60:4d:
         e2:85:83:cc:74:1c:f7:db:07:5d:11:9e:dc:c5:a0:1f:ce:1a:
         a4:66:da:68:d6:05:cf:5a:04:e3:a6:ed:29:e9:9f:de:9c:f3:
         c0:15:6c:14:6c:c2:8f:6a:71:3a:76:1d:0a:df:c6:4c:16:a7:
         31:d0:87:03:18:58:09:43:3b:76:b3:44:c4:e7:f3:95:08:69:
         19:d3:cf:72:f3:50:9b:68:11:f2:a8:0d:3e:c1:15:aa:8d:62:
         ac:bd:fb:40:8e:2a:88:00:c8:e4:28:99:29:94:b7:4a:33:6d:
         cd:53:6a:91
```

```
#パケットキャプチャ準備
root@sv1:/# tcpdump -i net0 port 443 and host 172.16.1.254 -w /tmp/tinet/https.pcapng
```

```
#SSLでアクセス
root@fw1:/# SSLLKEYLOGFILE=/tmp/tinet/key.log curl -vk https://sv1.example.com --tls-max 1.2 --http2 --ciphers DHE-RSA-AES256-GCM-SHA384
*   Trying 172.16.2.1:443...
* TCP_NODELAY set
* Connected to sv1.example.com (172.16.2.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* Cipher selection: DHE-RSA-AES256-GCM-SHA384
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / DHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: CN=sv1.example.com; C=JP
*  start date: Apr  6 01:31:34 2024 GMT
*  expire date: Mar 13 01:31:34 2124 GMT
*  issuer: CN=sv1.example.com; C=JP
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
* Using HTTP2, server supports multi-use
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x55d7f8f302f0)
> GET / HTTP/2
> Host: sv1.example.com
> user-agent: curl/7.68.0
> accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS == 128)!
< HTTP/2 200
< server: nginx/1.18.0 (Ubuntu)
< date: Sat, 06 Apr 2024 02:00:10 GMT
< content-type: text/html
< content-length: 16
< last-modified: Sat, 06 Apr 2024 01:34:12 GMT
< etag: "6610a694-10"
< accept-ranges: bytes
<
sv1.example.com
* Connection #0 to host sv1.example.com left intact
```

## DNS

```
#DNSクライアントからDNSサーバのIPアドレス確認
root@cl1:/# more /etc/resolv.conf
nameserver 192.168.11.254
#DNSキャッシュサーバのルートヒント確認
root@ns1:/# cat /usr/share/dns/root.hints
;       This file holds the information on root name servers needed to
;       initialize cache of Internet domain name servers
;       (e.g. reference this file in the "cache  .  <file>"
;       configuration file of BIND domain name servers).
;
;       This file is made available by InterNIC
;       under anonymous FTP as
;           file                /domain/named.cache
;           on server           FTP.INTERNIC.NET
;       -OR-                    RS.INTERNIC.NET
;
;       last update:     May 28, 2019
;       related version of root zone:     2019052802
;
; FORMERLY NS.INTERNIC.NET
;
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
;
; FORMERLY NS1.ISI.EDU
;
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     199.9.14.201
B.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:200::b
;
; FORMERLY C.PSI.NET
;
.                        3600000      NS    C.ROOT-SERVERS.NET.
C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
C.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2::c
;
; FORMERLY TERP.UMD.EDU
;
.                        3600000      NS    D.ROOT-SERVERS.NET.
D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13
D.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2d::d
;
; FORMERLY NS.NASA.GOV
;
.                        3600000      NS    E.ROOT-SERVERS.NET.
E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
E.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:a8::e
;
; FORMERLY NS.ISC.ORG
;
.                        3600000      NS    F.ROOT-SERVERS.NET.
F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2f::f
;
; FORMERLY NS.NIC.DDN.MIL
;
.                        3600000      NS    G.ROOT-SERVERS.NET.
G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
G.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:12::d0d
;
; FORMERLY AOS.ARL.ARMY.MIL
;
.                        3600000      NS    H.ROOT-SERVERS.NET.
H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53
H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::53
;
; FORMERLY NIC.NORDU.NET
;
.                        3600000      NS    I.ROOT-SERVERS.NET.
I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fe::53
;
; OPERATED BY VERISIGN, INC.
;
.                        3600000      NS    J.ROOT-SERVERS.NET.
J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:c27::2:30
;
; OPERATED BY RIPE NCC
;
.                        3600000      NS    K.ROOT-SERVERS.NET.
K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fd::1
;
; OPERATED BY ICANN
;
.                        3600000      NS    L.ROOT-SERVERS.NET.
L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:9f::42
;
; OPERATED BY WIDE
;
.                        3600000      NS    M.ROOT-SERVERS.NET.
M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33
M.ROOT-SERVERS.NET.      3600000      AAAA  2001:dc3::35
; End of fileroot@ns1:/#
#検証環境のキャッシュサーバはインターネット未接続のためデフォルトのルートヒントは使えない
#Unboundの設定ファイルで指定
root@ns1:/# cat /etc/unbound/root.hints
.                       3600000    NS   ns.root-servers.net.
ns.root-servers.net.    3600000    A    10.1.3.51

root@ns1:/# cat /etc/unbound/unbound.conf
# Unbound configuration file for Debian.
#
# See the unbound.conf(5) man page.
#
# See /usr/share/doc/unbound/examples/unbound.conf for a commented
# reference config file.
#
# The following line includes additional configuration files from the
# /etc/unbound/unbound.conf.d directory.
include: "/etc/unbound/unbound.conf.d/*.conf"
server:
  interface: 0.0.0.0
  access-control: 0.0.0.0/0 allow
  do-ip6: no
  root-hints: /etc/unbound/root.hints
remote-control:
  control-enable: yes
```

```
#UDP53の受け入れ確認
root@ns1:/# ss -lnup
State         Recv-Q        Send-Q               Local Address:Port               Peer Address:Port       Process
UNCONN        0             0                          0.0.0.0:53                      0.0.0.0:*           users:(("unbound",pid=109,fd=3))

root@lb1:/# ss -lnup
State         Recv-Q        Send-Q               Local Address:Port                Peer Address:Port        Process
UNCONN        0             0                      172.16.3.53:53                       0.0.0.0:*            users:(("named",pid=659,fd=27))
UNCONN        0             0                      172.16.3.52:53                       0.0.0.0:*            users:(("named",pid=659,fd=24))
UNCONN        0             0                      172.16.3.51:53                       0.0.0.0:*            users:(("named",pid=659,fd=21))
UNCONN        0             0                        127.0.0.1:53                       0.0.0.0:*            users:(("named",pid=659,fd=16))
```

```
#NATの設定確認
root@fw1:/# iptables -t nat -nL --line-numbers
Chain PREROUTING (policy ACCEPT)
num  target     prot opt source               destination
1    DNAT       all  --  0.0.0.0/0            10.1.3.1             to:172.16.2.1
2    DNAT       all  --  0.0.0.0/0            10.1.3.2             to:172.16.2.2
3    DNAT       all  --  0.0.0.0/0            10.1.3.53            to:172.16.3.53

Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination

Chain POSTROUTING (policy ACCEPT)
num  target     prot opt source               destination
FWの設定確認
root@fw1:/# iptables -t filter -nL --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination

Chain FORWARD (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2    ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3    ACCEPT     udp  --  0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
4    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.53          ctstate NEW tcp dpt:53

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination
```

```
#権威サーバーlb1のためにNATとFWを設定
root@fw1:/# iptables -t nat -A PREROUTING -d 10.1.3.51 -j DNAT --to 172.16.3.51
root@fw1:/# iptables -t nat -A PREROUTING -d 10.1.3.52 -j DNAT --to 172.16.3.52
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.51 -p udp -m udp --dport 53 -j ACCEPT
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.51 -p tcp -m tcp --dport 53 -j ACCEPT
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.52 -p udp -m udp --dport 53 -j ACCEPT
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.52 -p tcp -m tcp --dport 53 -j ACCEPT

root@fw1:/# iptables -t nat -nL PREROUTING --line-numbers
Chain PREROUTING (policy ACCEPT)
num  target     prot opt source               destination
1    DNAT       all  --  0.0.0.0/0            10.1.3.1             to:172.16.2.1
2    DNAT       all  --  0.0.0.0/0            10.1.3.2             to:172.16.2.2
3    DNAT       all  --  0.0.0.0/0            10.1.3.53            to:172.16.3.53
4    DNAT       all  --  0.0.0.0/0            10.1.3.51            to:172.16.3.51
5    DNAT       all  --  0.0.0.0/0            10.1.3.52            to:172.16.3.52
root@fw1:/# iptables -t filter -nL FORWARD --line-numbers
Chain FORWARD (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2    ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3    ACCEPT     udp  --  0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
4    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.53          ctstate NEW tcp dpt:53
5    ACCEPT     udp  --  0.0.0.0/0            172.16.3.51          ctstate NEW udp dpt:53
6    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.51          ctstate NEW tcp dpt:53
7    ACCEPT     udp  --  0.0.0.0/0            172.16.3.52          ctstate NEW udp dpt:53
8    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.52          ctstate NEW tcp dpt:53
```

```
#パケットキャプチャ準備
root@ns1:/# tcpdump -i net0 port 53 -w /tmp/tinet/dns.pcapng
tcpdump: listening on net0, link-type EN10MB (Ethernet), capture size 262144 bytes
#DNSデータグラム送信
root@cl1:/# dig www.example.com

; <<>> DiG 9.16.1-Ubuntu <<>> www.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 768
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.example.com.               IN      A

;; ANSWER SECTION:
www.example.com.        300     IN      A       10.1.3.12

;; Query time: 30 msec
;; SERVER: 192.168.11.254#53(192.168.11.254)
;; WHEN: Sat Apr 06 21:24:02 JST 2024
;; MSG SIZE  rcvd: 60
#キャッシュ確認
root@ns1:/# unbound-control dump_cache
START_RRSET_CACHE
;rrset 196 1 0 7 2
example.com.    196     IN      NS      lb1.example.com.
;rrset 196 1 0 8 0
.       196     IN      NS      ns.root-servers.net.
;rrset 196 1 0 3 2
lb1.example.com.        196     IN      A       10.1.3.53
;rrset 196 1 0 1 0
ns.gtld-servers.net.    196     IN      A       10.1.3.52
;rrset 196 1 0 8 2
www.example.com.        196     IN      A       10.1.3.12
;rrset 196 1 0 2 0
com.    196     IN      NS      ns.gtld-servers.net.
;rrset 196 1 0 3 0
ns.root-servers.net.    196     IN      A       10.1.3.51
END_RRSET_CACHE
START_MSG_CACHE
msg . IN NS 32896 1 196 0 1 0 1
. IN NS 0
ns.root-servers.net. IN A 0
msg www.example.com. IN A 32896 1 196 2 1 1 1
www.example.com. IN A 0
example.com. IN NS 0
lb1.example.com. IN A 0
END_MSG_CACHE
EOF
```

## DHCP

```
root@cl1:/# ip addr show net0
2: net0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:42:ac:01:10:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.11.1/24 brd 192.168.11.255 scope global dynamic net0
       valid_lft 2294sec preferred_lft 2294sec
    inet6 fe80::5074:19ff:fe68:fc99/64 scope link
       valid_lft forever preferred_lft forever

#アドレス返却
root@cl1:/# dhclient -r -v
Killed old client process
Internet Systems Consortium DHCP Client 4.4.1
Copyright 2004-2018 Internet Systems Consortium.
All rights reserved.
For info, please visit https://www.isc.org/software/dhcp/

Listening on LPF/net0/02:42:ac:01:10:01
Sending on   LPF/net0/02:42:ac:01:10:01
Sending on   Socket/fallback
DHCPRELEASE of 192.168.11.1 on net0 to 192.168.11.254 port 67 (xid=0x1ef1b3f3)
root@cl1:/# ip addr show net0
2: net0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:42:ac:01:10:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::5074:19ff:fe68:fc99/64 scope link
       valid_lft forever preferred_lft forever

#パケットキャプチャ準備
root@rt1:/# tcpdump -i net1 -w /tmp/tinet/dhcp.pcapng
tcpdump: listening on net1, link-type EN10MB (Ethernet), capture size 262144 bytes

#DHCPデータグラム送信
root@cl1:/# dhclient -v
Internet Systems Consortium DHCP Client 4.4.1
Copyright 2004-2018 Internet Systems Consortium.
All rights reserved.
For info, please visit https://www.isc.org/software/dhcp/

Listening on LPF/net0/02:42:ac:01:10:01
Sending on   LPF/net0/02:42:ac:01:10:01
Sending on   Socket/fallback
DHCPDISCOVER on net0 to 255.255.255.255 port 67 interval 3 (xid=0x13f3282d)
DHCPOFFER of 192.168.11.1 from 192.168.11.254
DHCPREQUEST for 192.168.11.1 on net0 to 255.255.255.255 port 67 (xid=0x2d28f313)
DHCPACK of 192.168.11.1 from 192.168.11.254 (xid=0x13f3282d)
bound to 192.168.11.1 -- renewal in 1728 seconds.

root@cl1:/# ip addr show net0
2: net0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:42:ac:01:10:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.11.1/24 brd 192.168.11.255 scope global dynamic net0
       valid_lft 3131sec preferred_lft 3131sec
    inet6 fe80::5074:19ff:fe68:fc99/64 scope link
       valid_lft forever preferred_lft forever
```

## 負荷分散

### ラウンドロビン

```
#NAT設定とtcp80許可
root@fw1:/# iptables -t nat -A PREROUTING -d 10.1.3.12 -j DNAT --to 172.16.3.12
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.12 -p tcp -m tcp --dport 80 -j ACCEPT
#設定確認
root@fw1:/# iptables -t nat -nL PREROUTING --line-numbers
Chain PREROUTING (policy ACCEPT)
num  target     prot opt source               destination
1    DNAT       all  --  0.0.0.0/0            10.1.3.1             to:172.16.2.1
2    DNAT       all  --  0.0.0.0/0            10.1.3.2             to:172.16.2.2
3    DNAT       all  --  0.0.0.0/0            10.1.3.53            to:172.16.3.53
4    DNAT       all  --  0.0.0.0/0            10.1.3.12            to:172.16.3.12
root@fw1:/# iptables -t filter -nL FORWARD --line-numbers
Chain FORWARD (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2    ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3    ACCEPT     udp  --  0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
4    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.53          ctstate NEW tcp dpt:53
5    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.12          ctstate NEW tcp dpt:80
```

haproxy.cfg に設定追記

```
frontend www-front
        bind 172.16.3.12:80
        default_backend www-back

backend www-back
        balance roundrobin
        server sv1 172.16.2.1:80 check inter 5000 fall 3 rise 2
        server sv2 172.16.2.2:80 check inter 5000 fall 3 rise 2
        http-request set-header x-forwarded-proto http if !{ ssl_fc }
        option forwardfor
        option httpchk GET / HTTP/1.1
        http-check send hdr HOST www.example.com
        http-check expect status 200
```

```
#サービス再起動
root@lb1:/# /etc/init.d/haproxy restart
 * Restarting haproxy haproxy                                                                                    [ OK ]
#負荷分散の確認
root@ns1:/# for i in {1..10}; do curl http://10.1.3.12/; sleep 1; done
sv1.example.com
sv2.example.com
sv1.example.com
sv2.example.com
sv1.example.com
sv2.example.com
sv1.example.com
sv2.example.com
sv1.example.com
sv2.example.com

#ログ確認
root@lb1:/# tail -10 /var/log/haproxy.log
Apr  7 14:46:47 lb1 haproxy[691]: 10.1.2.53:56460 [07/Apr/2024:14:46:47.148] www-front www-back/sv1 0/0/0/1/1 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:48 lb1 haproxy[691]: 10.1.2.53:37502 [07/Apr/2024:14:46:48.181] www-front www-back/sv2 0/0/0/1/1 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:49 lb1 haproxy[691]: 10.1.2.53:37516 [07/Apr/2024:14:46:49.213] www-front www-back/sv1 0/0/1/1/2 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:50 lb1 haproxy[691]: 10.1.2.53:37530 [07/Apr/2024:14:46:50.246] www-front www-back/sv2 0/0/1/2/3 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:51 lb1 haproxy[691]: 10.1.2.53:37538 [07/Apr/2024:14:46:51.274] www-front www-back/sv1 0/0/0/1/1 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:52 lb1 haproxy[691]: 10.1.2.53:37548 [07/Apr/2024:14:46:52.307] www-front www-back/sv2 0/0/1/1/2 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:53 lb1 haproxy[691]: 10.1.2.53:37554 [07/Apr/2024:14:46:53.338] www-front www-back/sv1 0/0/0/1/1 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:54 lb1 haproxy[691]: 10.1.2.53:37558 [07/Apr/2024:14:46:54.372] www-front www-back/sv2 0/0/1/1/2 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:55 lb1 haproxy[691]: 10.1.2.53:37574 [07/Apr/2024:14:46:55.409] www-front www-back/sv1 0/0/0/1/1 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 14:46:56 lb1 haproxy[691]: 10.1.2.53:37580 [07/Apr/2024:14:46:56.444] www-front www-back/sv2 0/0/1/2/3 200 229 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"

root@sv1:/# tail -20 /var/log/nginx/access.log
"07/Apr/2024:14:51:10 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:15 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:20 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:25 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:30 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:35 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:40 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:45 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:50 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:51:55 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:52:00 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:52:05 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:52:09 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:14:52:10 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:52:11 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:14:52:13 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:14:52:15 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:14:52:15 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:14:52:17 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:14:52:20 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
```

### Cookie パーシステンス

```
#パーシステンス用のIPアドレスとポート番号をインターネットに公開
root@fw1:/# iptables -t nat -A PREROUTING -d 10.1.3.34 -j DNAT --to 172.16.3.34
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.34 -p tcp -m tcp --dport 80 -j ACCEPT

root@fw1:/# iptables -t nat -nL PREROUTING --line-numbers
Chain PREROUTING (policy ACCEPT)
num  target     prot opt source               destination
1    DNAT       all  --  0.0.0.0/0            10.1.3.1             to:172.16.2.1
2    DNAT       all  --  0.0.0.0/0            10.1.3.2             to:172.16.2.2
3    DNAT       all  --  0.0.0.0/0            10.1.3.53            to:172.16.3.53
4    DNAT       all  --  0.0.0.0/0            10.1.3.12            to:172.16.3.12
5    DNAT       all  --  0.0.0.0/0            10.1.3.34            to:172.16.3.34
root@fw1:/# iptables -t filter -nL FORWARD --line-numbers
Chain FORWARD (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2    ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3    ACCEPT     udp  --  0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
4    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.53          ctstate NEW tcp dpt:53
5    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.12          ctstate NEW tcp dpt:80
6    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.34          ctstate NEW tcp dpt:80
```

haproxy.cfg に設定追記

```
frontend www2-front
        bind 172.16.3.34:80
        default_backend www2-back
        capture cookie SERVER len 32
backend www2-back
        balance roundrobin
        cookie SERVER insert indirect nocache
        server sv1 172.16.2.3:80 track www-back/sv1 cookie sv1
        server sv2 172.16.2.4:80 track www-back/sv2 cookie sv2
        http-request set-header x-forwarded-proto http
        option forwardfor
```

```
root@lb1:/# /etc/init.d/haproxy restart
 * Restarting haproxy haproxy                                                                                    [ OK ]
```

```
#パーシステンスの確認
root@ns1:/# curl -c cookie.txt http://10.1.3.34/
sv1.example.com
#割り当てサーバの確認
root@ns1:/# cat cookie.txt
# Netscape HTTP Cookie File
# https://curl.haxx.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

10.1.3.34       FALSE   /       FALSE   0       SERVER  sv1

root@ns1:/# for i in {1..10}; do curl -b cookie.txt http://10.1.3.34/; sleep 1; done
sv1.example.com
sv1.example.com
sv1.example.com
sv1.example.com
sv1.example.com
sv1.example.com
sv1.example.com
sv1.example.com
sv1.example.com
sv1.example.com
```

```
#ログ確認
root@lb1:/# tail -10 /var/log/haproxy.log
Apr  7 15:50:38 lb1 haproxy[773]: 10.1.2.53:34230 [07/Apr/2024:15:50:38.265] www2-front www2-back/sv1 0/0/0/1/1 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:39 lb1 haproxy[773]: 10.1.2.53:34246 [07/Apr/2024:15:50:39.295] www2-front www2-back/sv1 0/0/1/1/2 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:40 lb1 haproxy[773]: 10.1.2.53:34262 [07/Apr/2024:15:50:40.328] www2-front www2-back/sv1 0/0/1/2/3 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:41 lb1 haproxy[773]: 10.1.2.53:34272 [07/Apr/2024:15:50:41.365] www2-front www2-back/sv1 0/0/1/1/2 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:42 lb1 haproxy[773]: 10.1.2.53:34286 [07/Apr/2024:15:50:42.405] www2-front www2-back/sv1 0/0/1/1/2 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:43 lb1 haproxy[773]: 10.1.2.53:34300 [07/Apr/2024:15:50:43.459] www2-front www2-back/sv1 0/0/0/1/1 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:44 lb1 haproxy[773]: 10.1.2.53:34314 [07/Apr/2024:15:50:44.490] www2-front www2-back/sv1 0/0/1/1/2 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:45 lb1 haproxy[773]: 10.1.2.53:34320 [07/Apr/2024:15:50:45.510] www2-front www2-back/sv1 0/0/0/1/1 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:46 lb1 haproxy[773]: 10.1.2.53:34332 [07/Apr/2024:15:50:46.532] www2-front www2-back/sv1 0/0/0/1/1 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"
Apr  7 15:50:47 lb1 haproxy[773]: 10.1.2.53:34346 [07/Apr/2024:15:50:47.584] www2-front www2-back/sv1 0/0/0/1/1 200 229 SERVER=sv1 - --VN 1/1/0/0/0 0/0 "GET / HTTP/1.1"

root@sv1:/# tail -20 /var/log/nginx/access.log
"07/Apr/2024:15:50:42 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:15:50:43 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:15:50:44 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:15:50:45 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:15:50:46 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:15:50:47 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:50:47 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "http"
"07/Apr/2024:15:50:52 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:50:57 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:02 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:07 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:12 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:17 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:22 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:27 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:32 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:37 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:42 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:47 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:15:51:52 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
```

## SSL オフロード

```
#SSLオフロード用のIPアドレスとポートをインターネットに公開
root@fw1:/# iptables -t filter -A FORWARD -m conntrack --ctstate NEW -d 172.16.3.12 -p tcp -m tcp --dport 443  -j ACCEPT
root@fw1:/# iptables -t filter -nL FORWARD --line-numbers
Chain FORWARD (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2    ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0            ctstate NEW icmptype 8
3    ACCEPT     udp  --  0.0.0.0/0            172.16.3.53          ctstate NEW udp dpt:53
4    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.53          ctstate NEW tcp dpt:53
5    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.12          ctstate NEW tcp dpt:80
6    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.34          ctstate NEW tcp dpt:80
7    ACCEPT     tcp  --  0.0.0.0/0            172.16.3.12          ctstate NEW tcp dpt:443
```

```
#サーバー証明書作成
root@lb1:/# openssl req -subj '/CN=www.example.com/C=JP' -new -newkey rsa:2048 -sha256 -days 36500 -nodes -x509 -keyout
/etc/ssl/private/server.key -out /etc/ssl/private/server.crt
Generating a RSA private key
........................+++++
.................................................+++++
writing new private key to '/etc/ssl/private/server.key'
-----

root@lb1:/# openssl x509 -text -noout -in /etc/ssl/private/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            27:86:87:a3:32:0a:72:1d:64:ac:90:fd:25:82:15:4f:c1:10:1a:ea
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = www.example.com, C = JP
        Validity
            Not Before: Apr  7 11:14:43 2024 GMT
            Not After : Mar 14 11:14:43 2124 GMT
        Subject: CN = www.example.com, C = JP
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:f0:2b:d1:23:3f:f1:db:77:b8:4c:59:0b:b5:3e:
                    6d:7d:85:72:52:db:44:55:b5:36:33:c7:76:e1:91:
                    d7:90:ad:dd:44:4f:de:7f:e8:b7:61:62:5a:e2:6d:
                    23:ba:00:cb:d2:b1:05:bf:0f:ea:68:5c:c9:e8:4a:
                    f4:b1:52:ee:08:7e:b7:2d:e9:15:4e:c2:25:4f:4d:
                    5f:aa:b5:1c:d7:14:ed:00:e7:57:03:ad:c2:d4:3f:
                    63:24:c1:c4:a6:48:cb:f3:2e:c6:21:92:9f:40:b9:
                    3d:b6:f5:02:d9:96:a3:1a:c8:6b:aa:fc:cb:d2:c1:
                    76:8a:06:32:54:55:1a:15:77:83:0c:00:63:76:25:
                    9a:0a:8f:8e:d3:6c:65:4b:cc:4a:7e:22:23:5b:79:
                    ae:f9:cd:31:01:c5:94:47:7f:08:27:f8:c8:ae:b7:
                    ee:4f:fc:a3:e6:92:da:6c:8d:0f:37:95:37:76:a1:
                    08:00:62:62:c4:10:a0:7d:56:41:14:ab:42:b5:6b:
                    34:46:62:d1:69:64:6c:88:0f:83:56:e5:28:dc:15:
                    61:1b:62:e4:a1:e2:1b:0f:05:d8:80:a6:8f:22:5f:
                    41:9c:9c:e7:cb:95:47:a1:23:4e:71:f5:6b:17:56:
                    f6:49:85:6f:d7:6b:bd:cb:96:3c:54:7c:58:6a:e3:
                    0c:dd
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                28:F1:9D:2C:E1:51:C5:68:DD:6E:46:83:C3:F2:E1:ED:DC:76:72:85
            X509v3 Authority Key Identifier:
                keyid:28:F1:9D:2C:E1:51:C5:68:DD:6E:46:83:C3:F2:E1:ED:DC:76:72:85

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         5c:0a:b6:91:0d:7e:ae:9e:29:6f:15:b8:fe:1d:22:80:90:e9:
         36:48:0d:41:f0:06:43:f1:23:35:af:46:26:ff:cf:4c:5b:ad:
         1d:60:06:9e:cf:30:63:43:2f:e0:1c:9c:3a:03:66:6b:c8:8d:
         ad:7a:7b:3d:86:e0:59:6c:9b:89:f3:f4:54:bd:2c:9e:0b:13:
         8c:71:30:b6:32:2d:b4:88:b5:01:35:d1:04:58:9f:02:4f:ce:
         79:b2:0d:0a:e7:dc:32:16:3d:14:ac:59:55:e3:8a:3a:13:00:
         05:75:8d:51:24:0e:f5:53:df:87:31:0a:2c:46:91:7a:f3:60:
         45:8b:3a:fd:3c:a8:55:96:1a:c5:6a:d3:80:02:2d:ae:b8:47:
         7b:3c:5a:08:de:b1:3d:c5:57:3b:f8:db:62:0e:79:71:44:85:
         56:e7:bb:98:5b:03:3a:ca:73:e3:0f:41:5e:26:0d:d5:22:ef:
         d8:b2:9d:fc:55:22:e5:e2:30:8c:93:da:f1:db:b9:8b:dc:23:
         44:8d:47:28:bc:c6:51:11:e1:c2:f7:35:8e:f6:4c:b8:87:10:
         78:03:d9:a0:81:17:45:85:73:c9:17:cc:fa:30:95:4a:b4:7e:
         d7:44:ba:b2:44:6b:de:4f:6b:62:f9:cb:27:c9:29:32:28:72:
         52:38:1b:32
```

```
#HAProxy設定
root@lb1:/# cat /etc/ssl/private/server.crt /etc/ssl/private/server.key > /etc/ssl/private/server.pem
root@lb1:/# vi /etc/haproxy/haproxy.cfg
```

```
frontend www-front
        ...
        bind 172.16.3.12:443 ssl crt /etc/ssl/private/server.pem
backend www-back
        ...
        http-request set-header x-forwarded-proto https if { ssl_fc }
```

```
root@lb1:/# /etc/init.d/haproxy restart
 * Restarting haproxy haproxy                                                                                           [WARNING] 097/205622 (801) : parsing [/etc/haproxy/haproxy.cfg:38] : 'bind 172.16.3.12:443' :
  unable to load default 1024 bits DH parameter for certificate '/etc/ssl/private/server.pem'.
  , SSL library will use an automatically generated DH parameter.
[WARNING] 097/205622 (801) : Setting tune.ssl.default-dh-param to 1024 by default, if your workload permits it you should set it to at least 2048. Please set a value >= 1024 to make this warning disappear.
[WARNING] 097/205622 (803) : parsing [/etc/haproxy/haproxy.cfg:38] : 'bind 172.16.3.12:443' :
  unable to load default 1024 bits DH parameter for certificate '/etc/ssl/private/server.pem'.
  , SSL library will use an automatically generated DH parameter.
[WARNING] 097/205622 (803) : Setting tune.ssl.default-dh-param to 1024 by default, if your workload permits it you should set it to at least 2048. Please set a value >= 1024 to make this warning disappear.
                                                                                                                 [ OK ]
```

```
#SSL接続
root@ns1:/# curl -k -v https://10.1.3.12/ --tls-max 1.2
*   Trying 10.1.3.12:443...
* TCP_NODELAY set
* Connected to 10.1.3.12 (10.1.3.12) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=www.example.com; C=JP
*  start date: Apr  7 11:14:43 2024 GMT
*  expire date: Mar 14 11:14:43 2124 GMT
*  issuer: CN=www.example.com; C=JP
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
> GET / HTTP/1.1
> Host: 10.1.3.12
> User-Agent: curl/7.68.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< server: nginx/1.18.0 (Ubuntu)
< date: Sun, 07 Apr 2024 11:57:33 GMT
< content-type: text/html
< content-length: 16
< last-modified: Sun, 07 Apr 2024 05:21:07 GMT
< etag: "66122d43-10"
< accept-ranges: bytes
<
sv1.example.com
* Connection #0 to host 10.1.3.12 left intact
```

ログ確認

```
root@sv2:/# tail -10 /var/log/nginx/access.log
"07/Apr/2024:21:01:20 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:25 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:30 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:35 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:40 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:45 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:50 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:55 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
"07/Apr/2024:21:01:57 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "curl/7.68.0" "10.1.2.53" "https"
"07/Apr/2024:21:02:00 +0900" "172.16.2.254" "GET / HTTP/1.1" "200" "-" "-" "-"
```
