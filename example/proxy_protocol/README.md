Introduction of feature
=======================
Proxy protocol of quic packet is not a standard mechanism defined in the
https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-08, yet there is not any RFC about
this feature, but for a practical application, get the real ip/port of client is neccessary in
some scenario. So we just self define a quic proxy protocol.

quic-server can obtain real client ip with option "quic_lb_proxy_protocol", like this
```
server {
    listen 8001 quic reuseport;
    quic_lb_proxy_protocol on;
    ...
}
```

then every udp packet would carry a quic-lb-proxy-protocol Header as below:
```
PROXY_STRING + single space + INET_PROTOCOL + single space + CLIENT_IP + single space + PROXY_IP + single space + CLIENT_PORT + single space + PROXY_PORT + "\r\n"
```

for ipv4, it would like:
```
PROXY QUICV4 192.0.2.0 192.0.2.255 42300 443\r\n
```

for ipv6, it would like:
```
PROXY QUICV6 2001:db8:: 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff 42300 443\r\n
```

and this example shows how to use this feature. More detail information is shown in the quic_lb_proxy_protocol.conf,
further more, this case is working in plaintext routing mode.

How to use
=============
- make sure you are in the quic-lb root dir
- exec cmd: ./objs/nginx -p . -c example/proxy_protocol/quic_lb_proxy_protocol.conf
