nginx-quic-lb
====
nginx-quic-lb is an implementation of [ietf-quic-lb](https://tools.ietf.org/html/draft-ietf-quic-load-balancers-04), based on [nginx-release-1.18.0](https://github.com/nginx/nginx/tree/release-1.18.0), you can see the detailed
code in [this pull request](https://github.com/alipay/quic-lb/pull/1)

nginx-quic-lb just implement the date plane function of ietf-quic-lb(forward quic packet, retry service and so on).
For "configuration agent" defined in draft, user can implement it with your own control plane and nginx configuration file.

Some features are still under development:
```
(1) Stream cipher/Block cipher
(2) No-Shared-State Retry Service
```

How to build
----
```
1. git clone https://github.com/alipay/quic-lb
2. git submodule update --init --recursive
3. sh build.sh
```

How to use:
----
After success building, you can start quic-lb with this command:
```
mkdir logs
./objs/nginx -p . -c conf/quic_lb.conf
```

Explanation of configuration file
```
stream {
    upstream quic_upstreams {
        quic_lb_mode;  #tag, use to express that upstream block work in quic lb mode
        server 127.0.0.1:8443 sid=127.0.0.1:8443;  #quic server ip:port and its unique sid
        server 127.0.0.1:8444 sid=127.0.0.1:8444;
    }

    server {
        listen 8001 quic reuseport; #'quic' is a tag use to express this server block is quic lb
        proxy_pass quic_upstreams;
        quic_lb_conf_file quic_lb/conf/conf.json; #some configuration options writen in json file
        proxy_timeout 10s;
        proxy_requests 10000;
        proxy_responses 10000;
    }
}
```
Tutorial conf.json file is shown below, as draft description: "'configuration agent' will delivery conf file to quic-lb and quic-server at the same time", so we write the same conf options in quic-lb and server into a single conf.json file.
```
[{
    "conf_id": 0,
    "route_mode": "plaintext",
    "sid_len": 14,
    "retry_service_ctx":{
        "retry_method":"shared_state",
        "retry_mode":"inactive",
        "retry_token_key":"01234567890123456789012345678901"
    }
},
{
    "conf_id": 1,
    "route_mode": "block_cipher",
    "sid_len": 14,
    "retry_service_ctx":{
        "retry_method":"shared_state",
        "retry_mode":"inactive",
        "retry_token_key":"01234567890123456789012345678901"
    }
},
{
    "conf_id": 2,
    "route_mode": "stream_cipher",
    "sid_len": 14,
    "retry_service_ctx":{
        "retry_method":"shared_state",
        "retry_mode":"inactive",
        "retry_token_key":"01234567890123456789012345678901"
    }
}]
```

How to test
----
```
1. pip install pytest
2. cd ${quic-lb-dir}/test
3. make test
```

Additional:
----
1.you can test nginx-quic-lb with ngtcp2, like this:
```
1) git clone https://github.com/william-zk/ngtcp2
2) build ngtcp2(see https://github.com/william-zk/ngtcp2/blob/master/README.rst)
3) running ngtcp2-server:
./server -d testRoot 127.0.0.1 8444 rsa.key rsa.crt --sid 127.0.0.1:8444
./server -d testRoot 127.0.0.1 8443 rsa.key rsa.crt --sid 127.0.0.1:8443
4) running a quic-lb(with tutorial quic_lb.conf)
5) running ngtcp2-client to test basic quic transmission:
./client 127.0.0.1 9001 https://127.0.0.1:4433/index.html -n 1 --no-quic-dump --no-http-dump  --download clientDownload
6) running ngtcp2-client to test quic connection-migration:
./client 127.0.0.1 9001 https://127.0.0.1:4433/index.html -n 1 --no-quic-dump --no-http-dump  --download clientDownload --change-local-addr 1 --delay-stream 2 --nat-rebinding
```

2.quic-server can obtain real client ip with option "quic_lb_proxy_protocol", like this
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
