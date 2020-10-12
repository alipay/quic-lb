nginx-quic-lb
====
nginx-quic-lb is an implementation of ietf-quic-lb(see https://tools.ietf.org/html/draft-ietf-quic-load-balancers-04), based on nginx-release-1.18.0

nginx-quic-lb just implement the date plane function of ietf-quic-lb(forward quic packet, retry service and so on), as for "configuration agent" which was defined in draft, user can implement it with nginx conf file and your own control plane.

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
tutorial configuration file(whole configuration file you can see ${quic-lb-dir}/test/conf/quic_lb.conf):
```
    stream {
        upstream quic_upstreams {
            quic_lb_mode;
            server 127.0.0.1:8443 sid=127.0.0.1:8443;
            server 127.0.0.1:8444 sid=127.0.0.1:8444;
            server 127.0.0.1:8445 sid=127.0.0.1:8445;
            server 127.0.0.1:8446 sid=127.0.0.1:8446;
            server 127.0.0.1:8447 sid=127.0.0.1:8447;
        }

        server {
            listen 8001 quic reuseport;
            proxy_pass quic_upstreams;
            quic_lb_conf_file quic_lb/conf/conf.json;
            proxy_timeout 10s;
            proxy_requests 10000;
            proxy_responses 10000;
        }
    }
```
conf.json file are description below(as draft description: "'configuration agent' will delivery conf file to quic-lb and quic-server at the same time", so we write the same conf options in quic-lb and server into a single conf.json file):
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
