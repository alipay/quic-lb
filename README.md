nginx-quic-lb
====
nginx-quic-lb is an implementation of [ietf-quic-lb](https://tools.ietf.org/html/draft-ietf-quic-load-balancers-08), based on [nginx-release-1.18.0](https://github.com/nginx/nginx/tree/release-1.18.0)

nginx-quic-lb just implement the date plane function of ietf-quic-lb(forward quic packet, retry service and so on).
For "configuration agent" defined in draft, user can implement it with your own control plane and nginx configuration file.

Some features are still under discussion(have not been implemented yet):
```
(1) Block cipher(maybe remove later)
(2) stateless reset(maybe come soon)
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
All features and corresponding introductions and examples are shown below:
- [Plaintext CID routing](example/plaintext/README.md)
- [Stream cipher CID routing](example/stream_cipher/README.md)
- [Retry sevice](example/retry_service/README.md)
- [Proxy protocol](example/proxy_protocol/README.md)
- [Interop with ngtcp2](example/Interoperability_wtih_ngtcp2/README.md)

How to test
----
```
1. pip install pytest
2. cd ${quic-lb-dir}/test
3. make test
```
