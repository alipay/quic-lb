Introduction of feature
=======================
Although plaintext algorithm has been abandoned in
https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers,
it is still useful for doing basic interoperability test
with other quic implementation. And this case shows how to use quic-lb
with ngtcp2. Note that you MUST download ngtcp2 in our personal
repo(https://github.com/william-zk/ngtcp2), for we have done some
feature to help the interoperability test.

How to use
=============
- make sure you are in the quic-lb root dir
- compile ngtcp2(https://github.com/william-zk/ngtcp2) as its readme said
- start quic-lb: ./objs/nginx -p . -c example/plaintext/quic_lb_ngtcp2.conf
- Enter the directory of ngtcp2/examples
- start quic-server: ./server -d testRoot 127.0.0.1 8443 ecc-root.key ecc-root.crt --custom-hex-cid 00112233445566777777777777
- start quic-client: ./client 127.0.0.1 8001 https://127.0.0.1:8001/ -n 1 --dcid 0011223344556677
