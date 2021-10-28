Introduction of feature
=======================
You can get the full introduction in https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-08#section-7,
and this example shows how to use this feature. More detail information is shown in the quic_lb_retry_on.conf,
further more, this case is working in plaintext routing mode.

How to use
=============
- make sure you are in the quic-lb root dir
- exec cmd: ./objs/nginx -p . -c example/retry_service/quic_lb_retry_on.conf
