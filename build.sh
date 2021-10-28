#!/bin/sh
#****************************************************************#
# ScriptName: build.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2020-07-06 21:26
# Modify Author: william.zk@antfin.com
# Modify Date: 2020-07-25 16:15
# Function:
#***************************************************************#

# build cjson
cd libs/cJSON
make
cd ../..

CFLAGS="-g2 -O0"

#build nginx-quic-lb
./auto/configure --with-debug \
                 --with-stream_quic_lb_module \
                 --with-openssl=libs/openssl \
                 --with-cc-opt=" -I./libs/cJSON -Wall -Wno-type-limits"   \
                 --with-ld-opt=" ./libs/cJSON/libcjson.a " \
                 --with-stream

make install
cp -f objs/nginx output/nginx
cp -f objs/nginx test/quic_lb/nginx

#build autotest file
cd test
make clean
make build
cd ..
