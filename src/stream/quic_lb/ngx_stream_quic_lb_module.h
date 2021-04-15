
/*
 * Copyright 2020. All Rights Reserved.
 * Author: william.zk
 */


#ifndef _NGX_STREAM_QUIC_LB_MODULE_H_INCLUDED_
#define _NGX_STREAM_QUIC_LB_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <cJSON.h>


#define NGX_QUIC_LB_VALID_CONF_NUM  4
#define NGX_QUIC_LB_CONF_ID_MAX     3
#define NGX_QUIC_LB_CONF_ID_MIN     0


typedef enum {
    NGX_QUIC_LB_PLAINTEXT = 1,
    NGX_QUIC_LB_OBFUSCATED,
    NGX_QUIC_LB_STREAM_CIPHER,
    NGX_QUIC_LB_BLOCK_CIPHER
} ngx_quic_lb_route_mode_e;


typedef struct {
    ngx_int_t                   unset;
    ngx_flag_t                  valid;
    ngx_int_t                   conf_id;
    ngx_quic_lb_route_mode_e    quic_lb_route_mode;
    ngx_int_t                   sid_len;
    ngx_rbtree_t                sid_info_tree;
    ngx_rbtree_node_t           sentinel;
    ngx_quic_lb_retry_service_t retry_service;
} ngx_quic_lb_conf_t;


typedef struct {
    ngx_quic_lb_conf_t               quic_lb_conf[NGX_QUIC_LB_VALID_CONF_NUM];
    ngx_flag_t                       quic_lb_proxy_protocol;
} ngx_stream_quic_lb_srv_conf_t;


typedef struct {
    ngx_msec_t                  connect_timeout;
    size_t                      buffer_size;
    void                       *up_rate;
    void                       *down_rate;
    ngx_event_handler_pt        connect_handler;
    ngx_event_handler_pt        proxy_upstream_handler;
    ngx_chain_t                *out;
} ngx_stream_quic_lb_proxy_call_params_t;

extern ngx_module_t  ngx_stream_proxy_module;
ngx_int_t ngx_stream_quic_lb_add_proxy_protocol(void *s_);
ngx_int_t ngx_stream_quic_lb_downstream_pkt_send_process(void *s_,
    ngx_stream_quic_lb_proxy_call_params_t *pcps);
ngx_quic_header_t * ngx_stream_quic_lb_gen_copy_pkt(ngx_connection_t *c,
    ngx_quic_header_t *src);
#endif
