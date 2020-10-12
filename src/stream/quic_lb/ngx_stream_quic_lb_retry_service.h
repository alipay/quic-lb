
/*
 * Copyright 2020. All Rights Reserved.
 * Author: Lingtao Kong
 */


#ifndef _NGX_STREAM_QUIC_LB_RETRY_SERVICE_H
#define _NGX_STREAM_QUIC_LB_RETRY_SERVICE_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define NGX_STREAM_QUIC_LB_MAX_RETRY_TOKEN_SIZE   128


typedef enum {
    NGX_QUIC_LB_RETRY_NO_SHARE_STATE = 1,
    NGX_QUIC_LB_RETRY_SHARED_STATE
} ngx_quic_lb_retry_method_e;


typedef enum {
    NGX_QUIC_LB_RETRY_INACTIVE_MODE = 1,
    NGX_QUIC_LB_RETRY_ACTIVE_MODE
} ngx_quic_lb_retry_mode_e;


typedef struct {
    ngx_quic_lb_retry_method_e  retry_method;
    ngx_quic_lb_retry_mode_e    retry_mode;
    u_char                      retry_token_key[32]; /* AES 256 */
} ngx_quic_lb_retry_service_t;


extern ngx_int_t ngx_stream_quic_lb_do_retry_service(void *,
    ngx_quic_header_t *pkt, ngx_connection_t *c);

#endif //AFE_NGX_STREAM_QUIC_LB_RETRY_SERVICE_H
