
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
#define NGX_QUIC_RETRY_IP_ADDR_LEN                16
#define NGX_QUIC_RETRY_MAX_TOKEN_LEN              77
#define NGX_QUIC_RETRY_MIN_TOKEN_LEN              39
#define NGX_QUIC_RETRY_MAX_TOKEN_BODY_LEN         52
#define NGX_QUIC_RETRY_AAD_LEN                    29
#define NGX_QUIC_RETRY_BUFFER_SIZE                256
#define NGX_QUIC_RETRY_TIMESTAP_LEN               8
#define NGX_QUIC_RETRY_ICV_LEN                    16
#define NGX_QUIC_RETRY_MAX_KEY_NUM                16
#define NGX_QUIC_RETRY_KEY_LEN                    16
#define NGX_QUIC_RETRY_IV_LEN                     12
#define NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN      12
#define NGX_QUIC_RETRY_KEY_SEQ_LEN                1
#define NGX_QUIC_RETRY_CID_LEN_MAX                20


#define NGX_QUIC_RETRY_TOKEN_DEFAULT_LIFE_TIME    3000000


typedef enum {
    NGX_QUIC_LB_RETRY_NO_SHARE_STATE = 1,
    NGX_QUIC_LB_RETRY_SHARED_STATE
} ngx_quic_lb_retry_method_e;


typedef enum {
    NGX_QUIC_LB_RETRY_INACTIVE_MODE = 1,
    NGX_QUIC_LB_RETRY_ACTIVE_MODE
} ngx_quic_lb_retry_mode_e;


typedef struct {
    uint8_t                     retry_key_seq;
    u_char                      retry_token_key[NGX_QUIC_RETRY_KEY_LEN]; /* AES-128-gcm */
    u_char                      retry_token_iv_material[NGX_QUIC_RETRY_IV_LEN];
    uint64_t                    retry_token_alive_time;
} retry_token_enc_info_t;


typedef struct {
    ngx_quic_lb_retry_method_e  retry_method;
    ngx_quic_lb_retry_mode_e    retry_mode;
    uint8_t                     retry_key_num;
    retry_token_enc_info_t     *retry_token_enc_infos;
} ngx_quic_lb_retry_service_t;


typedef struct {
    uint8_t       odcid_len;
    uint8_t       rscid_len;
    uint16_t       port;
    u_char         odcid[NGX_QUIC_RETRY_CID_LEN_MAX];
    u_char         rscid[NGX_QUIC_RETRY_CID_LEN_MAX];
    uint64_t       expire_time;
} ngx_quic_lb_retry_token_body_t;


extern ngx_int_t ngx_stream_quic_lb_do_retry_service(void *,
    ngx_quic_header_t *pkt, ngx_connection_t *c);

#endif //AFE_NGX_STREAM_QUIC_LB_RETRY_SERVICE_H
