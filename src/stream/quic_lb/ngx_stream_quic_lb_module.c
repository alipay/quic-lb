
/*
 * Copyright 2020. All Rights Reserved.
 * Author: william.zk
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static char *ngx_stream_quic_lb_proxy_read_conf_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_quic_lb_parse_plaintext_route_ctx(ngx_conf_t *cf,
    ngx_quic_lb_conf_t *quic_lb_conf, cJSON *root, ngx_str_t *name, ngx_int_t i);
static ngx_int_t ngx_stream_quic_lb_parse_stream_cipher_route_ctx(ngx_conf_t *cf,
    ngx_quic_lb_conf_t *quic_lb_conf, cJSON *root, ngx_str_t *name, ngx_int_t i);
static ngx_int_t ngx_stream_quic_lb_parse_json_conf_file(ngx_conf_t *cf,
    ngx_str_t *name, ngx_quic_lb_conf_t *quic_lb_conf);
static ngx_int_t ngx_stream_quic_lb_parse_json(ngx_conf_t *cf,
    ngx_quic_lb_conf_t *quic_lb_conf, u_char *buf, size_t size, ngx_str_t *name);
static ngx_int_t ngx_stream_quic_lb_parse_retry_service_json(ngx_conf_t *cf,
    ngx_quic_lb_conf_t *quic_lb_conf, cJSON *root, ngx_str_t *name);
static void *ngx_stream_quic_lb_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_quic_lb_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_stream_quic_lb_init(ngx_conf_t *cf);
static ngx_int_t ngx_stream_quic_lb_parse_header_from_buf(ngx_quic_header_t *pkt,
    ngx_buf_t *buf, ngx_connection_t *c, ngx_quic_lb_conf_t *conf_list);
static ngx_int_t ngx_stream_quic_lb_parse_short_header_conf_bit(ngx_quic_header_t *pkt);
static ngx_int_t ngx_stream_quic_lb_parse_short_header_with_fix_dcid_len(
    ngx_quic_header_t *pkt, ngx_int_t dcid_len);
static ngx_int_t ngx_stream_quic_lb_parse_config_rotation_bit(ngx_quic_header_t *pkt);
static u_char * ngx_stream_quic_lb_proxy_protocol_write(ngx_connection_t *c, u_char *buf, u_char *last);
static ngx_int_t ngx_stream_quic_lb_parse_long_header(ngx_quic_header_t *pkt);
static ngx_int_t ngx_stream_quic_lb_rechoose_peer(ngx_stream_session_t *s,
    ngx_stream_quic_lb_proxy_call_params_t *pcps);
static ngx_int_t ngx_stream_quic_lb_reinit_upstream(ngx_stream_session_t *s,
    ngx_stream_quic_lb_proxy_call_params_t *pcps);


static ngx_command_t  ngx_stream_quic_lb_commands[] = {

    { ngx_string("quic_lb_conf_file"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_quic_lb_proxy_read_conf_file,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("quic_lb_proxy_protocol"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_quic_lb_srv_conf_t, quic_lb_proxy_protocol),
      NULL },

    ngx_null_command
};


static ngx_stream_module_t  ngx_stream_quic_lb_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_stream_quic_lb_init,                 /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    ngx_stream_quic_lb_create_srv_conf,      /* create server configuration */
    ngx_stream_quic_lb_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_stream_quic_lb_module = {
    NGX_MODULE_V1,
    &ngx_stream_quic_lb_module_ctx,          /* module context */
    ngx_stream_quic_lb_commands,             /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_stream_quic_lb_add_proxy_protocol(void *s_)
{
    ngx_stream_session_t         *s;
    ngx_connection_t             *c;
    ngx_stream_upstream_t        *u;
    ngx_chain_t                  *cl;
    u_char                       *p;
    s = s_;
    u = s->upstream;
    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "QUIC-LB add PROXY protocol header");

    cl = ngx_chain_get_free_buf(c->pool, &u->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(c->pool, NGX_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        return NGX_ERROR;
    }

    cl->buf->pos = p;

    p = ngx_stream_quic_lb_proxy_protocol_write(c, p, p + NGX_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        return NGX_ERROR;
    }

    cl->buf->last = p;
    cl->buf->temporary = 1;
    cl->buf->flush = 0;
    cl->buf->last_buf = 0;
    cl->buf->tag = (ngx_buf_tag_t)&ngx_stream_proxy_module;

    cl->next = u->upstream_out;
    u->upstream_out = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_reinit_upstream(ngx_stream_session_t *s,
    ngx_stream_quic_lb_proxy_call_params_t *pcps)
{
    u_char                       *p;
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;

    u = s->upstream;
    pc = u->peer.connection;

    ngx_stream_complex_value_t *up_rate = pcps->up_rate;
    ngx_stream_complex_value_t *down_rate = pcps->down_rate;

    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "QUIC-LB %sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = ngx_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    /* should never happen */
    if (u->upstream_buf.start == NULL) {
        p = ngx_pnalloc(c->pool, pcps->buffer_size);
        if (p == NULL) {
            return NGX_ERROR;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pcps->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    u->upload_rate = ngx_stream_complex_value_size(s, up_rate, 0);
    u->download_rate = ngx_stream_complex_value_size(s, down_rate, 0);

    u->connected = 1;

    pc->read->handler = pcps->proxy_upstream_handler;
    pc->write->handler = pcps->proxy_upstream_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_rechoose_peer(ngx_stream_session_t *s,
    ngx_stream_quic_lb_proxy_call_params_t *pcps)
{
    ngx_int_t                     rc;
    ngx_connection_t             *pc;
    ngx_connection_t             *c;
    ngx_stream_upstream_t        *u;

    c = s->connection;
    u = s->upstream;

    /* close last peer connection socket and free related timer */
    pc = u->peer.connection;
    ngx_close_connection(pc);
    u->peer.connection = NULL;

    /* connect to the new peer */
    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "QUIC-LB rechoose peer, "
        "proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    u->state->peer = u->peer.name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "QUIC-LB no live upstreams");
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        return NGX_ERROR;
    }

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NGX_AGAIN) {
        return ngx_stream_quic_lb_reinit_upstream(s, pcps);
    }

    pc->read->handler = pcps->connect_handler;
    pc->write->handler =  pcps->connect_handler;

    ngx_add_timer(pc->write, pcps->connect_timeout);

    return NGX_OK;
}


ngx_int_t
ngx_stream_quic_lb_downstream_pkt_send_process(void *s_,
    ngx_stream_quic_lb_proxy_call_params_t *pcps)
{
    ngx_stream_upstream_rr_peer_data_t *rrp;
    ngx_int_t                           rc;
    ngx_connection_t                   *c;
    ngx_stream_upstream_t              *u;
    ngx_stream_quic_lb_srv_conf_t      *qlscf;

    ngx_stream_session_t *s = s_;

    c = s->connection;
    u = s->upstream;
    rrp = u->peer.data;

    qlscf = ngx_stream_get_module_srv_conf(s, ngx_stream_quic_lb_module);

    if (ngx_stream_quic_lb_parse_header_from_buf(s->pkt, pcps->out->buf, c,
        qlscf->quic_lb_conf) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
            "QUIC-LB, recv packet does not follow quic packet format");
        return NGX_ERROR;
    }

    s->quic_lb_conf = &qlscf->quic_lb_conf[s->pkt->conf_id];

    ngx_quic_hexdump(c->pool->log, "last sid is", rrp->pkt->sid.data, rrp->pkt->sid.len);
    ngx_quic_hexdump(c->pool->log, "curr sid is", s->pkt->sid.data, s->pkt->sid.len);

    /* sid include conf rotation byte, we only compare sid */
    if (rrp->pkt->sid.len != s->pkt->sid.len
        || ngx_strncmp(s->pkt->sid.data, rrp->pkt->sid.data,
                       s->pkt->sid.len) != 0)
    {
        rrp->pkt->dcid.len = s->pkt->dcid.len;
        rrp->pkt->sid.len = s->pkt->sid.len;
        ngx_memcpy(rrp->pkt->dcid.data, s->pkt->dcid.data, s->pkt->dcid.len);
        ngx_memcpy(rrp->pkt->sid.data, s->pkt->sid.data, s->pkt->sid.len);
        rrp->pkt->conf_id = s->pkt->conf_id;
        rrp->quic_lb_conf = s->quic_lb_conf;

        /* for initial pkt, do retry service, draft 04, chapter 6. */
        if (rrp->quic_lb_conf->valid && s->pkt->initial_pkt) {
            ngx_int_t res = ngx_stream_quic_lb_do_retry_service(qlscf, s->pkt, c);
            if (res == NGX_OK) {
                ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                              "QUIC-LB, retry service, pass source "
                                  "address token validation.");
            } else {
                ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                              "QUIC-LB, do retry service failed, return. downstream close session");
                return NGX_ERROR;
            }
        }

        rc = ngx_stream_quic_lb_rechoose_peer(s, pcps);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                          "QUIC-LB, choose peer and send has error");
            return NGX_DECLINED;
        }
    }

    if (qlscf->quic_lb_proxy_protocol) {
        ngx_int_t ret = ngx_stream_quic_lb_add_proxy_protocol(s);
        if (ret != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_header_from_buf(ngx_quic_header_t *pkt, ngx_buf_t *buf,
    ngx_connection_t *c, ngx_quic_lb_conf_t *conf_list)
{
    ngx_int_t sid_len, conf_id;

    ngx_memzero(pkt, sizeof(ngx_quic_header_t));
    pkt->raw = buf;
    pkt->data = buf->pos;
    pkt->len = buf->last - buf->pos;
    pkt->log = c->pool->log;
    pkt->flags = buf->pos[0];

    ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                  "QUIC-LB, start to pasre header from buf");

    if (ngx_quic_long_pkt(pkt->flags)) {

        ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                      "QUIC-LB, is a long pkt");

        if (ngx_stream_quic_lb_parse_long_header(pkt) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                          "QUIC-LB, recv invalid long header packet.");
            return NGX_ERROR;
        }

        if (ngx_quic_pkt_in(pkt->flags)) {
            if (pkt->dcid.len < NGX_QUIC_CID_LEN_MIN) {
                /* draft-transport-7.2. Negotiating Connection IDs */
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic too short dcid in initial"
                              " packet: len:%i", pkt->dcid.len);
                return NGX_ERROR;
            }

            pkt->initial_pkt = 1;
            ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                          "QUIC-LB, is init pkt");
            /* get token*/
            if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                              "QUIC-LB, recv invalid initial packet.");
                return NGX_ERROR;
            }
        }
    } else if (ngx_quic_short_pkt(pkt->flags)) {
        /* we just read configuration rotate 2 bit to pkt->dcid.data for later process */
        if (ngx_stream_quic_lb_parse_short_header_conf_bit(pkt) != NGX_OK) {
            return NGX_ERROR;
        }
    } else {
        return NGX_ERROR;
    }

    /* Todo: for some init packet, cid would be random, how to recognized them */
    conf_id = ngx_stream_quic_lb_parse_config_rotation_bit(pkt);
    if (conf_id < NGX_QUIC_LB_CONF_ID_MIN || conf_id > NGX_QUIC_LB_CONF_ID_MAX) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, recv packet config rotation bit have problems");
        return NGX_ERROR;
    }

    pkt->conf_id = conf_id;
    sid_len = conf_list[conf_id].route_ctx.sid_len;
    if (sid_len > NGX_QUIC_CID_LEN_MAX - 1 || sid_len < 0) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, sid_len in current conf of short header packet has problem");
        return NGX_ERROR;
    }

    if (sid_len == 0) {
        if (ngx_quic_short_pkt(pkt->flags)) {
            ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                          "QUIC-LB, short packet mismatch config file, drop it");
            return NGX_ERROR;
        }

        /*
         * for long header packet, if config rotation bit mistach config file,
         * then we route it by dcid
         */
        sid_len = pkt->dcid.len;
    }


    if (ngx_quic_short_pkt(pkt->flags)) {
        ngx_int_t   route_info_len = 0;

        /*
         * for short header packet, we just need route_info in dcid for routing,
         * for plaintext route mode, length of route_info is 1+sid_len
         * for stream cipher route mode, length of route_info is 1+sid_len+nonce_len
         */
        switch (conf_list[conf_id].quic_lb_route_mode)
        {
        case NGX_QUIC_LB_PLAINTEXT:
            route_info_len = sid_len + 1;
            break;

        case NGX_QUIC_LB_STREAM_CIPHER:
            route_info_len = 1 + conf_list[conf_id].route_ctx.sid_len + conf_list[conf_id].route_ctx.nonce_len;
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                          "QUIC-LB, short packet match unkonw route mode");
            return NGX_ERROR;
        }

        if (ngx_stream_quic_lb_parse_short_header_with_fix_dcid_len(pkt, route_info_len) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* record dest sid, sid was composed by first byte and sid */
    pkt->sid.len = sid_len;
    pkt->sid.data = &pkt->dcid.data[1];
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, header dcid: ",
                     pkt->dcid.data, pkt->dcid.len);
#endif
    /*
     * pkt parse will change the buf->pos, actually we only need parse result,
     * so we change buf->pos to origin pos(pkt->data)
     */
    buf->pos = pkt->data;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_short_header_conf_bit(ngx_quic_header_t *pkt)
{
    return ngx_stream_quic_lb_parse_short_header_with_fix_dcid_len(pkt, 1);
}


static ngx_int_t
ngx_stream_quic_lb_parse_short_header_with_fix_dcid_len(ngx_quic_header_t *pkt,
    ngx_int_t dcid_len)
{
    u_char  *p, *end;

    p = pkt->data;
    end = pkt->data + pkt->len;

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(pkt->log, "QUIC-LB, quic short packet in", pkt->data, pkt->len);
#endif

    p = ngx_quic_read_uint8(p, end, &pkt->flags);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read flags");
        return NGX_ERROR;
    }

    if (!ngx_quic_short_pkt(pkt->flags)) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0, "QUIC-LB, quic not a short packet");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "QUIC-LB, quic short packet flags:%xi", pkt->flags);

    if (!(pkt->flags & NGX_QUIC_PKT_FIXED_BIT)) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0, "QUIC-LB, quic fixed bit is not set");
        return NGX_DECLINED;
    }

    /* we just read */
    pkt->dcid.len = dcid_len;

    p = ngx_quic_read_bytes(p, end, pkt->dcid.len, &pkt->dcid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read dcid");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_long_header(ngx_quic_header_t *pkt)
{
    u_char  *p, *end;
    uint8_t  idlen;

    p = pkt->data;
    end = pkt->data + pkt->len;

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(pkt->log, "QUIC-LB, quic long packet in", pkt->data, pkt->len);
#endif

    p = ngx_quic_read_uint8(p, end, &pkt->flags);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read flags");
        return NGX_ERROR;
    }

    if (!ngx_quic_long_pkt(pkt->flags)) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0, "QUIC-LB, not a quic long packet");
        return NGX_ERROR;
    }

    p = ngx_quic_read_uint32(p, end, &pkt->version);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read version");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "QUIC-LB, quic long packet flags:%xi version:%xD",
                   pkt->flags, pkt->version);
#if 0
    if (!(pkt->flags & NGX_QUIC_PKT_FIXED_BIT)) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0, "QUIC-LB, quic fixed bit is not set");
        return NGX_DECLINED;
    }
#endif
    if (pkt->version > NGX_QUIC_VERSION_UP) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0, "QUIC-LB, recv invalid quic version:%d",
                      pkt->version & 0xff);

        return NGX_ERROR;
    }

    p = ngx_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read dcid len");
        return NGX_ERROR;
    }

    if (idlen > NGX_QUIC_CID_LEN_MAX) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet dcid is too long");
        return NGX_ERROR;
    }

    pkt->dcid.len = idlen;

    p = ngx_quic_read_bytes(p, end, idlen, &pkt->dcid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read dcid");
        return NGX_ERROR;
    }

    p = ngx_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read scid len");
        return NGX_ERROR;
    }

    if (idlen > NGX_QUIC_CID_LEN_MAX) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet scid is too long");
        return NGX_ERROR;
    }

    pkt->scid.len = idlen;

    p = ngx_quic_read_bytes(p, end, idlen, &pkt->scid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, pkt->log, 0,
                      "QUIC-LB, quic packet is too small to read scid");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_config_rotation_bit(ngx_quic_header_t *pkt)
{
    uint8_t   conf_id = 0;
    u_char   *p;

    p = pkt->dcid.data;
    conf_id = (p[0] & 0xc0) >> 6;
    return (ngx_int_t)conf_id;
}


static u_char *
ngx_stream_quic_lb_proxy_protocol_write(ngx_connection_t *c, u_char *buf, u_char *last)
{
    ngx_uint_t  port, lport;

    if (last - buf < NGX_PROXY_PROTOCOL_MAX_HEADER) {
        return NULL;
    }

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NULL;
    }

    if (c->sockaddr->sa_family == AF_INET6) {
        buf = ngx_cpymem(buf, "PROXY QUICV6 ", sizeof("PROXY QUICV6 ") - 1);
    } else {
        buf = ngx_cpymem(buf, "PROXY QUICV4 ", sizeof("PROXY QUICV4 ") - 1);
    }

    buf += ngx_sock_ntop(c->sockaddr, c->socklen, buf, last - buf, 0);

    *buf++ = ' ';

    buf += ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf, last - buf, 0);

    port = ngx_inet_get_port(c->sockaddr);
    lport = ngx_inet_get_port(c->local_sockaddr);

    return ngx_slprintf(buf, last, " %ui %ui" CRLF, port, lport);
}


static char *
ngx_stream_quic_lb_proxy_read_conf_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_quic_lb_srv_conf_t     *qlscf = conf;
    ngx_str_t                         *value;

    value = cf->args->elts;
    if (cf->args->nelts != 2) {
        return "only one quic lb conf file needed";
    }

    if (ngx_stream_quic_lb_parse_json_conf_file(cf, &(value[1]),
        qlscf->quic_lb_conf) != NGX_OK)
    {
        return "quic lb conf file have problem";
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_json_conf_file(ngx_conf_t *cf, ngx_str_t *name,
    ngx_quic_lb_conf_t *quic_lb_conf)
{
    ngx_file_t                  file;
    ngx_file_info_t             fi;
    ngx_int_t                   rc, i;
    size_t                      size;
    u_char                     *buf;
    ssize_t                     n;
    ngx_err_t                   err;

    for (i = 0; i < NGX_QUIC_LB_VALID_CONF_NUM; i++) {
        quic_lb_conf[i].unset = 1;
    }

    rc = NGX_ERROR;
    ngx_memzero(&file, sizeof(ngx_file_t));

    file.name = *name;
    file.log = cf->log;
    file.fd = ngx_open_file(name->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, err,
                               ngx_open_file_n " \"%s\" failed", name->data);
        }
        goto failed;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_fd_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    size = (size_t) ngx_file_size(&fi);

    if (ngx_file_info(name->data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_file_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    buf = ngx_palloc(cf->pool, size);
    if (buf == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" failed", name->data);
        goto failed;
    }

    n = ngx_read_file(&file, buf, size, 0);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" failed", name->data);
        goto failed;
    }

    if ((size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
                           ngx_read_file_n " \"%s\" returned only %z bytes instead of %z",
                           name->data, n, size);
        goto failed;
    }

    if (ngx_stream_quic_lb_parse_json(cf, quic_lb_conf, buf,
        size, name) == NGX_ERROR)
    {
        goto failed;
    }

    rc = NGX_OK;

failed:
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n ngx_close_file_n " \"%s\" failed", name->data);
    }

    return rc;
}


static ngx_int_t
ngx_stream_quic_lb_parse_plaintext_route_ctx(ngx_conf_t *cf,
    ngx_quic_lb_conf_t *quic_lb_conf, cJSON *root, ngx_str_t *name, ngx_int_t i)
{
    cJSON   *route_ctx, *sid_len;

    route_ctx = cJSON_GetObjectItem(root, "route_ctx");
    if (route_ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file does not have json "
                            "object route_ctx, conf item index is: %d ", name->data, i);
        return NGX_ERROR;
    }

    sid_len = cJSON_GetObjectItem(route_ctx, "sid_len");
    if (sid_len == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file does not have json "
                            "object sid_len, conf item index is: %d ", name->data, i);
        return NGX_ERROR;
    }

    quic_lb_conf->route_ctx.sid_len = sid_len->valuedouble;
    if (quic_lb_conf->route_ctx.sid_len <= 0
        || quic_lb_conf->route_ctx.sid_len > NGX_QUIC_CID_LEN_MAX)
    {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file sid len was wrong"
                            "conf item index is: %d", name->data, i);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_stream_cipher_route_ctx(ngx_conf_t *cf,
    ngx_quic_lb_conf_t *quic_lb_conf, cJSON *root, ngx_str_t *name, ngx_int_t i)
{
    cJSON       *route_ctx, *sid_len, *nonce_len, *enc_key, *use_hex;
    ngx_int_t    enc_key_len;
    ngx_int_t    expected_enc_key_len;
    u_char      *expected_enc_key;
    u_char       enc_key_buf[NGX_QUIC_LB_STREAM_CIPHER_KEY_LEN];
    ngx_int_t    rc;

    route_ctx = cJSON_GetObjectItem(root, "route_ctx");
    if (route_ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file does not have json "
                           "object route_ctx, conf item index is: %d ", name->data, i);
        return NGX_ERROR;
    }

    sid_len = cJSON_GetObjectItem(route_ctx, "sid_len");
    if (sid_len == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file does not have json "
                           "object sid_len, conf item index is: %d ", name->data, i);
        return NGX_ERROR;
    }

    nonce_len = cJSON_GetObjectItem(route_ctx, "nonce_len");
    if (nonce_len == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file does not have json "
                           "object nonce_len, conf item index is: %d ", name->data, i);
        return NGX_ERROR;
    }

    enc_key = cJSON_GetObjectItem(route_ctx, "enc_key");
    if (enc_key == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file does not have json "
                            "object enc_key, conf item index is: %d ", name->data, i);
        return NGX_ERROR;
    }

    quic_lb_conf->route_ctx.use_hex = 0;
    use_hex = cJSON_GetObjectItem(route_ctx, "use_hex");
    if (use_hex && cJSON_IsTrue(use_hex)) {
        quic_lb_conf->route_ctx.use_hex = 1;
        ngx_conf_log_error(NGX_LOG_DEBUG, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file, conf item index is: %d, "
                            "input key/iv is hex style ", name->data, i);
    }

    quic_lb_conf->route_ctx.sid_len = sid_len->valuedouble;
    if (quic_lb_conf->route_ctx.sid_len < NGX_QUIC_LB_STREAM_CIPHER_SID_LEN_MIN
        || quic_lb_conf->route_ctx.sid_len > NGX_QUIC_LB_STREAM_CIPHER_SID_LEN_MAX)
    {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file sid len was wrong, "
                            "conf item index is: %d", name->data, i);
        return NGX_ERROR;
    }

    quic_lb_conf->route_ctx.nonce_len = nonce_len->valuedouble;
    if (quic_lb_conf->route_ctx.nonce_len < NGX_QUIC_LB_STREAM_CIPHER_NONCE_LEN_MIN
        || quic_lb_conf->route_ctx.nonce_len > NGX_QUIC_LB_STREAM_CIPHER_NONCE_LEN_MAX)
    {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file nonce len was wrong, "
                            "conf item index is: %d", name->data, i);
        return NGX_ERROR;
    }

    if (quic_lb_conf->route_ctx.sid_len + quic_lb_conf->route_ctx.nonce_len
            > NGX_QUIC_LB_STREAM_CIPHER_LIMIT_INFO_LEN)
    {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file sid_len+nonce_len out of range, "
                            "conf item index is: %d", name->data, i);
        return NGX_ERROR;
    }

    enc_key_len = ngx_strlen(enc_key->valuestring);
    expected_enc_key_len = NGX_QUIC_LB_STREAM_CIPHER_KEY_LEN;
    if (quic_lb_conf->route_ctx.use_hex) {
        rc = ngx_quic_hexstring_to_string(enc_key_buf, (u_char *)enc_key->valuestring,
                                          2 * NGX_QUIC_LB_STREAM_CIPHER_KEY_LEN);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%s\" file, conf item index is: %d, "
                               "enc_key is not follow hex style", name->data, i);
            return NGX_ERROR;
        }
        expected_enc_key = enc_key_buf;
        enc_key_len = enc_key_len / 2;
    } else {
        expected_enc_key = (u_char *)enc_key->valuestring;
    }

    if (enc_key_len != expected_enc_key_len) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file enc_key length error, "
                           "conf item index is: %d", name->data, i);
        return NGX_ERROR;
    }

    quic_lb_conf->route_ctx.enc_key.data = ngx_palloc(cf->pool, enc_key_len);
    if (quic_lb_conf->route_ctx.enc_key.data == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file, conf item index is: %d, "
                            "ngx_palloc error", name->data, i);
        return NGX_ERROR;
    }

    quic_lb_conf->route_ctx.enc_key.len = expected_enc_key_len;
    ngx_memcpy(quic_lb_conf->route_ctx.enc_key.data, expected_enc_key, expected_enc_key_len);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_json(ngx_conf_t *cf, ngx_quic_lb_conf_t *quic_lb_conf,
    u_char *buf, size_t size, ngx_str_t *name)
{
    cJSON                       *root;
    ngx_int_t                    conf_num, i;

    if (cf == NULL || quic_lb_conf == NULL || buf == NULL || name == NULL) {
        return NGX_ERROR;
    }

    /* parse json item */
    root = cJSON_ParseWithLength((const char*)buf, size);
    if (root == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file does not "
                           "follow json format", name->data);
        goto failed;
    }

    conf_num = cJSON_GetArraySize(root);
    if (conf_num <= 0 || conf_num > 3) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file have more "
                           "than 3 or less than 1 conf item", name->data);
        goto failed;
    }

    for (i = 0; i < conf_num; i++) {
        cJSON     *conf;
        cJSON     *conf_id, *route_mode;
        ngx_int_t  conf_index;

        conf = cJSON_GetArrayItem(root, i);
        if (conf == NULL) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%s\" file server_info object "
                               "read wrong, conf item index is: %d ", name->data, i);
            goto failed;
        }

        conf_id = cJSON_GetObjectItem(conf, "conf_id");
        if (conf_id == NULL) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%s\" file does not have json "
                               "object conf_id, conf item index is: %d", name->data, i);
            goto failed;
        }

        route_mode = cJSON_GetObjectItem(conf, "route_mode");
        if (route_mode == NULL) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%s\" file does not have json "
                               "object route_mode, conf item index is: %d ", name->data, i);
            goto failed;
        }

        conf_index = conf_id->valueint;
        if (conf_index < 0 || conf_index > 2) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%s\" file conf id error "
                               "conf item index is: %d  ", name->data, i);
            goto failed;
        }

        if (quic_lb_conf[conf_index].unset != 1) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%s\" file conf id error "
                               "conf item has duplicate conf_id ", name->data);
            goto failed;
        }

        quic_lb_conf[conf_index].unset = 0;
        /* store json item to quic_lb_conf */
        quic_lb_conf[conf_index].conf_id = conf_index;

        if (ngx_stream_quic_lb_parse_retry_service_json(cf,
            &(quic_lb_conf[conf_index]), conf, name) != NGX_OK)
        {
            goto failed;
        }

        if (ngx_strcmp(route_mode->valuestring, "plaintext") == 0) {
            quic_lb_conf[conf_index].quic_lb_route_mode = NGX_QUIC_LB_PLAINTEXT;
            if (ngx_stream_quic_lb_parse_plaintext_route_ctx(cf,
                    &(quic_lb_conf[conf_index]), conf, name, i) != NGX_OK)
            {
                goto failed;
            }

        } else if (ngx_strcmp(route_mode->valuestring, "stream_cipher") == 0) {
            quic_lb_conf[conf_index].quic_lb_route_mode = NGX_QUIC_LB_STREAM_CIPHER;
            if (ngx_stream_quic_lb_parse_stream_cipher_route_ctx(cf,
                    &(quic_lb_conf[conf_index]), conf, name, i) != NGX_OK)
            {
                goto failed;
            }

        } else {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                               ngx_read_file_n " \"%s\" file route mode does not match"
                               "any available route mode,conf item index is: %d ",
                               name->data, i);
            goto failed;
        }

        quic_lb_conf[conf_index].valid = 1;
    }

    cJSON_Delete(root);
    return NGX_OK;

failed:
    cJSON_Delete(root);
    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_quic_lb_parse_retry_service_json(ngx_conf_t *cf,
    ngx_quic_lb_conf_t *quic_lb_conf, cJSON *root, ngx_str_t *name)
{
    ngx_int_t   retry_token_enc_info_nums;
    ngx_int_t   i;
    cJSON      *retry_service_ctx;
    cJSON      *retry_method, *retry_mode;
    cJSON      *retry_token_enc_info, *retry_token_enc_info_item;
    cJSON      *retry_key_seq, *retry_token_key, *retry_token_iv_material;
    cJSON      *retry_token_life_time;

    if (quic_lb_conf == NULL || root == NULL) {
        return NGX_ERROR;
    }

    retry_service_ctx = cJSON_GetObjectItem(root, "retry_service_ctx");
    if (retry_service_ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file does not have json object retry_service_ctx ", name->data);
        return NGX_ERROR;
    }

    retry_method = cJSON_GetObjectItem(retry_service_ctx, "retry_method");
    if (retry_method == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file retry_service_ctx object has a wrong item, "
                           "need \"retry_method\" object ", name->data);
        return NGX_ERROR;
    }
    if (ngx_strcmp(retry_method->valuestring, "shared_state") == 0) {
        quic_lb_conf->retry_service.retry_method = NGX_QUIC_LB_RETRY_SHARED_STATE;
    } else if (ngx_strcmp(retry_method->valuestring, "no_state") == 0) {
        quic_lb_conf->retry_service.retry_method = NGX_QUIC_LB_RETRY_NO_SHARE_STATE;
    } else {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file retry_service_ctx method "
                           "should be \"shared_state or no_state\" ", name->data);
        return NGX_ERROR;
    }

    retry_mode = cJSON_GetObjectItem(retry_service_ctx, "retry_mode");
    if (retry_mode == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file retry_service_ctx object has a wrong item, "
                           "need \"retry_mode\" object ", name->data);
        return NGX_ERROR;
    }
    if (ngx_strcmp(retry_mode->valuestring, "inactive") == 0) {
        quic_lb_conf->retry_service.retry_mode = NGX_QUIC_LB_RETRY_INACTIVE_MODE;
    } else if (ngx_strcmp(retry_mode->valuestring, "active") == 0) {
        quic_lb_conf->retry_service.retry_mode = NGX_QUIC_LB_RETRY_ACTIVE_MODE;
    } else {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file retry_service_ctx state "
						   "should be \"inactive or active\" ", name->data);
        return NGX_ERROR;
    }


    retry_token_enc_info = cJSON_GetObjectItem(retry_service_ctx, "retry_token_enc_info");
    if (retry_token_enc_info == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file retry_service_ctx object has a wrong item, "
						   "need \"retry_token_enc_info\" object ", name->data);
        return NGX_ERROR;
    }

    retry_token_enc_info_nums = cJSON_GetArraySize(retry_token_enc_info);
    if (retry_token_enc_info_nums <= 0) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file retry_token_enc_info object "
                           "should have much than one item", name->data);
        return NGX_ERROR;
    }

    if (retry_token_enc_info_nums > NGX_QUIC_RETRY_MAX_KEY_NUM) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file retry_token_enc_info object "
                           "item nums illegal, show less than: %d",
                           name->data, NGX_QUIC_RETRY_MAX_KEY_NUM);
        return NGX_ERROR;
    }

    quic_lb_conf->retry_service.retry_key_num = retry_token_enc_info_nums;
    quic_lb_conf->retry_service.retry_token_enc_infos = ngx_palloc(cf->pool,
                                                                   retry_token_enc_info_nums * sizeof(retry_token_enc_info_t));

    for (i = 0; i < retry_token_enc_info_nums; i++) {
        retry_token_enc_info_item = cJSON_GetArrayItem(retry_token_enc_info, i);

        if (retry_token_enc_info_item == NULL) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%s\" file parse retry_token_enc_info object "
                           "internal error", name->data);
            return NGX_ERROR;
        }

        retry_key_seq = cJSON_GetObjectItem(retry_token_enc_info_item, "retry_key_seq");
        if (retry_key_seq == NULL) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file retry_token_enc_info object has a wrong item, "
                            "need \"retry_key_seq\" object ", name->data);
            return NGX_ERROR;
        }

        if (retry_key_seq->valueint > 255 || retry_key_seq->valueint < 0) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file retry_service_ctx object has a wrong item, "
                            "\"retry_key_seq\" should greater than 0 and less than 255");
            return NGX_ERROR;
        }

        quic_lb_conf->retry_service.retry_token_enc_infos[i].retry_key_seq = (uint8_t)retry_key_seq->valueint;

        retry_token_key = cJSON_GetObjectItem(retry_token_enc_info_item, "retry_token_key");
        if (retry_token_key == NULL) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file retry_token_enc_info object has a wrong item, "
                            "need \"retry_token_key\" object ", name->data);
            return NGX_ERROR;
        }

        if (ngx_strlen(retry_token_key->valuestring) != NGX_QUIC_RETRY_KEY_LEN) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file retry_service_ctx object has a wrong item, "
                            "\"retry_token_key\" len should be %d", name->data, NGX_QUIC_RETRY_KEY_LEN);
            return NGX_ERROR;
        }

        ngx_memcpy(quic_lb_conf->retry_service.retry_token_enc_infos[i].retry_token_key,
                retry_token_key->valuestring, NGX_QUIC_RETRY_KEY_LEN);

        retry_token_iv_material = cJSON_GetObjectItem(retry_token_enc_info_item, "retry_token_iv_material");
        if (retry_token_iv_material == NULL) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file retry_token_enc_info object has a wrong item, "
                            "need \"retry_token_iv_material\" object ", name->data);
            return NGX_ERROR;
        }

        if (ngx_strlen(retry_token_iv_material->valuestring) != NGX_QUIC_RETRY_IV_LEN) {
            ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file retry_service_ctx object has a wrong item, "
                            "\"retry_token_key\" len should be %d", name->data, NGX_QUIC_RETRY_IV_LEN);
            return NGX_ERROR;
        }

        ngx_memcpy(quic_lb_conf->retry_service.retry_token_enc_infos[i].retry_token_iv_material,
                retry_token_iv_material->valuestring, NGX_QUIC_RETRY_IV_LEN);

        retry_token_life_time = cJSON_GetObjectItem(retry_token_enc_info_item, "retry_token_life_time");
        if (retry_token_life_time == NULL) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, ngx_errno,
                            ngx_read_file_n " \"%s\" file retry_service_ctx object miss "
                            "\"retry_token_life_time\" item, use default value", name->data);
            quic_lb_conf->retry_service.retry_token_enc_infos[i].retry_token_alive_time = NGX_QUIC_RETRY_TOKEN_DEFAULT_LIFE_TIME;
        } else {
            quic_lb_conf->retry_service.retry_token_enc_infos[i].retry_token_alive_time = retry_token_life_time->valueint;
        }
    }

    return NGX_OK;
}


static void *
ngx_stream_quic_lb_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_quic_lb_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_quic_lb_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->quic_lb_proxy_protocol = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_quic_lb_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_quic_lb_srv_conf_t *prev = parent;
    ngx_stream_quic_lb_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->quic_lb_proxy_protocol,
                         prev->quic_lb_proxy_protocol, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_quic_lb_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c;

    c = s->connection;

    if (c->proxy_quic) {
        ngx_stream_quic_lb_srv_conf_t  *qlscf;

        qlscf = ngx_stream_get_module_srv_conf(s, ngx_stream_quic_lb_module);
        if (s->pkt == NULL) {
            s->pkt = ngx_palloc(c->pool, sizeof(ngx_quic_header_t));
        }

        if (s->pkt == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                "QUIC-LB, quic header packet alloc failed");
            return NGX_ERROR;
        }

        if (ngx_stream_quic_lb_parse_header_from_buf(s->pkt,
                c->buffer, c, qlscf->quic_lb_conf) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                "QUIC-LB, recv packet does not follow quic packet format");
            return NGX_ERROR;
        }

        s->quic_lb_conf = &qlscf->quic_lb_conf[s->pkt->conf_id];

        /* for initial pkt, do retry service, draft 04, chapter 6. */
        if (s->quic_lb_conf->valid && s->pkt->initial_pkt) {
            ngx_int_t res = ngx_stream_quic_lb_do_retry_service(qlscf, s->pkt, c);
            if (res == NGX_OK) {
                ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                              "QUIC-LB, retry service, pass source "
                              "address token validation.");
            } else {
                ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                              "QUIC-LB, do retry service failed, return.");
                return NGX_ERROR;
            }
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_quic_lb_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_quic_lb_handler;

    return NGX_OK;
}


ngx_quic_header_t *
ngx_stream_quic_lb_gen_copy_pkt(ngx_connection_t *c, ngx_quic_header_t *src)
{
    ngx_quic_header_t *pkt;

    pkt = ngx_palloc(c->pool, sizeof(ngx_quic_header_t));

    if (pkt == NULL) {
        return NULL;
    }

    /* just copy what we need */
    pkt->dcid.data = ngx_palloc(c->pool, src->dcid.len);
    pkt->sid.data = ngx_palloc(c->pool, src->sid.len);
    if (pkt->dcid.data == NULL || pkt->sid.data == NULL) {
        return NULL;
    }
    pkt->dcid.len = src->dcid.len;
    pkt->sid.len = src->sid.len;
    ngx_memcpy(pkt->dcid.data, src->dcid.data, src->dcid.len);
    ngx_memcpy(pkt->sid.data, src->sid.data, src->sid.len);
    pkt->conf_id = src->conf_id;

    return pkt;
}
