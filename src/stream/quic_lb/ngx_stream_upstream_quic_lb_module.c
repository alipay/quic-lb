
/*
 * Copyright 2020. All Rights Reserved.
 * Author: william.zk
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    uint32_t                              hash;
    ngx_str_t                            *server;
} ngx_stream_upstream_quic_lb_chash_point_t;


typedef struct {
    ngx_uint_t                                    number;
    ngx_stream_upstream_quic_lb_chash_point_t     point[1];
} ngx_stream_upstream_quic_lb_chash_points_t;


typedef struct {
    ngx_str_t                                     conf;
    ngx_str_t                                     quic_conf_file[3];
    ngx_stream_upstream_quic_lb_chash_points_t   *points;
    ngx_stream_complex_value_t                    key;
} ngx_stream_upstream_quic_lb_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    ngx_stream_upstream_rr_peer_data_t      rrp;
    ngx_stream_upstream_quic_lb_srv_conf_t  *conf;
    ngx_str_t                               key;
    ngx_uint_t                              tries;
    ngx_uint_t                              rehash;
    uint32_t                                hash;
    ngx_event_get_peer_pt                   get_rr_peer;
} ngx_stream_upstream_quic_lb_peer_data_t;


static ngx_int_t ngx_stream_upstream_init_quic_lb_with_sid(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
static char *ngx_stream_upstream_quic_lb_mode(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_stream_upstream_quic_lb_create_conf(ngx_conf_t *cf);
static char *ngx_stream_upstream_quic_lb_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_stream_upstream_init_quic_lb(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_init_quic_lb_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
static ngx_int_t ngx_stream_upstream_get_quic_lb_peer(ngx_peer_connection_t *pc,
    void *data);
static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_quic_lb_get_peer_by_plaintext_algo(
    ngx_peer_connection_t *pc, ngx_stream_upstream_rr_peer_data_t *rrp);
static ngx_stream_upstream_rr_peer_t * ngx_stream_upstream_quic_lb_get_peer_by_sid(
    ngx_peer_connection_t *pc, ngx_stream_upstream_rr_peer_data_t *rrp);
static void ngx_stream_upstream_free_quic_lb_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
static int ngx_libc_cdecl ngx_stream_upstream_quic_lb_chash_cmp_points(const void *one,
    const void *two);
static ngx_uint_t ngx_stream_upstream_quic_lb_find_chash_point(
    ngx_stream_upstream_quic_lb_chash_points_t *points, uint32_t hash);
static ngx_int_t ngx_stream_upstream_quic_lb_get_peer_by_chash(ngx_peer_connection_t *pc,
    void *data);


static ngx_command_t  ngx_stream_quic_lb_commands[] = {
    { ngx_string("quic_lb_mode"),
      NGX_STREAM_UPS_CONF|NGX_CONF_NOARGS,
      ngx_stream_upstream_quic_lb_mode,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_quic_lb_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_upstream_quic_lb_create_conf,        /* create server configuration */
    ngx_stream_upstream_quic_lb_merge_srv_conf,     /* merge server configuration */
};


ngx_module_t  ngx_stream_upstream_quic_lb_module = {
    NGX_MODULE_V1,
    &ngx_stream_quic_lb_module_ctx,        /* module context */
    ngx_stream_quic_lb_commands,           /* module directives */
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


static ngx_int_t
ngx_stream_upstream_init_quic_lb_with_sid(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_url_t                                u;
    ngx_uint_t                               i, j, n, w;
    ngx_stream_upstream_server_t            *server;
    ngx_stream_upstream_rr_peer_t           *peer, **peerp;
    ngx_stream_upstream_rr_peers_t          *peers, *backup;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;
        w = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "QUIC-LB, no servers in upstream \"%V\" in %s:%ui",
                          &us->host, us->file_name, us->line);
            return NGX_ERROR;
        }

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NGX_ERROR;
        }

        peers->single = (n == 1);
        peers->number = n;
        peers->weighted = (w != n);
        peers->total_weight = w;
        peers->name = &us->host;

        n = 0;
        peerp = &peers->peer;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
                peer[n].sid = server[i].sid;


                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        us->peer.data = peers;

        /* backup servers */

        n = 0;
        w = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;
        }

        if (n == 0) {
            return NGX_OK;
        }

        backup = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
        if (backup == NULL) {
            return NGX_ERROR;
        }

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NGX_ERROR;
        }

        peers->single = 0;
        backup->single = 0;
        backup->number = n;
        backup->weighted = (w != n);
        backup->total_weight = w;
        backup->name = &us->host;

        n = 0;
        peerp = &backup->peer;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
                peer[n].sid = server[i].sid;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        peers->next = backup;

        return NGX_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "QUIC-LB, no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
    u.port = us->port;

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "QUIC-LB, %s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->weighted = 0;
    peers->total_weight = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++) {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
        peer[i].current_weight = 0;
        peer[i].max_conns = 0;
        peer[i].max_fails = 1;
        peer[i].fail_timeout = 10;
        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_init_quic_lb(ngx_conf_t *cf, ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_rr_peer_t                   *peer;
    ngx_stream_upstream_rr_peers_t                  *peers;
    ngx_stream_upstream_quic_lb_chash_points_t      *points;
    ngx_stream_upstream_quic_lb_srv_conf_t          *qlcf;
    ngx_uint_t                                       npoints, i, j;
    u_char                                          *host, *port, c;
    size_t                                           host_len, port_len, size;
    uint32_t                                         hash, base_hash;
    ngx_str_t                                        *server;
    union {
        uint32_t  value;
        u_char    byte[4];
    } prev_hash;

    if (ngx_stream_upstream_init_quic_lb_with_sid(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_stream_upstream_init_quic_lb_peer;

    peers = us->peer.data;
    npoints = peers->total_weight * 160;

    size = sizeof(ngx_stream_upstream_quic_lb_chash_points_t)
           + sizeof(ngx_stream_upstream_quic_lb_chash_point_t) * (npoints - 1);

    points = ngx_palloc(cf->pool, size);
    if (points == NULL) {
        return NGX_ERROR;
    }

    points->number = 0;

    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && ngx_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
        {
            host = server->data + 5;
            host_len = server->len - 5;
            port = NULL;
            port_len = 0;
            goto done;
        }

        for (j = 0; j < server->len; j++) {
            c = server->data[server->len - j - 1];

            if (c == ':') {
                host = server->data;
                host_len = server->len - j - 1;
                port = server->data + server->len - j;
                port_len = j;
                goto done;
            }

            if (c < '0' || c > '9') {
                break;
            }
        }

        host = server->data;
        host_len = server->len;
        port = NULL;
        port_len = 0;

    done:

        ngx_crc32_init(base_hash);
        ngx_crc32_update(&base_hash, host, host_len);
        ngx_crc32_update(&base_hash, (u_char *) "", 1);
        ngx_crc32_update(&base_hash, port, port_len);

        prev_hash.value = 0;
        npoints = peer->weight * 160;

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            ngx_crc32_update(&hash, prev_hash.byte, 4);
            ngx_crc32_final(hash);

            points->point[points->number].hash = hash;
            points->point[points->number].server = server;
            points->number++;

#if (NGX_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    ngx_qsort(points->point,
              points->number,
              sizeof(ngx_stream_upstream_quic_lb_chash_point_t),
              ngx_stream_upstream_quic_lb_chash_cmp_points);

    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    points->number = i + 1;

    qlcf = ngx_stream_conf_upstream_srv_conf(us,
                                             ngx_stream_upstream_quic_lb_module);
    qlcf->points = points;

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_stream_upstream_quic_lb_chash_cmp_points(const void *one, const void *two)
{
    ngx_stream_upstream_quic_lb_chash_point_t *first =
        (ngx_stream_upstream_quic_lb_chash_point_t *) one;
    ngx_stream_upstream_quic_lb_chash_point_t *second =
        (ngx_stream_upstream_quic_lb_chash_point_t *) two;

    if (first->hash < second->hash) {
        return -1;

    } else if (first->hash > second->hash) {
        return 1;

    } else {
        return 0;
    }
}


static ngx_uint_t
ngx_stream_upstream_quic_lb_find_chash_point(ngx_stream_upstream_quic_lb_chash_points_t *points,
    uint32_t hash)
{
    ngx_uint_t                                  i, j, k;
    ngx_stream_upstream_quic_lb_chash_point_t  *point;

    /* find first point >= hash */

    point = &points->point[0];

    i = 0;
    j = points->number;

    while (i < j) {
        k = (i + j) / 2;

        if (hash > point[k].hash) {
            i = k + 1;

        } else if (hash < point[k].hash) {
            j = k;

        } else {
            return k;
        }
    }

    return i;
}


static ngx_int_t
ngx_stream_upstream_init_quic_lb_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us)
{
    ngx_stream_upstream_quic_lb_srv_conf_t   *qlcf;
    ngx_stream_upstream_quic_lb_peer_data_t  *qlp;
    uint32_t                                  hash;

    qlcf = ngx_stream_conf_upstream_srv_conf(us,
                                             ngx_stream_upstream_quic_lb_module);

    qlp = ngx_palloc(s->connection->pool,
                    sizeof(ngx_stream_upstream_quic_lb_peer_data_t));
    if (qlp == NULL) {
        return NGX_ERROR;
    }

    qlp->rrp.pkt = NULL;
    qlp->rrp.quic_lb_conf = NULL;

    s->upstream->peer.data = &qlp->rrp;

    if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_complex_value(s, &qlcf->key, &qlp->key) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Todo: only long header packet need this */
    hash = ngx_crc32_long(qlp->key.data, qlp->key.len);

    ngx_stream_upstream_rr_peers_rlock(qlp->rrp.peers);

    qlp->hash = ngx_stream_upstream_quic_lb_find_chash_point(qlcf->points, hash);

    ngx_stream_upstream_rr_peers_unlock(qlp->rrp.peers);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "QUIC-LB, upstream hash key:\"%V\"", &qlp->key);

    s->upstream->peer.get = ngx_stream_upstream_get_quic_lb_peer;
    s->upstream->peer.free = ngx_stream_upstream_free_quic_lb_peer;

    qlp->conf = qlcf;
    qlp->tries = 0;
    qlp->rehash = 0;
    qlp->get_rr_peer = ngx_stream_upstream_get_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_get_quic_lb_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_rr_peer_data_t *rrp = data;

    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "QUIC-LB, get rr peer, try: %ui", pc->tries);

    pc->connection = NULL;

    peers = rrp->peers;
    ngx_stream_upstream_rr_peers_wlock(peers);

    if (peers->single) {
        peer = peers->peer;

        if (peer->down ||
            (peer->max_conns && peer->conns >= peer->max_conns))
        {
            ngx_stream_upstream_rr_peers_unlock(peers);
            pc->name = peers->name;

            return NGX_BUSY;
        }

        rrp->current = peer;

    } else {
        /* there are several peers */
        peer = ngx_stream_upstream_quic_lb_get_peer_by_sid(pc, rrp);

        /*
         * if sid match failed, try const hash choose peer
         */
        if (peer == NULL) {
            ngx_stream_upstream_rr_peers_unlock(peers);
            return ngx_stream_upstream_quic_lb_get_peer_by_chash(pc, data);
        }
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "QUIC-LB, get quic peer by sid , current: %p %i",
                       peer, peer->current_weight);
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    ngx_stream_upstream_rr_peers_unlock(peers);

    return NGX_OK;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_quic_lb_get_peer_by_plaintext_algo(ngx_peer_connection_t *pc,
    ngx_stream_upstream_rr_peer_data_t *rrp)
{
    ngx_stream_upstream_rr_peer_t  *peer, *best;

    best = NULL;

    for (peer = rrp->peers->peer; peer; peer = peer->next) {
        if (ngx_strncmp(&rrp->pkt->dcid.data[1],
                        peer->sid.data, peer->sid.len) == 0)
        {
            best = peer;
        }
    }

    return best;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_quic_lb_get_peer_by_single_pass(ngx_peer_connection_t *pc,
    ngx_stream_upstream_rr_peer_data_t *rrp)
{
    ngx_stream_upstream_rr_peer_t  *peer, *best;
    ngx_quic_lb_conf_t             *quic_lb_conf;
    u_char                         *enc_key;
    u_char                         *encrypted_cid;
    u_char                          plaintext[NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN] = {0};
    ngx_int_t                       rc;

    best = NULL;
    quic_lb_conf = rrp->quic_lb_conf;

    encrypted_cid = &rrp->pkt->dcid.data[1];
    enc_key = quic_lb_conf->route_ctx.enc_key.data;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pc->log, "QUIC-LB, stream cipher, encrypted-cid: ",
                     encrypted_cid, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN);
#endif

    rc = ngx_quic_aes_128_ecb_decrypt(encrypted_cid, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN,
                                      enc_key, plaintext);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "QUIC-LB, decrypt dcid error");
        return NULL;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pc->log, "QUIC-LB, stream cipher, plaintext cid: ",
                     plaintext, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN);
#endif

    for (peer = rrp->peers->peer; peer; peer = peer->next) {
        if (ngx_strncmp(plaintext, peer->sid.data, peer->sid.len) == 0) {
            best = peer;
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "QUIC-LB, stream cipher, no sid match");
    }

    return best;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_quic_lb_get_peer_by_four_pass(ngx_peer_connection_t *pc,
    ngx_stream_upstream_rr_peer_data_t *rrp)
{
    ngx_stream_upstream_rr_peer_t  *peer, *best;
    ngx_quic_lb_conf_t             *quic_lb_conf;
    u_char                         *enc_key;
    u_char                          plaintext[NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN] = {0};
    ngx_int_t                       rc, i;
    u_char                         *left_1, *right_1, *left_0, *right_0, expand_arg;
    u_char                          left_2[NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN] = {0};
    u_char                          right_2[NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN] = {0};
    ngx_int_t                       half_len, half_bits;
    u_char                          expand_text[NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN] = {0};
    u_char                          cipher_text[NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN] = {0};
    u_char                          truncate_text[NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN] = {0};

    best = NULL;
    quic_lb_conf = rrp->quic_lb_conf;
    enc_key = quic_lb_conf->route_ctx.enc_key.data;

    if ((rrp->pkt->dcid.len - 1) % 2 == 0) {
        half_len = (rrp->pkt->dcid.len - 1) / 2;
        half_bits = half_len * 8;
        ngx_memcpy(left_2, &rrp->pkt->dcid.data[1], half_len);
        ngx_memcpy(right_2, &rrp->pkt->dcid.data[1 + half_len], half_len);
    } else {
        half_len = (rrp->pkt->dcid.len - 1 - 1) / 2 + 1;
        half_bits = (half_len - 1) * 8 + 4;
        ngx_memcpy(left_2, &rrp->pkt->dcid.data[1], half_len);
        ngx_memcpy(right_2, &rrp->pkt->dcid.data[1 + half_len - 1], half_len);
        left_2[half_len - 1] &= 0xf0;
        right_2[0] &= 0x0f; 
    }
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pc->log, "QUIC-LB, stream cipher, dcid: ",
                     rrp->pkt->dcid.data, rrp->pkt->dcid.len);
    ngx_quic_hexdump(pc->log, "QUIC-LB, stream cipher, left_2: ",
                     left_2, NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN);
    ngx_quic_hexdump(pc->log, "QUIC-LB, stream cipher, right_2: ",
                     right_2, NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN);
#endif
    /* left_1 = left_2 ^ truncate_left(AES_ECB(key, expand_right(right_2), 0x04)) */
    expand_arg = 0x04;
    rc = expand_right(expand_text, right_2, half_bits, &expand_arg, 8);
    if (rc != NGX_OK) {
        return NULL;
    }

    rc = ngx_quic_aes_128_ecb_encrypt(expand_text, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN,
                                      enc_key, cipher_text);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "QUIC-LB, encrypt right_2 error");
        return NULL;
    }

    rc = truncate_left(truncate_text, NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN, cipher_text, 
                       NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN, half_bits);
    if (rc != NGX_OK) {
        return NULL;
    }

    for (i = 0; i < half_len; i++) {
        left_2[i] = left_2[i] ^ truncate_text[i];
    }
    left_1 = left_2;

    /* right_1 = right_2 ^ truncate_right(AES_ECB(key, expand_left(left_1, 0x03)) */
    expand_arg = 0x03;
    rc = expand_left(expand_text, left_1, half_bits, &expand_arg, 8);
    if (rc != NGX_OK) {
        return NULL;
    }

    rc = ngx_quic_aes_128_ecb_encrypt(expand_text, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN,
                                      enc_key, cipher_text);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "QUIC-LB, encrypt left_1 error");
        return NULL;
    }

    rc = truncate_right(truncate_text, NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN, cipher_text, 
                        NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN, half_bits);
    if (rc != NGX_OK) {
        return NULL;
    }

    for (i = 0; i < half_len; i++) {
        right_2[i] = right_2[i] ^ truncate_text[i];
    }
    right_1 = right_2;

    /* left_0 = left_1 ^ truncate_left(AES_ECB(key, expand_right(right_1), 0x02)) */
    expand_arg = 0x02;
    rc = expand_right(expand_text, right_1, half_bits, &expand_arg, 8);
    if (rc != NGX_OK) {
        return NULL;
    }

    rc = ngx_quic_aes_128_ecb_encrypt(expand_text, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN,
                                      enc_key, cipher_text);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "QUIC-LB, encrypt right_1 error");
        return NULL;
    }

    rc = truncate_left(truncate_text, NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN, cipher_text, 
                       NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN, half_bits);
    if (rc != NGX_OK) {
        return NULL;
    }

    for (i = 0; i < half_len; i++) {
        left_1[i] = left_1[i] ^ truncate_text[i];
    }

    left_0 = left_1;
    ngx_memcpy(plaintext, left_0,  half_len);
    if (quic_lb_conf->route_ctx.sid_len < half_len || 
        ((rrp->pkt->dcid.len - 1) % 2 == 0 && quic_lb_conf->route_ctx.sid_len < half_len)) {
        goto done;
    }

    /* right_0 = right_1 ^ truncate_right(AES_ECB(key, expand_left(left_0, 0x01))) */
    expand_arg = 0x01;
    rc = expand_left(expand_text, left_0, half_bits, &expand_arg, 8);
    if (rc != NGX_OK) {
        return NULL;
    }

    rc = ngx_quic_aes_128_ecb_encrypt(expand_text, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN,
                                      enc_key, cipher_text);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "QUIC-LB, encrypt left_0 error");
        return NULL;
    }

    rc = truncate_right(truncate_text, NGX_QUIC_LB_STREAM_CIPHER_ENC_BUF_LEN, cipher_text, 
                        NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN, half_bits);
    if (rc != NGX_OK) {
        return NULL;
    }

    for (i = 0; i < half_len; i++) {
        right_1[i] = right_1[i] ^ truncate_text[i];
    }
    right_0 = right_1;

    if ((rrp->pkt->dcid.len - 1) % 2 != 0) {
        plaintext[half_len - 1] |= right_0[0] & 0x0f;
        ngx_memcpy(plaintext + half_len, &right_0[1],  half_len - 1);
    } else {
        ngx_memcpy(plaintext + half_len, right_0,  half_len);
    }

done:
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pc->log, "QUIC-LB, stream cipher, encrypted-padded-nonce: ",
                     plaintext, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN);
#endif
    for (peer = rrp->peers->peer; peer; peer = peer->next) {
        if (ngx_strncmp(plaintext, peer->sid.data, peer->sid.len) == 0) {
            best = peer;
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "QUIC-LB, stream cipher, no sid match");
    }

    return best;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_quic_lb_get_peer_by_stream_cipher_algo(ngx_peer_connection_t *pc,
    ngx_stream_upstream_rr_peer_data_t *rrp)
{
    if (rrp->pkt->dcid.len == 17) {
        return ngx_stream_upstream_quic_lb_get_peer_by_single_pass(pc, rrp);
    }

    return ngx_stream_upstream_quic_lb_get_peer_by_four_pass(pc, rrp);
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_quic_lb_get_peer_by_sid(ngx_peer_connection_t *pc,
    ngx_stream_upstream_rr_peer_data_t *rrp)
{
    ngx_stream_upstream_rr_peer_t  *best;
    ngx_quic_lb_conf_t             *quic_lb_conf;

    best = NULL;

    /* for configuration bit '11', we would not use sid route */
    if (rrp->pkt->conf_id == NGX_QUIC_LB_CONF_ID_MAX) {
        return best;
    }

    quic_lb_conf = rrp->quic_lb_conf;

    switch (quic_lb_conf->quic_lb_route_mode)
    {
    case NGX_QUIC_LB_PLAINTEXT:
        return ngx_stream_upstream_quic_lb_get_peer_by_plaintext_algo(pc, rrp);
    case NGX_QUIC_LB_STREAM_CIPHER:
        return ngx_stream_upstream_quic_lb_get_peer_by_stream_cipher_algo(pc, rrp);
    default:
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "QUIC-LB, no route mode match");
        break;
    }

    return best;
}

static ngx_int_t
ngx_stream_upstream_quic_lb_get_peer_by_chash(ngx_peer_connection_t *pc, void *data)
{
    ngx_stream_upstream_quic_lb_peer_data_t      *qlp = data;
    ngx_stream_upstream_quic_lb_srv_conf_t       *qlcf;
    time_t                                        now;
    intptr_t                                      m;
    ngx_str_t                                    *server;
    ngx_int_t                                     total;
    ngx_uint_t                                    i, n, best_i;
    ngx_stream_upstream_rr_peer_t                *peer, *best;
    ngx_stream_upstream_quic_lb_chash_point_t    *point;
    ngx_stream_upstream_quic_lb_chash_points_t   *points;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                   "QUIC-LB, get consistent hash peer, try: %ui", pc->tries);

    ngx_stream_upstream_rr_peers_wlock(qlp->rrp.peers);

    if (qlp->tries > 20 || qlp->rrp.peers->single || qlp->key.len == 0) {
        ngx_stream_upstream_rr_peers_unlock(qlp->rrp.peers);
        return qlp->get_rr_peer(pc, &qlp->rrp);
    }

    pc->connection = NULL;

    now = ngx_time();
    qlcf = qlp->conf;

    points = qlcf->points;
    point = &points->point[0];

    for ( ;; ) {
        server = point[qlp->hash % points->number].server;

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
                       "QUIC-LB, consistent hash peer:%uD, server:\"%V\"",
                       qlp->hash, server);

        best = NULL;
        best_i = 0;
        total = 0;

        for (peer = qlp->rrp.peers->peer, i = 0;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (qlp->rrp.tried[n] & m) {
                continue;
            }

            if (peer->down) {
                continue;
            }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
                continue;
            }

            if (peer->server.len != server->len
                || ngx_strncmp(peer->server.data, server->data, server->len)
                   != 0)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (best == NULL || peer->current_weight > best->current_weight) {
                best = peer;
                best_i = i;
            }
        }

        if (best) {
            best->current_weight -= total;
            break;
        }

        qlp->hash++;
        qlp->tries++;

        if (qlp->tries > 20) {
            ngx_stream_upstream_rr_peers_unlock(qlp->rrp.peers);
            return qlp->get_rr_peer(pc, &qlp->rrp);
        }
    }

    qlp->rrp.current = best;

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    ngx_stream_upstream_rr_peers_unlock(qlp->rrp.peers);

    n = best_i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));

    qlp->rrp.tried[n] |= m;

    return NGX_OK;
}


static void *
ngx_stream_upstream_quic_lb_create_conf(ngx_conf_t *cf)
{
    ngx_stream_upstream_quic_lb_srv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_stream_upstream_quic_lb_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->points = NULL;

    return conf;
}


static char *
ngx_stream_upstream_quic_lb_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_upstream_quic_lb_srv_conf_t *prev = parent;
    ngx_stream_upstream_quic_lb_srv_conf_t *conf = child;
    ngx_int_t                               i;

    for (i = 0; i < NGX_QUIC_LB_VALID_CONF_NUM; i++) {
        ngx_conf_merge_str_value(conf->quic_conf_file[i], prev->quic_conf_file[i], "");
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_upstream_quic_lb_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_upstream_quic_lb_srv_conf_t   *qlcf = conf;

    ngx_stream_upstream_srv_conf_t           *uscf;
    ngx_stream_compile_complex_value_t        ccv;
    ngx_str_t                                 value;

    uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    /* we only support ip:port chash now */
    value.data = (u_char *)"$remote_addr:$remote_port";
    value.len = ngx_strlen(value.data);

    ccv.cf = cf;
    ccv.value = &value;
    ccv.complex_value = &qlcf->key;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "QUIC-LB, load balancing method redefined");
    }

    uscf->flags = NGX_STREAM_UPSTREAM_CREATE
                  |NGX_STREAM_UPSTREAM_WEIGHT
                  |NGX_STREAM_UPSTREAM_MAX_CONNS
                  |NGX_STREAM_UPSTREAM_MAX_FAILS
                  |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NGX_STREAM_UPSTREAM_DOWN;

    uscf->peer.init_upstream = ngx_stream_upstream_init_quic_lb;

    return NGX_CONF_OK;
}


static void
ngx_stream_upstream_free_quic_lb_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
   /* Todo: match quic lb algorithm */
}
