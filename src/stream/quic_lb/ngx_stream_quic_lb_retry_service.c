
/*
 * Copyright 2020. All Rights Reserved.
 * Author: Lingtao Kong
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_string.h>
#include <time.h>
#include <openssl/aes.h>


static ngx_int_t ngx_stream_quic_lb_create_retry_packet(ngx_quic_header_t *pkt, ngx_str_t *res);
static ngx_int_t ngx_stream_quic_lb_tls_seal(const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad, ngx_log_t *log);
static ngx_int_t ngx_stream_quic_lb_tls_open(const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in, ngx_str_t *ad,
    ngx_log_t *log);

static ngx_int_t ngx_stream_quic_lb_retry_ciphers(ngx_ssl_conn_t *ssl_conn,
    ngx_quic_ciphers_t *ciphers);
static size_t ngx_stream_quic_lb_create_retry_itag(ngx_quic_header_t *pkt,
   u_char *out, u_char **start);
static ngx_int_t ngx_stream_quic_lb_process_retry_service_in_shared_state(
    ngx_quic_lb_conf_t *conf, ngx_connection_t *c, ngx_quic_header_t *pkt);
static ngx_int_t ngx_stream_quic_lb_gen_and_send_retry_packet(ngx_connection_t *c,
    ngx_quic_lb_conf_t *qconf, ngx_str_t *cids);
static ngx_int_t ngx_stream_quic_lb_gen_new_cid(ngx_str_t *new_dcid, ngx_connection_t *c);

static ngx_int_t ngx_stream_quic_lb_new_share_state_retry_token(ngx_connection_t *c,
    ngx_str_t *token, ngx_quic_lb_conf_t *qconf, ngx_str_t *cids);
static ngx_int_t ngx_stream_quic_lb_gen_share_state_plain_token_body(ngx_connection_t *c,
    retry_token_enc_info_t *enc_info, ngx_str_t *cids, u_char *buf, ngx_int_t buf_len,
    size_t *out_len);
static ngx_int_t ngx_stream_quic_lb_parse_quic_lb_model_plain_token_body(ngx_connection_t *c,
    u_char *buf, ngx_int_t buf_len, ngx_quic_lb_retry_token_body_t *token_body);
static ngx_int_t ngx_stream_quic_lb_validate_share_state_token(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_lb_conf_t *qconf);
static ngx_int_t ngx_stream_quic_lb_write_ip_address(ngx_connection_t *c, u_char *buf,
    ngx_int_t buf_len, size_t *out_len);
static ngx_int_t ngx_stream_quic_lb_write_port(ngx_connection_t *c, u_char *buf,
    ngx_int_t buf_len, size_t *out_len);
static uint64_t ngx_stream_quic_lb_get_timestamp(uint64_t token_alive_time);
static ngx_int_t ngx_stream_quic_lb_validate_timestamp(uint64_t expire_time);
static ngx_int_t ngx_stream_quic_lb_get_key_index(ngx_quic_lb_conf_t *qconf, uint8_t key_seq);
static ngx_int_t ngx_stream_quic_lb_generate_key_index(ngx_quic_lb_conf_t *qconf);

static size_t
ngx_stream_quic_lb_create_retry_itag(ngx_quic_header_t *pkt, u_char *out,
    u_char **start)
{
    u_char  *p;
    p = out;
    *p++ = pkt->odcid.len;
    p = ngx_cpymem(p, pkt->odcid.data, pkt->odcid.len);

    *start = p;

    *p++ = 0xff;

    p = ngx_quic_write_uint32(p, NGX_QUIC_VERSION);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    p = ngx_cpymem(p, pkt->token.data, pkt->token.len);

    return p - out;
}


/*
 * NGX_OK: validate success;
 * NGX_ERROR: validate failed or token not found.
 */
static ngx_int_t
ngx_stream_quic_lb_process_retry_service_in_shared_state(ngx_quic_lb_conf_t *conf,
    ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t  rc;

    /* If in inactive mode, pass through directly */
    if (conf->retry_service.retry_mode == NGX_QUIC_LB_RETRY_INACTIVE_MODE) {
        ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                      "QUIC-LB, retry service, work in inactive mode");
        return NGX_OK;
    }

    if (pkt->token.len == 0) {
        ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                      "QUIC-LB, retry service, token not found");
        return NGX_ERROR;
    }

    rc = ngx_stream_quic_lb_validate_share_state_token(c, pkt, conf);
    ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                  "QUIC-LB, retry service, validate token:%s, rc:%d",
                  rc == NGX_OK ? "suc":"failed", rc);
    return rc;
}


static ngx_int_t
ngx_stream_quic_lb_gen_and_send_retry_packet(ngx_connection_t *c,
    ngx_quic_lb_conf_t *qconf, ngx_str_t *cids)
{
    ssize_t            len;
    ngx_str_t          res, token;
    ngx_quic_header_t  pkt;
    u_char             buf[NGX_QUIC_RETRY_BUFFER_SIZE];

    ngx_memzero(buf, NGX_QUIC_RETRY_BUFFER_SIZE);

    if (ngx_stream_quic_lb_new_share_state_retry_token(c, &token,
                                                       qconf, cids) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
    pkt.flags = NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_RETRY;
    pkt.log = c->log;

    /* origin dcid */
    pkt.odcid = cids[0];
    /* scid */
    pkt.dcid = cids[1];
    /* new dcid */
    pkt.scid = cids[2];

    pkt.token = token;

    res.data = buf;

    if (ngx_stream_quic_lb_create_retry_packet(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(c->log, "quic packet to send", res.data, res.len);
#endif

    len = c->send(c, res.data, res.len);
    if (len == NGX_ERROR || (size_t) len != res.len) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_validate_share_state_token(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_lb_conf_t *qconf)
{
    size_t                          len;
    ngx_int_t                       res, i;
    const EVP_CIPHER               *cipher;
    ngx_quic_secret_t               s;
    ngx_str_t                       token_body_plaintext;
    ngx_str_t                       token_body_enc;
    ngx_str_t                       aad;
    ngx_str_t                       plaintext_buf;
    uint8_t                         key_seq;
    ngx_int_t                       key_index;
    ngx_str_t                       unique_token_num;
    u_char                         *pp, *cp; /* pp for plaintext_buf, cp for recv token */
    ngx_quic_lb_retry_token_body_t  token_body;

    if (pkt->token.len > NGX_STREAM_QUIC_LB_MAX_RETRY_TOKEN_SIZE
        || pkt->token.len < NGX_QUIC_RETRY_MIN_TOKEN_LEN)
    {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, length illegal");
    }
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, token:",
                     pkt->token.data, pkt->token.len);
#endif
    unique_token_num.data = pkt->token.data;
    unique_token_num.len = NGX_QUIC_RETRY_IV_LEN;
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, unique_token_num:",
                     unique_token_num.data, unique_token_num.len);
#endif
    plaintext_buf.len = NGX_QUIC_RETRY_IP_ADDR_LEN + NGX_QUIC_RETRY_MAX_TOKEN_LEN;
    plaintext_buf.data = ngx_palloc(c->pool, plaintext_buf.len);
    if (plaintext_buf.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, ngx_palloc error");
        return NGX_ERROR;
    }
    ngx_memzero(plaintext_buf.data, plaintext_buf.len);

    pp = plaintext_buf.data;
    aad.data = pp;

    res = ngx_stream_quic_lb_write_ip_address(c, pp, NGX_QUIC_RETRY_IP_ADDR_LEN, &len);
    if (res != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, write ip address error");
        return NGX_ERROR;
    }
    pp += len;

    /* extract ctx for decrypt token body */
    cp = pkt->token.data;
    pp = ngx_cpymem(pp, cp, NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN);
    cp += NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN;

    key_seq = *cp;
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, key_seq:",
                     &key_seq, NGX_QUIC_RETRY_KEY_SEQ_LEN);
#endif
    pp = ngx_cpymem(pp, cp, NGX_QUIC_RETRY_KEY_SEQ_LEN);
    cp += NGX_QUIC_RETRY_KEY_SEQ_LEN;

    key_index = ngx_stream_quic_lb_get_key_index(qconf, key_seq);
    if (key_index == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, key_seq illegal");
        return NGX_ERROR;
    } else if (key_index == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, can not find matched key_seq");
        return NGX_ERROR;
    }
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, "
                     "key_index:", &key_index, sizeof(ngx_int_t));
#endif

    aad.len = pp - plaintext_buf.data;

    token_body_enc.data = cp;
    token_body_enc.len = pkt->token.len - (cp - pkt->token.data);
    if (token_body_enc.len <= 0) {
        /* should never happen */
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, internal error");
        return NGX_ERROR;
    }

    /* decrypt token */
    cipher = EVP_aes_128_gcm();
    s.key.len = NGX_QUIC_RETRY_KEY_LEN;
    s.key.data = qconf->retry_service.retry_token_enc_infos[key_index].retry_token_key;
    s.iv.len = NGX_QUIC_RETRY_IV_LEN;
    s.iv.data = ngx_palloc(c->pool, s.iv.len);
    if (s.iv.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, ngx_palloc error");
        return NGX_ERROR;
    }
    ngx_memcpy(s.iv.data, qconf->retry_service.retry_token_enc_infos[key_index].retry_token_iv_material, s.iv.len);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, "
                     "retry_token_iv_material:", s.iv.data,
                     NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN);
#endif
    for (i = 0; i < NGX_QUIC_RETRY_IV_LEN; i++) {
        s.iv.data[i] = s.iv.data[i] ^ unique_token_num.data[i];
    }
    token_body_plaintext.data = pp;
    token_body_plaintext.len = token_body_enc.len;
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, aad:",
                     aad.data, aad.len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, iv:",
                     s.iv.data, s.iv.len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, key:",
                     s.key.data, s.key.len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, body enc:",
                     token_body_enc.data, token_body_enc.len - NGX_QUIC_RETRY_ICV_LEN);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, aead icv:",
                     token_body_enc.data + token_body_enc.len - NGX_QUIC_RETRY_ICV_LEN, NGX_QUIC_RETRY_ICV_LEN);
#endif
    res = ngx_stream_quic_lb_tls_open(cipher, &s, &token_body_plaintext, s.iv.data,
                                      &token_body_enc, &aad, c->pool->log);
    if (res != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, decrypt failed");
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token validate, body plaintext:",
                     token_body_plaintext.data, token_body_plaintext.len);
#endif
    /* you can implement your self define token validation here */
    res = ngx_stream_quic_lb_parse_quic_lb_model_plain_token_body(c, token_body_plaintext.data,
                                                                  token_body_plaintext.len, &token_body);
    if (res != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, parse token body failed");
        return NGX_ERROR;
    }

    res = ngx_stream_quic_lb_validate_timestamp(token_body.expire_time);
    if (res != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, token expired");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static uint64_t
ngx_stream_quic_lb_get_timestamp(uint64_t token_alive_time)
{
    time_t      now;
    uint64_t    expire_time;

    now = time(NULL);
    if (now < 0) {
        return NGX_ERROR;
    }

    expire_time = now;
    expire_time += token_alive_time;

    return expire_time;
}


static ngx_int_t
ngx_stream_quic_lb_validate_timestamp(uint64_t expire_time)
{
    time_t      now;

    now = time(NULL);
    if (now < 0) {
        return NGX_ERROR;
    }

    if (now > 0 && (uint64_t)now > expire_time - NGX_QUIC_RETRY_TIMESTAMP_SKEW) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/* Defined in: https://tools.ietf.org/html/draft-ietf-quic-load-balancers-06#section-7.3
 * Plaintext Token Body format:
 * +++++++++++++++++++++++++++++++
 * | ODCIL(8 bit) | RSCIL (8bit) |
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * | Port(16bit, optional, appears when ODCIL greater than 0)|
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * | Orig dest Connection ID (0..160) |
 * +++++++++++++++++++++++++++++++++++++++
 * | Retry Source Connection ID (0..160) |
 * +++++++++++++++++++++++++++++++++++++++
 * | Timestamp(64bit) | Opaque Data (..)|
 * ++++++++++++++++++++++++++++++++++++++
 */
static ngx_int_t
ngx_stream_quic_lb_gen_share_state_plain_token_body(ngx_connection_t *c,
    retry_token_enc_info_t *enc_info, ngx_str_t *cids, u_char *buf,
    ngx_int_t buf_len, size_t *out_len)
{
    ngx_int_t                           token_body_len = 0;
    size_t                              len;
    ngx_quic_lb_retry_token_body_t      token_body;
    ngx_str_t                           odcid, rscid;

    odcid = cids[0];
    rscid = cids[2];

    token_body.odcid_len = odcid.len;
    token_body.rscid_len = rscid.len;

    if (odcid.len > NGX_QUIC_RETRY_CID_LEN_MAX
        || rscid.len > NGX_QUIC_RETRY_CID_LEN_MAX)
    {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen plaintext token body error, odcid or rscid length illegal, "
                      "odcid.len: %d, rscid.len: %d");
        return NGX_ERROR;
    }

    ngx_memcpy(token_body.odcid, odcid.data, odcid.len);
    ngx_memcpy(token_body.rscid, rscid.data, rscid.len);

    /* port field only exist when odcid length greater than 0 */
    if (odcid.len > 0) {
        ngx_stream_quic_lb_write_port(c, (u_char *)&token_body.port, sizeof(token_body.port), &len);
        token_body_len += len;
    }

    /*
     * Opaque Data is a self define place, is NULL for quic-lb generate retry token
     * only in quic-server will there be data
     */
    token_body_len = token_body_len + 1 + 1; /* ODCIL and RSCIL */
    token_body_len = token_body_len + odcid.len + rscid.len;
    token_body_len = token_body_len + NGX_QUIC_RETRY_TIMESTAP_LEN; /* timestamp */

    if (buf_len < token_body_len) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen plaintext token body error, buf_len smaller than require");
        return NGX_ERROR;
    }

    token_body.expire_time = ngx_stream_quic_lb_get_timestamp(enc_info->retry_token_alive_time);
    if (token_body.expire_time <= 0) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen timestamp error");
        return NGX_ERROR;
    }

    buf = ngx_quic_write_uint8(buf, token_body.odcid_len);
    buf = ngx_quic_write_uint8(buf, token_body.rscid_len);
    if (token_body.odcid_len > 0) {
        buf = ngx_quic_write_uint16(buf, token_body.port);
    }
    buf = ngx_cpymem(buf, token_body.odcid, token_body.odcid_len);
    buf = ngx_cpymem(buf, token_body.rscid, token_body.rscid_len);
    buf = ngx_quic_write_uint64(buf, token_body.expire_time);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body generate, odcid_len:",
                     &token_body.odcid_len, sizeof(token_body.odcid_len));
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body generate, rscid_len:",
                     &token_body.rscid_len, sizeof(token_body.rscid_len));
    if (token_body.odcid_len > 0) {
        ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body generate, port:",
                         &token_body.port, sizeof(token_body.port));
    }
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body generate, odcid:",
                     token_body.odcid, token_body.odcid_len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body generate, rscid:",
                     token_body.rscid, token_body.rscid_len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body generate, expire_time:",
                     &token_body.expire_time, sizeof(token_body.expire_time));
#endif

    *out_len = token_body_len;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_parse_quic_lb_model_plain_token_body(ngx_connection_t *c, u_char *buf,
    ngx_int_t buf_len, ngx_quic_lb_retry_token_body_t *token_body)
{
    u_char   *p = buf;


    if (buf_len <= 1 + 1 + NGX_QUIC_RETRY_TIMESTAP_LEN) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, parse token body failed, "
                      "buf_len:%d too small", buf_len);
        return NGX_ERROR;
    }

    token_body->odcid_len = (uint8_t)p[0];
    p++;
    buf_len--;

    token_body->rscid_len = (uint8_t)p[0];
    p++;
    buf_len--;

    ngx_memcpy(token_body->odcid, p ,token_body->odcid_len);
    buf_len -= token_body->odcid_len;
    p += token_body->odcid_len;
    if (buf_len < NGX_QUIC_RETRY_TIMESTAP_LEN) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, parse token body odcid failed, "
                      "buf_len:%d, odcid_len:%d, ", buf_len, token_body->odcid_len);
        return NGX_ERROR;
    }

    ngx_memcpy(token_body->rscid, p ,token_body->rscid_len);
    buf_len -= token_body->rscid_len;
    p += token_body->rscid_len;
    if (buf_len < NGX_QUIC_RETRY_TIMESTAP_LEN) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, token validate failed, parse token body rscid failed, "
                      "buf_len:%d, rscid_len:%d, ", buf_len, token_body->rscid_len);
        return NGX_ERROR;
    }

    token_body->expire_time = ngx_quic_parse_uint64(buf);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body validate, odcid_len:",
                     &token_body->odcid_len, sizeof(token_body->odcid_len));
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body validate, rscid_len:",
                     &token_body->rscid_len, sizeof(token_body->rscid_len));
    if (token_body->odcid_len > 0) {
        ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body validate, port:",
                         &token_body->port, sizeof(token_body->port));
    }
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body validate, odcid:",
                     token_body->odcid, token_body->odcid_len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body validate, rscid:",
                     token_body->rscid, token_body->rscid_len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token body validate, expire_time:",
                     &token_body->expire_time, sizeof(token_body->expire_time));
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_write_ip_address(ngx_connection_t *c, u_char *buf,
    ngx_int_t buf_len, size_t *out_len)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (buf_len < NGX_QUIC_RETRY_IP_ADDR_LEN) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, buf len too small");
        return NGX_ERROR;
    }

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        buf = ngx_cpymem(buf, sin6->sin6_addr.s6_addr, NGX_QUIC_RETRY_IP_ADDR_LEN);
        break;
#endif

    case AF_INET:
        sin = (struct sockaddr_in *) c->sockaddr;
        buf = ngx_quic_write_uint32(buf, sin->sin_addr.s_addr);
        break;

    default: /* AF_INET */
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, only support ipv4/v6");
        return NGX_ERROR;
    }

    *out_len = NGX_QUIC_RETRY_IP_ADDR_LEN;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_write_port(ngx_connection_t *c, u_char *buf,
    ngx_int_t buf_len, size_t *out_len)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    ngx_int_t             len = sizeof(uint16_t);

    if (buf_len < len) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, buf len too small");
        return NGX_ERROR;
    }

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        buf = ngx_quic_write_uint16(buf, sin6->sin6_port);
        break;
#endif

    case AF_INET:
        sin = (struct sockaddr_in *) c->sockaddr;
        buf = ngx_quic_write_uint16(buf, sin->sin_port);
        break;

    default: /* AF_INET */
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, only support ipv4/v6");
        return NGX_ERROR;
    }

    *out_len = len;

    return NGX_OK;
}

/* now we just random choose a vaild key_seq, and use it for key_seq */
static ngx_int_t
ngx_stream_quic_lb_generate_key_index(ngx_quic_lb_conf_t *qconf)
{
    uint8_t  key_index;

    if (qconf->retry_service.retry_key_num <= 0
        || qconf->retry_service.retry_key_num > NGX_QUIC_RETRY_MAX_KEY_NUM)
    {
        return NGX_ERROR;
    }

    key_index = ngx_random() % qconf->retry_service.retry_key_num;

    return key_index;
}


static ngx_int_t
ngx_stream_quic_lb_get_key_index(ngx_quic_lb_conf_t *qconf, uint8_t key_seq)
{
    ngx_int_t   i;

    if (key_seq > NGX_QUIC_RETRY_MAX_KEY_NUM) {
        return NGX_ERROR;
    }

    if (qconf->retry_service.retry_key_num <= 0
        || qconf->retry_service.retry_key_num > NGX_QUIC_RETRY_MAX_KEY_NUM)
    {
        /* should never happen */
        return NGX_ERROR;
    }

    for (i = 0; i < qconf->retry_service.retry_key_num; i++) {
        if (qconf->retry_service.retry_token_enc_infos[i].retry_key_seq == key_seq) {
            return i;
        }
    }

    return NGX_DECLINED;
}


/*
 * Defined in: https://tools.ietf.org/html/draft-ietf-quic-load-balancers-06#section-7.3
 * Encryption: AES-128-gcm
 * Token format:
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++
 * | Unique Token Number(96 bit) | Key Sequence (8bit) |
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++
 * | Token Body(...)| AEAD ICV(128bit) |
 * +++++++++++++++++++++++++++++++++++++
 * IV format: "Unique Token Number(96 bit)" xor "IV material(96 bit, get by key-seq and conf)"
 * Key format: 128 bit, get by key-seq and conf
 */
static ngx_int_t
ngx_stream_quic_lb_new_share_state_retry_token(ngx_connection_t *c, ngx_str_t *token,
    ngx_quic_lb_conf_t *qconf, ngx_str_t *cids)
{
    uint8_t               key_seq;
    ngx_int_t             key_index;
    ngx_str_t             plaintext_buf;
    u_char               *p;
    ngx_str_t             token_body_plaintext, token_body_enc, aad;
    const EVP_CIPHER     *cipher;
    ngx_quic_secret_t     s;
    ngx_int_t             i, res;
    size_t                len;

    /*
     * plaintext_buf format:
     * +++++++++++++++++++++++++++++++++++++
     * | IP address(128 bit) | Token (...) |
     * +++++++++++++++++++++++++++++++++++++
     */
    plaintext_buf.len = NGX_QUIC_RETRY_IP_ADDR_LEN + NGX_QUIC_RETRY_MAX_TOKEN_LEN;
    plaintext_buf.data = ngx_palloc(c->pool, plaintext_buf.len);
    if (plaintext_buf.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, ngx_palloc error");
        return NGX_ERROR;
    }
    ngx_memzero(plaintext_buf.data, plaintext_buf.len);
    p = plaintext_buf.data;
    /*
    * Defined in: https://tools.ietf.org/html/draft-ietf-quic-load-balancers-06#section-7.3
    * AAD format:
    * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    * | IP Address(128 bit) | Unique Token Number(96 bit) | Key Sequence (8bit) |
    * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    */
    aad.data = p;

    res = ngx_stream_quic_lb_write_ip_address(c, p, NGX_QUIC_RETRY_IP_ADDR_LEN, &len);
    if (res != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, write ip address error");
        return NGX_ERROR;
    }
    p += len;

    /* generate uniq_token_number */
    if (RAND_bytes(p, NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN) <= 0) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, rand error");
        return NGX_ERROR;
    }
    p += NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN;

    key_index = ngx_stream_quic_lb_generate_key_index(qconf);
    if (key_index < 0) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, gen key_index error");
        return NGX_ERROR;
    }
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, key_index:", 
                     &key_index, sizeof(ngx_int_t));
#endif

    key_seq = qconf->retry_service.retry_token_enc_infos[key_index].retry_key_seq;
    p = ngx_quic_write_uint8(p, key_seq);
    aad.len = p - aad.data;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, aad:",
                     aad.data, aad.len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, key_seq:",
                     &key_seq, NGX_QUIC_RETRY_KEY_SEQ_LEN);
#endif

    res = ngx_stream_quic_lb_gen_share_state_plain_token_body(c,
              &qconf->retry_service.retry_token_enc_infos[key_index], cids, p,
              NGX_QUIC_RETRY_MAX_TOKEN_BODY_LEN, &token_body_plaintext.len);
    if (res != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, gen plaintext token error");
        return NGX_ERROR;
    }
    token_body_plaintext.data = p;
    p += token_body_plaintext.len;

    /* now we generate real token */
    token->len = p - plaintext_buf.data + NGX_QUIC_RETRY_ICV_LEN - NGX_QUIC_RETRY_IP_ADDR_LEN;
    token->data = ngx_palloc(c->pool, token->len);
    if (token->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, ngx_palloc error");
        return NGX_ERROR;
    }
    ngx_memzero(token->data, token->len);

    p = token->data;
    p = ngx_cpymem(p, plaintext_buf.data + NGX_QUIC_RETRY_IP_ADDR_LEN,
                   NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN + NGX_QUIC_RETRY_KEY_SEQ_LEN);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, unique_token_num:",
                     token->data, NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN);
#endif
    /* encrypy token body */
    token_body_enc.data = p;
    token_body_enc.len = token_body_plaintext.len;
    cipher = EVP_aes_128_gcm();
    s.key.len = NGX_QUIC_RETRY_KEY_LEN;
    s.key.data = qconf->retry_service.retry_token_enc_infos[key_index].retry_token_key;
    s.iv.len = NGX_QUIC_RETRY_IV_LEN;
    s.iv.data = ngx_palloc(c->pool, s.iv.len);
    if (s.iv.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, ngx_palloc error");
        return NGX_ERROR;
    }
    ngx_memcpy(s.iv.data,
               qconf->retry_service.retry_token_enc_infos[key_index].retry_token_iv_material,
               s.iv.len);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, "
                     "retry_token_iv_material:", s.iv.data,
                     NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN);
#endif
    for (i = 0; i < NGX_QUIC_RETRY_UNIQ_TOKEN_NUMBER_LEN; i++) {
        s.iv.data[i] = s.iv.data[i] ^ token->data[i];
    }
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, iv:",
                     s.iv.data, s.iv.len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, key:",
                     s.key.data, s.key.len);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, body plaintext:",
                     token_body_plaintext.data, token_body_plaintext.len);
#endif

    res = ngx_stream_quic_lb_tls_seal(cipher, &s, &token_body_enc, s.iv.data,
                                      &token_body_plaintext, &aad, c->pool->log);
    if (res != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0,
                      "QUIC-LB, gen retry token error, encrypt token body error");
        return NGX_ERROR;
    }
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, body enc:",
                     token_body_enc.data, token_body_enc.len - NGX_QUIC_RETRY_ICV_LEN);
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, aead icv:",
                     token_body_enc.data + token_body_enc.len - NGX_QUIC_RETRY_ICV_LEN, NGX_QUIC_RETRY_ICV_LEN);
#endif
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->pool->log, "QUIC-LB, quic retry token generate, token:",
                     token->data, token->len);
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_create_retry_packet(ngx_quic_header_t *pkt, ngx_str_t *res)
{
    u_char              *start;
    ngx_str_t            ad, itag;
    ngx_quic_secret_t    secret;
    ngx_quic_ciphers_t   ciphers;

    /* 5.8.  Retry Packet Integrity */
    static u_char     key[16] =
#if (NGX_QUIC_DRAFT_VERSION >= 29)
        "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1";
#else
        "\x4d\x32\xec\xdb\x2a\x21\x33\xc8\x41\xe4\x04\x3d\xf2\x7d\x44\x30";
#endif
    static u_char     nonce[12] =
#if (NGX_QUIC_DRAFT_VERSION >= 29)
        "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c";
#else
        "\x4d\x16\x11\xd0\x55\x13\xa5\x52\xc5\x87\xd5\x75";
#endif
    static ngx_str_t  in = ngx_string("");

    ad.data = res->data;
    ad.len = ngx_stream_quic_lb_create_retry_itag(pkt, ad.data, &start);

    itag.data = ad.data + ad.len;
    itag.len = EVP_GCM_TLS_TAG_LEN;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic retry itag", ad.data, ad.len);
#endif

    if (ngx_stream_quic_lb_retry_ciphers(NULL, &ciphers) == NGX_ERROR) {
        return NGX_ERROR;
    }

    secret.key.len = sizeof(key);
    secret.key.data = key;
    secret.iv.len = sizeof(nonce);

    if (ngx_stream_quic_lb_tls_seal(ciphers.c, &secret, &itag, nonce, &in, &ad, pkt->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    res->len = itag.data + itag.len - start;
    res->data = start;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_tls_seal(const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s,
    ngx_str_t *out, u_char *nonce, ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log)
{

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX  *ctx;

    ctx = EVP_AEAD_CTX_new(cipher, s->key.data, s->key.len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_AEAD_CTX_seal(ctx, out->data, &out->len, out->len, nonce, s->iv.len,
                          in->data, in->len, ad->data, ad->len)
        != 1)
    {
        EVP_AEAD_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_seal() failed");
        return NGX_ERROR;
    }

    EVP_AEAD_CTX_free(ctx);
#else
    int              len;
    EVP_CIPHER_CTX  *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, out->data, &len, in->data, in->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptUpdate() failed");
        return NGX_ERROR;
    }

    out->len = len;

    if (EVP_EncryptFinal_ex(ctx, out->data + out->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptFinal_ex failed");
        return NGX_ERROR;
    }

    out->len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                            out->data + in->len)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed");
        return NGX_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    out->len += EVP_GCM_TLS_TAG_LEN;
#endif
    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_tls_open(const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s,
    ngx_str_t *out, u_char *nonce, ngx_str_t *in, ngx_str_t *ad,
    ngx_log_t *log)
{

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX  *ctx;

    ctx = EVP_AEAD_CTX_new(cipher, s->key.data, s->key.len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_AEAD_CTX_open(ctx, out->data, &out->len, out->len, nonce, s->iv.len,
                          in->data, in->len, ad->data, ad->len)
        != 1)
    {
        EVP_AEAD_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_open() failed");
        return NGX_ERROR;
    }

    EVP_AEAD_CTX_free(ctx);
#else
    int              len;
    u_char          *tag;
    EVP_CIPHER_CTX  *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptUpdate(ctx, out->data, &len, in->data,
                          in->len - EVP_GCM_TLS_TAG_LEN)
        != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptUpdate() failed");
        return NGX_ERROR;
    }

    out->len = len;
    tag = in->data + in->len - EVP_GCM_TLS_TAG_LEN;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tag)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG) failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptFinal_ex(ctx, out->data + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptFinal_ex failed");
        return NGX_ERROR;
    }

    out->len += len;

    EVP_CIPHER_CTX_free(ctx);
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_lb_retry_ciphers(ngx_ssl_conn_t *ssl_conn, ngx_quic_ciphers_t *ciphers)
{
    ngx_int_t          len;

#ifdef OPENSSL_IS_BORINGSSL
    ciphers->c = EVP_aead_aes_128_gcm();
#else
    ciphers->c = EVP_aes_128_gcm();
#endif
    ciphers->hp = EVP_aes_128_ctr();
    ciphers->d = EVP_sha256();
    len = 16;

    return len;
}


static ngx_int_t
ngx_stream_quic_lb_gen_new_cid(ngx_str_t *new_dcid, ngx_connection_t *c)
{
    uint8_t                 len;

    if (RAND_bytes(&len, sizeof(len)) != 1) {
        return NGX_ERROR;
    }

    len = len % 10 + 10;

    new_dcid->len = len;
    new_dcid->data = ngx_pnalloc(c->pool, len);
    if (new_dcid->data == NULL) {
        return NGX_ERROR;
    }

    if (RAND_bytes(new_dcid->data, len) != 1) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_stream_quic_lb_do_retry_service(void *cf, ngx_quic_header_t *pkt,
    ngx_connection_t *c)
{

    ngx_stream_quic_lb_srv_conf_t *qlscf = cf;
    ngx_quic_lb_conf_t *qconf = &qlscf->quic_lb_conf[pkt->conf_id];

    /* get cids */
    ngx_str_t cids[3];
    /* origin dcid */
    cids[0] = pkt->dcid;
    /* scid */
    cids[1] = pkt->scid;

    ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                  "QUIC-LB, start do retry service ");

    if (ngx_stream_quic_lb_gen_new_cid(&cids[2], c) != NGX_OK) {
        return NGX_ERROR;
    }

    /* for cid which generated by quic-lb, conf_id should match current conf_id */
    if (pkt->conf_id < 0 || pkt->conf_id > 3) {
        ngx_log_error(NGX_LOG_ERR, c->pool->log, 0, "QUIC-LB, illegal pkt conf id");
        return NGX_ERROR;
    }
    cids[2].data[0] &= 0x3F;
    cids[2].data[0] |= pkt->conf_id << 6;

    ngx_int_t rc;
    if (qconf->retry_service.retry_method == NGX_QUIC_LB_RETRY_SHARED_STATE) {
        rc = ngx_stream_quic_lb_process_retry_service_in_shared_state(qconf, c, pkt);
        if (rc != NGX_OK) {
            /* generate retry packet and send */
            ngx_int_t rc_ = ngx_stream_quic_lb_gen_and_send_retry_packet(c, qconf, cids);
            ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                          "QUIC-LB, do retry service failed, "
                              "generate and send new retry packet:%s",
                          rc_ == NGX_OK ? "suc":"failed");
        }
        return rc;
    } else if (qconf->retry_service.retry_method == NGX_QUIC_LB_RETRY_NO_SHARE_STATE) {
        /* TODO */
    }

    /* pass through default */
    return NGX_OK;
}
