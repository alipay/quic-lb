
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

#define NGX_QUIC_RETRY_LIFETIME  300000


static ngx_int_t ngx_stream_quic_lb_validate_ngx_quic_model_token(
    ngx_connection_t *c, ngx_quic_header_t *pkt, u_char *key);
static ngx_int_t ngx_stream_quic_lb_new_ngx_quic_model_token(
    ngx_connection_t *c, ngx_str_t *token, u_char *key);
static ngx_int_t ngx_stream_quic_lb_create_retry_packet(ngx_quic_header_t *pkt, ngx_str_t *res);
static ngx_int_t ngx_stream_quic_lb_tls_seal(const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad, ngx_log_t *log);
static ngx_int_t ngx_stream_quic_lb_retry_ciphers(ngx_ssl_conn_t *ssl_conn,
    ngx_quic_ciphers_t *ciphers);
static size_t ngx_stream_quic_lb_create_retry_itag(ngx_quic_header_t *pkt,
   u_char *out, u_char **start);
static ngx_int_t ngx_stream_quic_lb_process_retry_service_in_shared_state(
    ngx_quic_lb_conf_t *conf, ngx_connection_t *c, ngx_quic_header_t *pkt);
static ngx_int_t ngx_stream_quic_lb_gen_and_send_retry_packet(ngx_connection_t *c,
    ngx_quic_lb_conf_t *qconf, ngx_str_t *cids);
static ngx_int_t ngx_stream_quic_lb_gen_new_cid(ngx_str_t *new_dcid, ngx_connection_t *c);
__attribute__((unused)) static ngx_int_t
ngx_stream_quic_lb_new_shared_state_token(ngx_connection_t *c,
    ngx_str_t *token, u_char *key, ngx_str_t *cids);

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

    ngx_int_t rc = ngx_stream_quic_lb_validate_ngx_quic_model_token(c, pkt,
        conf->retry_service.retry_token_key);
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

    /* currently, use nginx quic model token format */
    if (ngx_stream_quic_lb_new_ngx_quic_model_token(
        c, &token, qconf->retry_service.retry_token_key)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if 0
    u_char key_16[16]="0123456789012345";
    if (ngx_stream_quic_lb_new_shared_state_token(c, &token, key_16, cids) != NGX_OK) {
        ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                      "QUIC-LB, new shared state token failed.");
        return NGX_ERROR;
    }
#endif

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
ngx_stream_quic_lb_validate_ngx_quic_model_token(ngx_connection_t *c,
    ngx_quic_header_t *pkt, u_char *key)
{
    int                      len, tlen, iv_len;
    u_char                  *iv, *p, *data;
    ngx_msec_t               msec;
    EVP_CIPHER_CTX          *ctx;
    const EVP_CIPHER        *cipher;
    struct sockaddr_in      *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6;
#endif
    u_char                  tdec[NGX_QUIC_MAX_TOKEN_SIZE];

    cipher = EVP_aes_256_cbc();
    iv = pkt->token.data;
    iv_len = EVP_CIPHER_iv_length(cipher);

    /* sanity checks */

    if (pkt->token.len < (size_t) iv_len + EVP_CIPHER_block_size(cipher)) {
        return NGX_ERROR;
    }

    if (pkt->token.len > (size_t) iv_len + NGX_QUIC_MAX_TOKEN_SIZE) {
        return NGX_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    p = pkt->token.data + iv_len;
    len = pkt->token.len - iv_len;

    if (EVP_DecryptUpdate(ctx, tdec, &len, p, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    if (EVP_DecryptFinal_ex(ctx, tdec + len, &tlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        len = sizeof(struct in6_addr);
        data = sin6->sin6_addr.s6_addr;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        len = ngx_min(c->addr_text.len, NGX_QUIC_MAX_TOKEN_SIZE - sizeof(msec));
        data = c->addr_text.data;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) c->sockaddr;

        len = sizeof(in_addr_t);
        data = (u_char *) &sin->sin_addr;
        ngx_log_error(NGX_LOG_DEBUG, c->pool->log, 0,
                      "QUIC-LB, retry service, addr value in token is:%d", sin->sin_addr);
        break;
    }

    if (ngx_memcmp(tdec, data, len) != 0) {
        return NGX_ERROR;
    }

    ngx_memcpy(&msec, tdec + len, sizeof(msec));

    if (ngx_current_msec - msec > NGX_QUIC_RETRY_LIFETIME) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t ngx_stream_quic_lb_encrypt_token_with_aes_ecb_128(
    ngx_connection_t *c, u_char *key, ngx_str_t *token,
    u_char *input, size_t input_len)
{
    int res_len = ((input_len + AES_BLOCK_SIZE - 1) /
        AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    token->len = res_len;
    token->data = ngx_pnalloc(c->pool, res_len);
    if (token->data == NULL) {
        return NGX_ERROR;
    }

    memset((void*)token->data, 0, token->len);
    AES_KEY en_key;
    AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &en_key);

    int len = 0;
    while(len < res_len) {
        AES_encrypt(input + len, token->data + len, &en_key);
        len += AES_BLOCK_SIZE;
    }

    return NGX_OK;
}


/* format: 1990-08-08T08:08:08Z, total 20B */
static ngx_int_t ngx_stream_quic_lb_put_timestamp_in_rfc_3339(u_char *output) {
    time_t now = time(&now);
    if (now == -1) {
        return NGX_ERROR;
    }

    struct tm *ptm = gmtime(&now);
    if (ptm == NULL) {
        return NGX_ERROR;
    }

    int year = ptm->tm_year + 1900;
    int month = ptm->tm_mon + 1;
    int day = ptm->tm_mday;
    int hour = ptm->tm_hour;
    int min = ptm->tm_min;
    int sec = ptm->tm_sec;

    u_char s_time_format[32];
    ngx_snprintf(s_time_format, 32, "%4d-%02d-%02dT%02d:%02d:%02dZ",
            year, month, day, hour, min, sec);
    if (strlen((const char*)s_time_format) != 20) {
        return NGX_ERROR;
    }

    output = ngx_cpymem(output, s_time_format, strlen((const char*)s_time_format));

    return NGX_OK;
}


/* Format:
 *  ODCIL(1B)
 *  RSCIL(1B)
 *  ODCID(0~20B)
 *  RSCID(0~20B)
 *  Client IP (16B, for ipv4, the least 12B all 0)
 *  Date-time (20B)
 *  Opaque Data (optional)
 *
 * Encryption:
 *  AES-ECB-128bit
 */
__attribute__((unused)) static ngx_int_t
ngx_stream_quic_lb_new_shared_state_token(ngx_connection_t *c, ngx_str_t *token,
    u_char *key, ngx_str_t *cids)
{
    struct sockaddr_in   *sin;
    u_char               *data, *p;

#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    ngx_str_t orin_dcid   = cids[0];
    ngx_str_t retry_scid  = cids[2];

    u_char in[NGX_STREAM_QUIC_LB_MAX_RETRY_TOKEN_SIZE];
    p = ngx_cpymem(in, &(orin_dcid.len), 1);
    p = ngx_cpymem(p, orin_dcid.data, orin_dcid.len);
    p = ngx_cpymem(p, &(retry_scid.len), 1);
    p = ngx_cpymem(p, retry_scid.data, retry_scid.len);

    switch (c->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        data = sin6->sin6_addr.s6_addr;
        p = ngx_cpymem(p, data, 16);
        break;
#endif
    default: /* AF_INET */
        sin = (struct sockaddr_in *) c->sockaddr;
        data = (u_char *) &sin->sin_addr;
        p = ngx_cpymem(p, data, 4);
        p = ngx_cpymem(p, "0", 12);
        break;
    }

    if (NGX_STREAM_QUIC_LB_MAX_RETRY_TOKEN_SIZE - (p - in) < 20) {
        return NGX_ERROR;
    }

    if (ngx_stream_quic_lb_put_timestamp_in_rfc_3339(p) != NGX_OK) {
        return NGX_ERROR;
    }

    /* with aes-ecb-128 encryption */
    return ngx_stream_quic_lb_encrypt_token_with_aes_ecb_128(
        c, key, token, in, p - in);
}

/*
 * Format: IP_ADDRESS(4B(ipv4)/16B(ipb6)) Timestamp(8B)
 * Encryption: AES-256-ECB
 */
static ngx_int_t
ngx_stream_quic_lb_new_ngx_quic_model_token(ngx_connection_t *c, ngx_str_t *token, u_char *key)
{
    int                   len, iv_len;
    u_char               *data, *p, *iv;
    ngx_msec_t            now;
    EVP_CIPHER_CTX       *ctx;
    const EVP_CIPHER     *cipher;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    u_char                in[NGX_QUIC_MAX_TOKEN_SIZE];

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        len = sizeof(struct in6_addr);
        data = sin6->sin6_addr.s6_addr;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        len = ngx_min(c->addr_text.len, NGX_QUIC_MAX_TOKEN_SIZE - sizeof(now));
        data = c->addr_text.data;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) c->sockaddr;
        len = sizeof(in_addr_t);
        data = (u_char *) &sin->sin_addr;

        break;
    }

    p = ngx_cpymem(in, data, len);

    now = ngx_current_msec;
    len += sizeof(now);
    ngx_memcpy(p, &now, sizeof(now));

    cipher = EVP_aes_256_cbc();
    iv_len = EVP_CIPHER_iv_length(cipher);

    token->len = iv_len + len + EVP_CIPHER_block_size(cipher);
    token->data = ngx_pnalloc(c->pool, token->len);
    if (token->data == NULL) {
        return NGX_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    iv = token->data;

    if (RAND_bytes(iv, iv_len) <= 0
        || !EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len = iv_len;

    if (EVP_EncryptUpdate(ctx, token->data + token->len, &len, in, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len += len;

    if (EVP_EncryptFinal_ex(ctx, token->data + token->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len += len;

    EVP_CIPHER_CTX_free(ctx);

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(c->log, "QUIC-LB, quic new token", token->data, token->len);
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

    if (ngx_stream_quic_lb_gen_new_cid(&cids[2], c) != NGX_OK) {
        return NGX_ERROR;
    }

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
