
/*
 * Copyright 2020. All Rights Reserved.
 * Author: william.zk
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

static ngx_inline u_char *ngx_quic_parse_int(u_char *pos, u_char *end, uint64_t *out);


u_char *
ngx_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value)
{
    if ((size_t)(end - pos) < 1) {
        return NULL;
    }

    *value = *pos;

    return pos + 1;
}


u_char *
ngx_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value)
{
    if ((size_t)(end - pos) < sizeof(uint32_t)) {
        return NULL;
    }

    *value = ngx_quic_parse_uint32(pos);

    return pos + sizeof(uint32_t);
}


static ngx_inline u_char *
ngx_quic_parse_int(u_char *pos, u_char *end, uint64_t *out)
{
    u_char      *p;
    uint64_t     value;
    ngx_uint_t   len;

    if (pos >= end) {
        return NULL;
    }

    p = pos;
    len = 1 << ((*p & 0xc0) >> 6);

    value = *p++ & 0x3f;

    if ((size_t)(end - p) < (len - 1)) {
        return NULL;
    }

    while (--len) {
        value = (value << 8) + *p++;
    }

    *out = value;

    return p;
}


u_char *
ngx_quic_read_bytes(u_char *pos, u_char *end, size_t len, u_char **out)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    *out = pos;

    return pos + len;
}


ngx_int_t
ngx_quic_parse_initial_header(ngx_quic_header_t *pkt)
{
    u_char    *p, *end;
    uint64_t   varint;

    p = pkt->raw->pos;

    end = pkt->raw->last;

    pkt->log->action = "QUIC-LB, parsing quic initial header";

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "QUIC-LB, quic failed to parse token length");
        return NGX_ERROR;
    }

    pkt->token.len = varint;

    p = ngx_quic_read_bytes(p, end, pkt->token.len, &pkt->token.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "QUIC-LB, quic packet too small to read token data");
        return NGX_ERROR;
    }

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "QUIC-LB, quic bad packet length");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "QUIC-LB, quic initial packet length: %uL", varint);

    if (varint > (uint64_t) ((pkt->data + pkt->len) - p)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "QUIC-LB, quic truncated initial packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = varint;

    return NGX_OK;
}


ngx_int_t
ngx_quic_hexstring_to_string(u_char *dst, u_char *src, ngx_int_t src_len)
{
    ngx_int_t  i, len;
    ngx_int_t  rc;

    if (dst == NULL || src == NULL || src_len < 0) {
        return NGX_ERROR;
    }

    if (src_len % 2 != 0) {
        return NGX_ERROR;
    }

    len = src_len / 2;

    for (i = 0; i < len; i++) {
        rc = ngx_hextoi(src + (2 * i), 2);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
        dst[i] = (u_char)rc;
    }

    return NGX_OK;
}

ngx_int_t
ngx_quic_aes_128_ecb_encrypt(u_char *plaintext, ngx_int_t plaintext_len,
    u_char *key, u_char *ciphertext)
{
    EVP_CIPHER_CTX   *ctx;
    int               len;
    ngx_int_t         ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto failed;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) <= 0 ) {
        goto failed;
    }

    if (EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0) {
        goto failed;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) <= 0) {
        goto failed;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0) {
        goto failed;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
failed:
    EVP_CIPHER_CTX_free(ctx);
    return NGX_ERROR;
}


ngx_int_t
ngx_quic_aes_128_ecb_decrypt(u_char *ciphertext, ngx_int_t ciphertext_len,
    u_char *key, u_char *plaintext)
{
    EVP_CIPHER_CTX   *ctx;
    int               len;
    ngx_int_t         plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto failed;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) <= 0 ) {
        goto failed;
    }

    if (EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0) {
        goto failed;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0) {
        goto failed;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        goto failed;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
failed:
    EVP_CIPHER_CTX_free(ctx);
    return NGX_ERROR;
}

ngx_int_t
expand_left(u_char *result, u_char *s1, ngx_int_t s1_bits,
    u_char *s2, ngx_int_t s2_bits)
{
    ngx_int_t i, j, offset = 0;
    ngx_int_t s1_byte, s1_bitofbyte, s2_byte, s2_bitofbyte;


    if (s1_bits + s2_bits > 128) {
        return NGX_ERROR;
    }

    ngx_memzero(result, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN);

    s1_byte = s1_bits / 8;
    s1_bitofbyte = s1_bits % 8;
    s2_byte = s2_bits / 8;
    s2_bitofbyte = s2_bits % 8;

    for (i = 0; i < s1_byte; i++) {
        result[i] = s1[i];
    }

    for (j = 0; j < s1_bitofbyte; j++) {
        result[i] |= (s1[i]) & (1 << (7 - j));
    }

    if (s2_bitofbyte != 0) {
        offset = 1;
    }

    for (i = NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN - 1; i > NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN - 1 - s2_byte; i--) {
        result[i] = s2[s2_byte + i - NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN + offset];
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "QUIC-LB, i:%d s2_offset:%d result[i]:%02x s2[x]:%02x",i, s2_byte + i - NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN + offset,
                      result[i], s2[s2_byte + i - NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN + offset]);
    }

    for (j = 0; j < s2_bitofbyte; j++) {
        result[i] |= (s2[0]) & (1 << j);
    }
    return NGX_OK;
}

ngx_int_t
expand_right(u_char *result, u_char *s1, ngx_int_t s1_bits,
    u_char *s2, ngx_int_t s2_bits)
{
    ngx_int_t i, j, offset = 0;
    ngx_int_t s1_byte, s1_bitofbyte, s2_byte, s2_bitofbyte;


    if (s1_bits + s2_bits > 128) {
        return NGX_ERROR;
    }

    ngx_memzero(result, NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN);

    s1_byte = s1_bits / 8;
    s1_bitofbyte = s1_bits % 8;
    s2_byte = s2_bits / 8;
    s2_bitofbyte = s2_bits % 8;

    for (i = 0; i < s2_byte; i++) {
        result[i] = s2[i];
    }

    for (j = 0; j < s2_bitofbyte; j++) {
        result[i] |= (s2[i]) & (1 << (7 - j));
    }

    if (s1_bitofbyte != 0) {
        offset = 1;
    }

    for (i = NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN - 1; i > NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN - 1 - s1_byte; i--) {
        result[i] = s1[s1_byte + i - NGX_QUIC_LB_STREAM_CIPHER_PADDED_DATA_LEN + offset];
    }

    for (j = 0; j < s1_bitofbyte; j++) {
        result[i] |= (s1[0]) & (1 << j);
    }
    return NGX_OK;
}

ngx_int_t
truncate_left(u_char *result, ngx_int_t result_len, u_char *src, ngx_int_t src_len, ngx_int_t truncate_bits)
{
    ngx_int_t i, j;
    ngx_int_t truncate_byte, truncate_bitofbyte;

    truncate_byte = truncate_bits / 8;
    truncate_bitofbyte = truncate_bits % 8;

    if (result_len * 8 < truncate_bits || src_len * 8 < truncate_bits) {
        return NGX_ERROR;
    }

    ngx_memzero(result, result_len);

    for (i = 0; i < truncate_byte; i++) {
        result[i] = src[i];
    }

    for (j = 0; j < truncate_bitofbyte; j++) {
        result[i] |= (src[i]) & (1 << (7 - j));
    }
    return NGX_OK;
}

ngx_int_t
truncate_right(u_char *result, ngx_int_t result_len, u_char *src, ngx_int_t src_len, ngx_int_t truncate_bits)
{
    ngx_int_t i, offset, j;
    ngx_int_t truncate_byte, truncate_bitofbyte;

    truncate_byte = truncate_bits / 8;
    truncate_bitofbyte = truncate_bits % 8;

    if (truncate_bitofbyte != 0) {
        offset = 1;
    }

    if (result_len * 8 < truncate_bits || src_len * 8 < truncate_bits) {
        return NGX_ERROR;
    }

    ngx_memzero(result, result_len);

    for (i = src_len - 1; i > src_len - 1 - truncate_byte; i--) {
        result[truncate_byte + offset + i - src_len] = src[i];
    }

    for (j = 0; j < truncate_bitofbyte; j++) {
        result[0] |= (src[i]) & (1 << j);
    }

    return NGX_OK;
}