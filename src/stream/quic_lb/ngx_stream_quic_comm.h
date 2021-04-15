
/*
 * Copyright 2020. All Rights Reserved.
 * Author: william.zk
 */


#ifndef _NGX_STREAM_QUIC_COMM_H_INCLUDED_
#define _NGX_STREAM_QUIC_COMM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define NGX_QUIC_DEBUG_CRYPTO


#define NGX_QUIC_IV_LEN               12


#define NGX_AES_128_GCM_SHA256        0x1301
#define NGX_AES_256_GCM_SHA384        0x1302
#define NGX_CHACHA20_POLY1305_SHA256  0x1303


#ifdef OPENSSL_IS_BORINGSSL
#define ngx_quic_cipher_t             EVP_AEAD
#else
#define ngx_quic_cipher_t             EVP_CIPHER
#endif


#define NGX_QUIC_CID_LEN_MIN                                8
#define NGX_QUIC_CID_LEN_MAX                               20


#define NGX_QUIC_PKT_LONG       0x80  /* header form */
#define NGX_QUIC_PKT_FIXED_BIT  0x40
#define NGX_QUIC_PKT_TYPE       0x30  /* in long packet */
#define NGX_QUIC_PKT_KPHASE     0x04  /* in short packet */


#define NGX_QUIC_PKT_LONG_RESERVED_BIT   0x0C
#define NGX_QUIC_PKT_SHORT_RESERVED_BIT  0x18


#define ngx_quic_long_pkt(flags)  ((flags) & NGX_QUIC_PKT_LONG)
#define ngx_quic_short_pkt(flags)  (((flags) & NGX_QUIC_PKT_LONG) == 0)


/* Long packet types */
#define NGX_QUIC_PKT_INITIAL    0x00
#define NGX_QUIC_PKT_ZRTT       0x10
#define NGX_QUIC_PKT_HANDSHAKE  0x20
#define NGX_QUIC_PKT_RETRY      0x30


#define ngx_quic_pkt_in(flags)                                                \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_INITIAL)
#define ngx_quic_pkt_zrtt(flags)                                              \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_ZRTT)
#define ngx_quic_pkt_hs(flags)                                                \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_HANDSHAKE)
#define ngx_quic_pkt_retry(flags)                                             \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_RETRY)


#ifndef NGX_QUIC_DRAFT_VERSION
#define NGX_QUIC_DRAFT_VERSION               29
#endif
#define NGX_QUIC_VERSION  (0xff000000 + NGX_QUIC_DRAFT_VERSION)


#if (NGX_HAVE_NONALIGNED)

#define ngx_quic_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define ngx_quic_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#define ngx_quic_write_uint16  ngx_quic_write_uint16_aligned
#define ngx_quic_write_uint32  ngx_quic_write_uint32_aligned

#else


#define ngx_quic_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define ngx_quic_parse_uint32(p)                                              \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])





#define ngx_quic_write_uint16(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))


#define ngx_quic_write_uint32(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))


#endif


#define ngx_quic_write_uint8(p, s)                                            \
    ((p)[0] = (u_char)  (s),                                                  \
     (p) + sizeof(uint8_t))


#define ngx_quic_write_uint24(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 16),                                           \
     (p)[1] = (u_char) ((s) >> 8),                                            \
     (p)[2] = (u_char)  (s),                                                  \
     (p) + sizeof(uint8_t) + sizeof(uint16_t))


#define ngx_quic_write_uint64(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 56),                                           \
     (p)[1] = (u_char) ((s) >> 48),                                           \
     (p)[2] = (u_char) ((s) >> 40),                                           \
     (p)[3] = (u_char) ((s) >> 32),                                           \
     (p)[4] = (u_char) ((s) >> 24),                                           \
     (p)[5] = (u_char) ((s) >> 16),                                           \
     (p)[6] = (u_char) ((s) >> 8),                                            \
     (p)[7] = (u_char)  (s),                                                  \
     (p) + sizeof(uint64_t))


#define ngx_quic_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))


#define ngx_quic_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))


#define ngx_quic_varint_len(value)                                            \
     ((value) <= 63 ? 1                                                       \
     : ((uint32_t) value) <= 16383 ? 2                                        \
     : ((uint64_t) value) <= 1073741823 ?  4                                  \
     : 8)


#if (NGX_DEBUG)

#define ngx_quic_hexdump(log, label, data, len)                               \
do {                                                                          \
    ngx_int_t  m;                                                             \
    u_char     buf[2048];                                                     \
                                                                              \
    if (log->log_level & NGX_LOG_DEBUG_EVENT) {                               \
        m = ngx_hex_dump(buf, (u_char *) data, ngx_min(len, 1024)) - buf;     \
        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,                           \
                      label " len:%uz data:%*s%s",                            \
                      len, m, buf, len < 2048 ? "" : "...");                  \
    }                                                                         \
} while (0)

#else

#define ngx_quic_hexdump(log, fmt, data, len)

#endif


typedef struct ngx_quic_secret_s {
    ngx_str_t                 secret;
    ngx_str_t                 key;
    ngx_str_t                 iv;
    ngx_str_t                 hp;
} ngx_quic_secret_t;


typedef struct {
    ngx_log_t                                  *log;

    struct ngx_quic_secret_s                   *secret;
    struct ngx_quic_secret_s                   *next;
    uint64_t                                    number;
    uint8_t                                     num_len;
    uint32_t                                    trunc;
    uint8_t                                     flags;
    uint32_t                                    version;
    ngx_str_t                                   token;
    ngx_uint_t                                  error;

    /* filled in by parser */
    ngx_buf_t                                  *raw;   /* udp datagram */

    u_char                                     *data;  /* quic packet */
    size_t                                      len;

    /* cleartext fields */
    ngx_str_t                                   odcid; /* retry packet tag */
    ngx_str_t                                   dcid;
    ngx_str_t                                   scid;
    uint64_t                                    pn;
    u_char                                     *plaintext;
    ngx_str_t                                   payload; /* decrypted data */

    unsigned                                    need_ack:1;
    unsigned                                    key_phase:1;
    unsigned                                    key_update:1;

    /* add for quic lb */
    ngx_int_t                                   conf_id;
    ngx_flag_t                                  initial_pkt;
    ngx_str_t                                   sid; /* record dst server id */
} ngx_quic_header_t;


typedef struct {
    const ngx_quic_cipher_t  *c;
    const EVP_CIPHER         *hp;
    const EVP_MD             *d;
} ngx_quic_ciphers_t;


ngx_int_t ngx_quic_parse_initial_header(ngx_quic_header_t *pkt);
u_char *ngx_quic_read_bytes(u_char *pos, u_char *end,
    size_t len, u_char **out);
u_char *ngx_quic_read_uint8(u_char *pos, u_char *end,
    uint8_t *value);
u_char *ngx_quic_read_uint32(u_char *pos, u_char *end,
    uint32_t *value);
#endif
