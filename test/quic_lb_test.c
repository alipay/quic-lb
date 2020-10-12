/*
 * Copyright 2020. All Rights Reserved.
 * Author: Lingtao Kong
 */


#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/evp.h>


#define  TEST_RETRY_TAG_LEN     16
#define  u_char                 unsigned char
#define  TEST_ERROR            -1
#define  TEST_OK                0
#define  TEST_MAX_TOKEN_SIZE    32
#define  RETRY_LIFETIME         30000


u_char key[16] =
    "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1";
u_char nonce[12] =
    "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c";
u_char token_key[32] = "01234567890123456789012345678901";


typedef struct {
    size_t      len;
    u_char     *data;
} test_string_t;


typedef struct {
    test_string_t key;
    test_string_t iv;
} test_retry_secret_t;


static test_string_t *test_get_retry_packet_tag(u_char *pseudo_data, size_t pseudo_len);
static size_t test_encode_retry(const EVP_CIPHER  *cipher, test_retry_secret_t *s,
    test_string_t *out, u_char *nonce, test_string_t *in, test_string_t *pseu_pkt);


/*
 * only support ipv4 address currently.
 */
size_t test_verify_token(unsigned int addr_value, u_char *token, size_t token_len) {
    int                     len, tlen, iv_len;
    u_char                 *iv, *p;
    time_t                  sec;
    unsigned int            msec, curremt_msec;
    EVP_CIPHER_CTX         *ctx;
    const EVP_CIPHER       *cipher;
    u_char                  tdec[TEST_MAX_TOKEN_SIZE];

    cipher = EVP_aes_256_cbc();
    iv = token;
    iv_len = EVP_CIPHER_iv_length(cipher);

    /* sanity checks */
    if (token_len < (size_t) iv_len + EVP_CIPHER_block_size(cipher)) {
        return 0;
    }
    if (token_len > (size_t) iv_len + TEST_MAX_TOKEN_SIZE) {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return 0;
    }
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, token_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    p = token + iv_len;
    len = token_len - iv_len;
    if (EVP_DecryptUpdate(ctx, tdec, &len, p, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_DecryptFinal_ex(ctx, tdec + len, &tlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    EVP_CIPHER_CTX_free(ctx);


    if (memcmp(tdec, (u_char*)(&addr_value), 4) != 0) {
        return 0;
    }

    return 1;
    /* don't check timestamp at this time */
    memcpy(&msec, tdec + len, sizeof(msec));
    struct timeval tv;
    gettimeofday(&tv, NULL);
    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;
    curremt_msec = (unsigned int) sec * 1000 + msec;
    if (curremt_msec - msec > RETRY_LIFETIME) {
        return 0;
    }

    return 1;
}

/*
 * recompute tag with pseudo_data input, then compare
 * the result with retry_tag input.
 */
size_t test_verify_retry_tag(u_char *pseudo_data,
    size_t pseudo_len, u_char *retry_tag)
{
    test_string_t *retry_tag_ = test_get_retry_packet_tag(pseudo_data, pseudo_len);
    if (retry_tag_ == NULL) {
        printf("test_get_retry_packet_tag failed\n");
        return 0;
    }
    if (0 != memcmp(retry_tag, retry_tag_->data, retry_tag_->len)) {
        return 0;
    }
    return 1;
}


static test_string_t *
test_get_retry_packet_tag(u_char *pseudo_data, size_t pseudo_len)
{
    static u_char retry_tag_data[TEST_RETRY_TAG_LEN];
    static test_string_t  retry_tag;
    retry_tag.data = retry_tag_data;
    retry_tag.len =  TEST_RETRY_TAG_LEN;
    test_string_t pesudo_packet;
    pesudo_packet.data = pseudo_data;
    pesudo_packet.len = pseudo_len;
    test_retry_secret_t secret1;
    secret1.key.data = key;
    secret1.key.len = sizeof(key);
    secret1.iv.len = sizeof(nonce);
    test_string_t  in;
    in.data = NULL;
    in.len = 0;

    const EVP_CIPHER *cipher = EVP_aes_128_gcm();
    if (test_encode_retry(cipher,
        &secret1, &retry_tag, nonce, &in, &pesudo_packet) != TEST_OK)
    {
        return NULL;
    }

    return &retry_tag;
}


static size_t
test_encode_retry(const EVP_CIPHER  *cipher, test_retry_secret_t *s,
    test_string_t *out, u_char *nonce, test_string_t *in,
    test_string_t *pseu_pkt)
{
    int              len;
    EVP_CIPHER_CTX  *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("EVP_CIPHER_CTX_new() failed\n");
        return TEST_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        printf("EVP_EncryptInit_ex() failed\n");
        return TEST_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        printf("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed\n");
        return TEST_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        printf("EVP_EncryptInit_ex() failed\n");
        return TEST_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, pseu_pkt->data, pseu_pkt->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        printf("EVP_EncryptUpdate() failed\n");
        return TEST_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, out->data, &len, in->data, in->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        printf("EVP_EncryptUpdate()  failed\n");
        return TEST_ERROR;
    }

    out->len = len;
    if (EVP_EncryptFinal_ex(ctx, out->data + out->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        printf("EVP_EncryptFinal_ex  failed\n");
        return TEST_ERROR;
    }

    out->len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                            out->data + in->len)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        printf("EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed\n");
        return TEST_ERROR;
    }
    EVP_CIPHER_CTX_free(ctx);
    out->len += EVP_GCM_TLS_TAG_LEN;

    return TEST_OK;
}
