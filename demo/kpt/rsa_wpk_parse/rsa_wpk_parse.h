#ifndef __RSA_WPK_PARSE_H__
#define __RSA_WPK_PARSE_H__

#include <openssl/pem.h>
#include <openssl/asn1t.h>
#include <openssl/rsa.h>

#define PEM_STRING_WRAPPEDKEY "WRAPPED PRIVATE KEY"
#define KPT_WRAP_FORMAT_INDEX 12345

typedef struct enc_algo_desp_st {
    ASN1_OBJECT *enc_algo_id;
    ASN1_OCTET_STRING *iv;
    ASN1_INTEGER *ic;
    ASN1_OBJECT *hmac_algo_id;
} ENC_ALGO_DESP;
DECLARE_ASN1_FUNCTIONS(ENC_ALGO_DESP)

typedef struct wrap_desp_st {
    ASN1_OBJECT *wrapping_format;
    ENC_ALGO_DESP *encrypt_algo;
} WRAP_DESP;
DECLARE_ASN1_FUNCTIONS(WRAP_DESP)

typedef struct wrap_priv_key_st {
    ASN1_INTEGER *version;
    ASN1_OBJECT *algo_id;
    ASN1_OCTET_STRING *wrapped_key;
} WRAPPED_PRIV_KEY;
DECLARE_ASN1_FUNCTIONS(WRAPPED_PRIV_KEY)

typedef struct wrapped_priv_key_info_st {
    WRAP_DESP *wrap_desp;
    WRAPPED_PRIV_KEY *encrypted_data;
} WRAPPED_PRIV_KEY_INFO;
DECLARE_ASN1_FUNCTIONS(WRAPPED_PRIV_KEY_INFO)

typedef struct KPT_wrapping_format_st {
    unsigned char IV[32];
    unsigned int IV_length;
    unsigned int iteration_count;
    unsigned int enc_algorithm_id;
    unsigned int hmac_algorithm_id;
} KPT_WRAP_FORMAT;

#endif
