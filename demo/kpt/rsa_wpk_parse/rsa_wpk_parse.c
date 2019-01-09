#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rsa_wpk_parse.h"

ASN1_SEQUENCE(ENC_ALGO_DESP) = {
        ASN1_SIMPLE(ENC_ALGO_DESP, enc_algo_id, ASN1_OBJECT),
        ASN1_SIMPLE(ENC_ALGO_DESP, iv, ASN1_OCTET_STRING),
        ASN1_SIMPLE(ENC_ALGO_DESP, ic, ASN1_INTEGER),
        ASN1_SIMPLE(ENC_ALGO_DESP, hmac_algo_id, ASN1_OBJECT)
}ASN1_SEQUENCE_END(ENC_ALGO_DESP)
IMPLEMENT_ASN1_FUNCTIONS(ENC_ALGO_DESP)

ASN1_SEQUENCE(WRAP_DESP) = {
        ASN1_SIMPLE(WRAP_DESP, wrapping_format,ASN1_OBJECT),
        ASN1_SIMPLE(WRAP_DESP, encrypt_algo, ENC_ALGO_DESP)
}ASN1_SEQUENCE_END(WRAP_DESP)
IMPLEMENT_ASN1_FUNCTIONS(WRAP_DESP)

ASN1_SEQUENCE(WRAPPED_PRIV_KEY) = {
        ASN1_SIMPLE(WRAPPED_PRIV_KEY, version, ASN1_INTEGER),
        ASN1_SIMPLE(WRAPPED_PRIV_KEY, algo_id, ASN1_OBJECT),
        ASN1_SIMPLE(WRAPPED_PRIV_KEY, wrapped_key, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(WRAPPED_PRIV_KEY)
IMPLEMENT_ASN1_FUNCTIONS(WRAPPED_PRIV_KEY)

ASN1_SEQUENCE(WRAPPED_PRIV_KEY_INFO) = {
        ASN1_SIMPLE(WRAPPED_PRIV_KEY_INFO, wrap_desp, WRAP_DESP),
        ASN1_SIMPLE(WRAPPED_PRIV_KEY_INFO, encrypted_data, WRAPPED_PRIV_KEY)
}ASN1_SEQUENCE_END(WRAPPED_PRIV_KEY_INFO)
IMPLEMENT_ASN1_FUNCTIONS(WRAPPED_PRIV_KEY_INFO)

int print_RSA(char* file, RSA* rsa) {
    FILE* fp = NULL;

    if (!file){
        fprintf(stderr, " -- File is NULL\n");
        return -1;
    }

    fp = fopen(file, "w");
    if (!fp) {
        fprintf(stderr, " -- Failed to open file %s\n", file);
        return -1;
    }

    RSA_print_fp(fp, rsa, 0);

    fclose(fp);
    return 0;
}

int print_wrap_format(KPT_WRAP_FORMAT *kpt_wrap_format) {
    int i;
    char buff[1024];
    ASN1_OBJECT *enc_algo_id;
    ASN1_OBJECT *hmac_algo_id;

    fprintf(stderr, "iv:");
    for (i=0; i<kpt_wrap_format->IV_length; i++) {
        if (i%2==0)
            fprintf(stderr, " ");
        fprintf(stderr, "%02x", kpt_wrap_format->IV[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "iteration_count: %u\n", kpt_wrap_format->iteration_count);

    enc_algo_id = OBJ_nid2obj(kpt_wrap_format->enc_algorithm_id);
    OBJ_obj2txt(buff, 1024, enc_algo_id, 0);
    fprintf(stderr, "enc_algo_id: %s\n", buff);

    hmac_algo_id = OBJ_nid2obj(kpt_wrap_format->hmac_algorithm_id);
    OBJ_obj2txt(buff, 1024, hmac_algo_id, 0);
    fprintf(stderr, "hmac_algo_id: %s\n", buff);

    return 0;
}

EVP_PKEY *EVP_WPK2PKEY(const WRAPPED_PRIV_KEY_INFO *wpkinfo) {
    EVP_PKEY *pkey = NULL;

    WRAP_DESP *wrap_desp;
    WRAPPED_PRIV_KEY *encrypted_data;
    ENC_ALGO_DESP *encrypt_algo;
    ASN1_OCTET_STRING *wrapped_key;

    ASN1_OBJECT *enc_algo_id;
    ASN1_OBJECT *hmac_algo_id;
    ASN1_OCTET_STRING *iv;
    ASN1_INTEGER *ic;
    int enc_algo_nid;
    int hmac_algo_nid;

    RSA *kpt_rsa;
    KPT_WRAP_FORMAT *kpt_wrap_format = NULL;
    unsigned long temp;

    if ((wrap_desp = wpkinfo->wrap_desp) == NULL) goto error;
    if ((encrypted_data = wpkinfo->encrypted_data) == NULL) goto error;
    if ((encrypt_algo = wrap_desp->encrypt_algo) == NULL) goto error;
    if ((wrapped_key = encrypted_data->wrapped_key) == NULL) goto error;

    if ((enc_algo_id = encrypt_algo->enc_algo_id) == NULL) goto error;
    if ((hmac_algo_id = encrypt_algo->hmac_algo_id) == NULL) goto error;
    if ((iv = encrypt_algo->iv) == NULL) goto error;
    if ((ic = encrypt_algo->ic) == NULL) goto error;
    enc_algo_nid = OBJ_obj2nid(encrypt_algo->enc_algo_id);
    hmac_algo_nid = OBJ_obj2nid(encrypt_algo->hmac_algo_id);

    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char **) &wrapped_key->data, wrapped_key->length);
    if (pkey == NULL) {
        fprintf(stderr, "d2i_PrivateKey failed\n");
        goto error;
    }

    if ((kpt_rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) goto error;
    print_RSA("wrapped_RSA", kpt_rsa);

    kpt_wrap_format = (KPT_WRAP_FORMAT*) OPENSSL_malloc(sizeof(KPT_WRAP_FORMAT));
    if (kpt_wrap_format == NULL) goto error;
    kpt_wrap_format->IV_length = iv->length;
    memcpy(kpt_wrap_format->IV, iv->data, iv->length);
    ASN1_INTEGER_get_uint64(&temp, ic);
    kpt_wrap_format->iteration_count = temp;
    kpt_wrap_format->enc_algorithm_id = enc_algo_nid;
    kpt_wrap_format->hmac_algorithm_id = hmac_algo_nid;

    print_wrap_format(kpt_wrap_format);

    if (RSA_set_ex_data(kpt_rsa, KPT_WRAP_FORMAT_INDEX, kpt_wrap_format) != 1) {
        OPENSSL_free(kpt_wrap_format);
        goto error;
    }

    return pkey;

error:
    fprintf(stderr, "EVP_WPK2PKEY failed\n");
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    return NULL;
}

EVP_PKEY *PEM_read_bio_WPK(BIO *bp) {
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    EVP_PKEY *ret = NULL;

    if (!PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_WRAPPEDKEY, bp, NULL, NULL)) {
        fprintf(stderr, "PEM_bytes_read_bio failed\n");
        return NULL;
    }
    p = data;

    if (strcmp(nm, PEM_STRING_WRAPPEDKEY) == 0) {
        WRAPPED_PRIV_KEY_INFO *wpkinfo;

        wpkinfo = d2i_WRAPPED_PRIV_KEY_INFO(NULL, &p, len);
        if (wpkinfo == NULL)
            goto error;

        ret = EVP_WPK2PKEY(wpkinfo);
    }

error:
    if (ret == NULL)
        fprintf(stderr, "PEM_read_bio_WPK failed\n");
    OPENSSL_free(nm);
    OPENSSL_clear_free(data, len);
    return (ret);
}

int main(int argc, char **argv) {
    unsigned char *wpk_file = NULL;
    BIO *in = NULL;

    if (argc != 2) {
        fprintf(stderr, "Error usage\n");
        return 0;
    }

    wpk_file = *(++argv);

    if(access(wpk_file, F_OK)) {
        fprintf(stderr, "File %s does not exist\n", wpk_file);
        return -1;
    }

    in = BIO_new(BIO_s_file());
    if (!in) {
        fprintf(stderr, "BIO new failed\n");
        return 0;
    }

    if(!(BIO_read_filename(in, wpk_file))) {
        fprintf(stderr, "Read wrapped private key file %s failed\n", wpk_file);
        BIO_free(in);
        return 0;
    }

    PEM_read_bio_WPK(in);

    return 0;
}