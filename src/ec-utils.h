#ifndef EC_UTILS_H
#define EC_UTILS_H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ECDSA_signature_request_t {
    ASN1_OCTET_STRING *digest;
    BIGNUM *inv;
    BIGNUM *rp;
};

typedef struct ECDSA_signature_request_t ECDSA_signature_request;

DECLARE_ASN1_FUNCTIONS(ECDSA_signature_request)

#ifdef __cplusplus
};
#endif

#endif /* EC_UTILS_H */
