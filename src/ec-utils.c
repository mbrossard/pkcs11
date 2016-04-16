#include "ec-utils.h"

ASN1_SEQUENCE(ECDSA_signature_request) = {
        ASN1_SIMPLE(ECDSA_signature_request, digest, ASN1_OCTET_STRING),
        ASN1_SIMPLE(ECDSA_signature_request, inv, BIGNUM),
        ASN1_SIMPLE(ECDSA_signature_request, rp, BIGNUM)
} ASN1_SEQUENCE_END(ECDSA_signature_request)
