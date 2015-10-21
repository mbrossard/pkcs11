#include "config.h"
#include "crypto.h"

#ifdef HAVE_OPENSSL
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#if ((defined(LIBRESSL_VERSION_NUMBER) && \
	(LIBRESSL_VERSION_NUMBER >= 0x20010002L))) || \
	(defined(ECDSA_F_ECDSA_METHOD_NEW))
#define ENABLE_PKCS11_ECDSA 1
#endif

void init_crypto()
{
    OPENSSL_add_all_algorithms_noconf();
}

EVP_PKEY *load_pkcs11_key(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_ULONG kt, class;
    CK_ATTRIBUTE key_type[] = {
        { CKA_CLASS,    &class, sizeof(class) },
        { CKA_KEY_TYPE, &kt,    sizeof(kt)    }
    };
    EVP_PKEY *k = NULL;
    CK_RV rv;

    rv = funcs->C_GetAttributeValue(session, key, key_type, 2);
    if(rv != CKR_OK || class != CKO_PRIVATE_KEY) {
        return k;
    }

    if(kt == CKK_RSA) {
        CK_ATTRIBUTE rsa_attributes[] = {
            { CKA_MODULUS, NULL, 0 },
            { CKA_PUBLIC_EXPONENT, NULL, 0 }
        };
        RSA *rsa = RSA_new();

        if(((rv = funcs->C_GetAttributeValue(session, key, rsa_attributes, 2)) == CKR_OK) &&
           ((rsa_attributes[0].pValue = malloc(rsa_attributes[0].ulValueLen)) != NULL) &&
           ((rsa_attributes[1].pValue = malloc(rsa_attributes[1].ulValueLen)) != NULL) &&
           ((rv = funcs->C_GetAttributeValue(session, key, rsa_attributes, 2)) == CKR_OK) && 
           (rsa != NULL) &&
           ((rsa->n = BN_bin2bn(rsa_attributes[1].pValue,
                                rsa_attributes[1].ulValueLen, NULL)) != NULL) &&
           ((rsa->e = BN_bin2bn(rsa_attributes[2].pValue,
                                rsa_attributes[2].ulValueLen, NULL)) != NULL)) {
            // build k from rsa
        }

        free(rsa_attributes[0].pValue);
        free(rsa_attributes[1].pValue);
#ifdef ENABLE_PKCS11_ECDSA
    } else if(kt == CKK_EC) {
        CK_ATTRIBUTE ecdsa_public[] = {
            { CKA_ID,       NULL,   0             },
            { CKA_CLASS,    &class, sizeof(class) },
            { CKA_KEY_TYPE, &kt,    sizeof(kt)    }
        };
        CK_ATTRIBUTE ecdsa_attributes[] = {
            { CKA_EC_PARAMS, NULL, 0 },
            { CKA_EC_POINT, NULL, 0 }
        };
        CK_OBJECT_HANDLE pub;
        CK_ULONG found;
        class = CKO_PUBLIC_KEY;

		if (((rv = funcs->C_GetAttributeValue(session, key, ecdsa_public, 1)) == CKR_OK) &&
            ((ecdsa_public[0].pValue = malloc(ecdsa_public[0].ulValueLen)) != NULL) &&
            ((rv = funcs->C_GetAttributeValue(session, key, ecdsa_public, 1)) == CKR_OK) &&
            ((rv = funcs->C_FindObjectsInit(session, ecdsa_public, 3)) == CKR_OK) &&
            ((rv = funcs->C_FindObjects(session, &pub, 1, &found)) == CKR_OK) && (found != 0) &&
            ((rv = funcs->C_FindObjectsFinal(session)) == CKR_OK) &&
            ((rv = funcs->C_GetAttributeValue(session, key, ecdsa_attributes, 2)) == CKR_OK) &&
            ((ecdsa_attributes[0].pValue = malloc(ecdsa_attributes[0].ulValueLen)) != NULL) &&
            ((ecdsa_attributes[1].pValue = malloc(ecdsa_attributes[1].ulValueLen)) != NULL) &&
            ((rv = funcs->C_GetAttributeValue(session, key, ecdsa_attributes, 2)) == CKR_OK)) {
            const unsigned char *ptr1 = ecdsa_attributes[1].pValue;
            const unsigned char *ptr2 = ecdsa_attributes[2].pValue;
            CK_ULONG len1 = ecdsa_attributes[1].ulValueLen;
            CK_ULONG len2 = ecdsa_attributes[2].ulValueLen;
            ASN1_OCTET_STRING *point = NULL;
            EC_KEY *ecdsa = NULL;

            /*
             * CKA_EC_PARAMS contains the curve parameters of the key
             * either referenced as an OID or directly with all values.
             * CKA_EC_POINT contains the point (public key) on the curve.
             * The point is should be returned inside a DER-encoded
             * ASN.1 OCTET STRING value (but some implementation).
             */
            if ((point = d2i_ASN1_OCTET_STRING(NULL, &ptr2, len2))) {
                /* Pointing to OCTET STRING content */
                ptr2 = point->data;
                len2 = point->length;
            } else {
                /* No OCTET STRING */
                ptr2 = ecdsa_attributes[2].pValue;
            }
            
            if((d2i_ECParameters(&ecdsa, &ptr1, len1) == NULL) ||
               (o2i_ECPublicKey(&ecdsa, &ptr2, len2) == NULL)) {
                EC_KEY_free(ecdsa);
                ecdsa = NULL;
            }
            
            if(point) {
                M_ASN1_OCTET_STRING_free(point);
            }

            if(ecdsa) {
                // build k from ecdsa
            }
        }

        free(ecdsa_public[0].pValue);
        free(ecdsa_attributes[0].pValue);
        free(ecdsa_attributes[1].pValue);
#endif
    }

    return k;
}

#else

void init_crypto()
{
}

#endif
