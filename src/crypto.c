/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "crypto.h"
#include "pkcs11_display.h"

#ifdef HAVE_OPENSSL
#include <string.h>
#include <openssl/rsa.h>

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#ifndef OPENSSL_NO_ECDSA
#include <openssl/ecdsa.h>
#if ((defined(LIBRESSL_VERSION_NUMBER) &&           \
      (LIBRESSL_VERSION_NUMBER >= 0x20010002L))) || \
	(defined(ECDSA_F_ECDSA_METHOD_NEW)) ||          \
    ((defined(OPENSSL_VERSION_NUMBER) &&            \
      (OPENSSL_VERSION_NUMBER >= 0x10100000L)))
#define ENABLE_PKCS11_ECDSA 1
#endif
#endif
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#endif

void init_crypto()
{
    OPENSSL_add_all_algorithms_noconf();
}

struct pkcs11_key_data {
    CK_FUNCTION_LIST *funcs;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    CK_BYTE type;
};

static int pkcs11_rsa_key_idx = -1;

static int pkcs11_rsa_private_encrypt(int flen, const unsigned char *from,
                                      unsigned char *to, RSA *rsa, int padding)
{
    struct pkcs11_key_data *pkd = NULL;
	CK_MECHANISM mech = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};
	CK_ULONG tlen = 0;
	CK_RV rv;
	int rval = -1;

    tlen = RSA_size(rsa);
    if(((pkd = RSA_get_ex_data(rsa, pkcs11_rsa_key_idx)) != NULL) &&
       ((rv = pkd->funcs->C_SignInit(pkd->session, &mech, pkd->key)) == CKR_OK) &&
       /* TODO: handle CKR_BUFFER_TOO_SMALL */
       ((rv = pkd->funcs->C_Sign(pkd->session, (CK_BYTE *)from, flen, to, &tlen)) == CKR_OK)) {
        rval = tlen;
    } else {
        return -1;
    }

	return (rval);
}

static int pkcs11_rsa_private_decrypt(int flen, const unsigned char *from,
                                      unsigned char *to, RSA *rsa, int padding)
{
    struct pkcs11_key_data *pkd = NULL;
	CK_MECHANISM mech = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};
	CK_ULONG tlen = 0;
	CK_RV rv;
	int rval = -1;

    tlen = RSA_size(rsa);
    if(((pkd = RSA_get_ex_data(rsa, pkcs11_rsa_key_idx)) != NULL) &&
       ((rv = pkd->funcs->C_DecryptInit(pkd->session, &mech, pkd->key)) == CKR_OK) &&
       /* TODO: handle CKR_BUFFER_TOO_SMALL */
       ((rv = pkd->funcs->C_Decrypt(pkd->session, (CK_BYTE *)from, flen, to, &tlen)) == CKR_OK)) {
        rval = tlen;
    } else {
        return -1;
    }

	return (rval);
}

static RSA_METHOD *get_pkcs11_rsa_method(void) {
	static RSA_METHOD *pkcs11_rsa_method = NULL;
	if(pkcs11_rsa_key_idx == -1) {
		pkcs11_rsa_key_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11_rsa_method == NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100005L        
		const RSA_METHOD *def = RSA_get_default_method();
		pkcs11_rsa_method = calloc(1, sizeof(*pkcs11_rsa_method));
		memcpy(pkcs11_rsa_method, def, sizeof(*pkcs11_rsa_method));
		pkcs11_rsa_method->name = "pkcs11";
		pkcs11_rsa_method->rsa_priv_enc = pkcs11_rsa_private_encrypt;
		pkcs11_rsa_method->rsa_priv_dec = pkcs11_rsa_private_decrypt;
#else
        pkcs11_rsa_method = RSA_meth_dup(RSA_get_default_method());
        RSA_meth_set1_name(pkcs11_rsa_method, "pkcs11");
        RSA_meth_set_priv_enc(pkcs11_rsa_method, pkcs11_rsa_private_encrypt);
        RSA_meth_set_priv_dec(pkcs11_rsa_method, pkcs11_rsa_private_decrypt);
#endif
	}
	return pkcs11_rsa_method;
}

#ifdef ENABLE_PKCS11_ECDSA
static int pkcs11_ecdsa_key_idx = -1;

static ECDSA_SIG *pkcs11_ecdsa_sign(const unsigned char *dgst, int dgst_len,
                                    const BIGNUM *inv, const BIGNUM *rp,
                                    EC_KEY *ecdsa) {
    struct pkcs11_key_data *pkd = NULL;
	CK_MECHANISM mech = {
		CKM_ECDSA, NULL_PTR, 0
	};
	CK_ULONG tlen = 0;
	CK_RV rv;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    pkd = ECDSA_get_ex_data(ecdsa, pkcs11_ecdsa_key_idx);
#else
    pkd = EC_KEY_get_ex_data(ecdsa, pkcs11_ecdsa_key_idx);
#endif
    if((pkd != NULL) &&
       ((rv = pkd->funcs->C_SignInit(pkd->session, &mech, pkd->key)) == CKR_OK)) {
		CK_BYTE_PTR buf = NULL;
        ECDSA_SIG *rval;
        BIGNUM *r, *s;
        int nlen;
        
        /* Make a call to C_Sign to find out the size of the signature */
        rv = pkd->funcs->C_Sign(pkd->session, (CK_BYTE *)dgst, dgst_len, NULL, &tlen);
        if (rv != CKR_OK) {
            return NULL;
        }
        
        if ((buf = malloc(tlen)) == NULL) {
            return NULL;
        }
        
        rv = pkd->funcs->C_Sign(pkd->session, (CK_BYTE *)dgst, dgst_len, buf, &tlen);
        if (rv != CKR_OK) {
            free(buf);
            return NULL;
        }
        
        if ((rval = ECDSA_SIG_new()) != NULL) {
            /* 
             * ECDSA signature is 2 large integers of same size returned
             * concatenated by PKCS#11, we separate them to create an
             * ECDSA_SIG for OpenSSL.
             */
            nlen = tlen / 2;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            ECDSA_SIG_get0(&r, &s, rval);
#else
            r = rval->r;
            s = rval->s;
#endif
            BN_bin2bn(&buf[0], nlen, r);
            BN_bin2bn(&buf[nlen], nlen, s);
        }
        free(buf);
        return rval;
    } else {
        return NULL;
    }
}

static int pkcs11_ecdh_compute_key_common(unsigned char **out, size_t *outlen,
                                          const EC_POINT *point, const EC_KEY *key,
                                          struct pkcs11_key_data *pkd)
{
	int rv = 0;

    if(pkd != NULL) {
        unsigned char oct[256];
        const EC_GROUP *group = EC_KEY_get0_group(key);
        size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), NULL);
        if(len > 0) {
            CK_ECDH1_DERIVE_PARAMS params = { CKD_NULL, 0, NULL, len, oct };
            CK_BBOOL ck_true = TRUE;
            CK_BBOOL ck_false = FALSE;
            CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
            CK_OBJECT_CLASS class = CKO_SECRET_KEY;
            CK_KEY_TYPE type = CKK_GENERIC_SECRET;
            CK_ATTRIBUTE template[] = {
                {CKA_TOKEN,    &ck_false, sizeof(ck_false)},
                {CKA_CLASS,    &class,    sizeof(class)},
                {CKA_KEY_TYPE, &type,     sizeof(type)},
                {CKA_ENCRYPT,  &ck_true,  sizeof(ck_true)},
                {CKA_DECRYPT,  &ck_true,  sizeof(ck_true)}
            };
            CK_MECHANISM mech = {
                CKM_ECDH1_DERIVE, &params, sizeof(params)
            };

            if(pkd->funcs->C_DeriveKey(pkd->session, &mech, pkd->key, template, 5, &derived) == CKR_OK) {
                CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
                if((pkd->funcs->C_GetAttributeValue(pkd->session, derived, &attr, 1) == CKR_OK)
                   && (attr.ulValueLen > 0)
                   && ((attr.pValue = malloc(attr.ulValueLen)) != NULL)) {
                    if(pkd->funcs->C_GetAttributeValue(pkd->session, derived, &attr, 1) == CKR_OK) {
                        *out = attr.pValue;
                        *outlen = attr.ulValueLen;
                        rv = 1;
                    } else {
                        free(attr.pValue);
                    }
                }
                pkd->funcs->C_DestroyObject(pkd->session, derived);
            }
        }
    }
	return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static int pkcs11_ecdh_compute_key(unsigned char **out, size_t *outlen,
                                   const EC_POINT *point, const EC_KEY *key)
{
    return pkcs11_ecdh_compute_key_common(out, outlen, point, key, EC_KEY_get_ex_data(key, pkcs11_ecdsa_key_idx));
}
#else
static int pkcs11_ecdh_compute_key_kdf(void *out, size_t outlen,
                                       const EC_POINT *point, EC_KEY *key,
                                       void *(*KDF)(const void *, size_t, void *, size_t *))
{
	unsigned char *buf = NULL;
	size_t buflen;
	int rv = -1;
    struct pkcs11_key_data *pkd = ECDSA_get_ex_data((EC_KEY *)key, pkcs11_ecdsa_key_idx);
    if(pkcs11_ecdh_compute_key_common(&buf, &buflen, point, key, pkd)) {
        if(KDF && KDF(buf, buflen, out, &outlen)) {
            rv = outlen;
        } else {
            if(outlen > buflen) {
                outlen = buflen;
            }
            memcpy(out, buf, outlen);
            rv = outlen;
        }
    }
    free(buf);
    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static ECDSA_METHOD *get_pkcs11_ecdsa_method(void) {
	static ECDSA_METHOD *pkcs11_ecdsa_method = NULL;
	if(pkcs11_ecdsa_key_idx == -1) {
		pkcs11_ecdsa_key_idx = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11_ecdsa_method == NULL) {
		const ECDSA_METHOD *def = ECDSA_get_default_method();
#ifdef ECDSA_F_ECDSA_METHOD_NEW
		pkcs11_ecdsa_method = ECDSA_METHOD_new((ECDSA_METHOD *)def);
		ECDSA_METHOD_set_name(pkcs11_ecdsa_method, "pkcs11");
		ECDSA_METHOD_set_sign(pkcs11_ecdsa_method, pkcs11_ecdsa_sign);
#else
		pkcs11_ecdsa_method = calloc(1, sizeof(*pkcs11_ecdsa_method));
		memcpy(pkcs11_ecdsa_method, def, sizeof(*pkcs11_ecdsa_method));
		pkcs11_ecdsa_method->name = "pkcs11";
		pkcs11_ecdsa_method->ecdsa_do_sign = pkcs11_ecdsa_sign;
#endif
	}
	return pkcs11_ecdsa_method;
}

struct ecdh_method {
    const char *name;
    int (*compute_key) (void *key, size_t outlen, const EC_POINT *pub_key,
                        EC_KEY *ecdh, void *(*KDF) (const void *in,
                                                    size_t inlen, void *out,
                                                    size_t *outlen));
    int flags;
    char *app_data;
};

static ECDH_METHOD *get_pkcs11_ecdh_method(void) {
	static ECDH_METHOD *pkcs11_ecdh_method = NULL;
	if(pkcs11_ecdsa_key_idx == -1) {
		pkcs11_ecdsa_key_idx = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11_ecdh_method == NULL) {
		const ECDH_METHOD *def = ECDH_get_default_method();
		pkcs11_ecdh_method = calloc(1, sizeof(struct ecdh_method));
		memcpy(pkcs11_ecdh_method, def, sizeof(struct ecdh_method));
		pkcs11_ecdh_method->name = "pkcs11";
		pkcs11_ecdh_method->compute_key = pkcs11_ecdh_compute_key_kdf;
	}
	return pkcs11_ecdh_method;
}

#else
static EC_KEY_METHOD *get_pkcs11_ec_method(void) {
	static EC_KEY_METHOD *pkcs11_ec_method = NULL;
	if(pkcs11_ecdsa_key_idx == -1) {
		pkcs11_ecdsa_key_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11_ec_method == NULL) {
        int (*sig)(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
                    unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey) = NULL;
		pkcs11_ec_method = EC_KEY_METHOD_new(EC_KEY_get_default_method());
        EC_KEY_METHOD_get_sign(pkcs11_ec_method, &sig, NULL, NULL);
		EC_KEY_METHOD_set_sign(pkcs11_ec_method, sig, NULL, pkcs11_ecdsa_sign);
        EC_KEY_METHOD_set_compute_key(pkcs11_ec_method, pkcs11_ecdh_compute_key);
	}
	return pkcs11_ec_method;
}
#endif

#endif

EVP_PKEY *load_pkcs11_key(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_ULONG kt, class;
    CK_ATTRIBUTE key_type[] = {
        { CKA_CLASS,    &class, sizeof(class) },
        { CKA_KEY_TYPE, &kt,    sizeof(kt)    }
    };
    struct pkcs11_key_data *pkd = NULL;
    EVP_PKEY *k = NULL;
    CK_RV rv;
    
    pkd = malloc(sizeof(struct pkcs11_key_data));
    rv = funcs->C_GetAttributeValue(session, key, key_type, 2);
    if(pkd == NULL || rv != CKR_OK || class != CKO_PRIVATE_KEY) {
        return k;
    }

    pkd->funcs = funcs;
    pkd->session = session;
    pkd->key = key;

    if(kt == CKK_RSA) {
        CK_ATTRIBUTE rsa_attributes[] = {
            { CKA_MODULUS, NULL, 0 },
            { CKA_PUBLIC_EXPONENT, NULL, 0 }
        };
        RSA *rsa = RSA_new();

        if(((rv = funcs->C_GetAttributeValue(session, key, rsa_attributes, 2)) == CKR_OK) &&
           (rsa_attributes[0].ulValueLen > 0) && (rsa_attributes[1].ulValueLen > 0) &&
           ((rsa_attributes[0].pValue = malloc(rsa_attributes[0].ulValueLen)) != NULL) &&
           ((rsa_attributes[1].pValue = malloc(rsa_attributes[1].ulValueLen)) != NULL) &&
           ((rv = funcs->C_GetAttributeValue(session, key, rsa_attributes, 2)) == CKR_OK) && 
           (rsa != NULL)) {
#if OPENSSL_VERSION_NUMBER < 0x10100005L
            rsa->n = BN_bin2bn(rsa_attributes[0].pValue,
                               rsa_attributes[0].ulValueLen, NULL);
            rsa->e = BN_bin2bn(rsa_attributes[1].pValue,
                               rsa_attributes[1].ulValueLen, NULL);
            rsa->d = BN_dup(BN_value_one());
            rsa->p = BN_dup(BN_value_one());
            rsa->q = BN_dup(BN_value_one());
            rsa->dmp1 = BN_dup(BN_value_one());
            rsa->dmq1 = BN_dup(BN_value_one());
            rsa->iqmp = BN_dup(BN_value_one());
#else
            RSA_set0_key(rsa,
                         BN_bin2bn(rsa_attributes[0].pValue,
                                   rsa_attributes[0].ulValueLen, NULL),
                         BN_bin2bn(rsa_attributes[1].pValue,
                                   rsa_attributes[1].ulValueLen, NULL),
                         NULL);
#endif
            
            if((k = EVP_PKEY_new()) != NULL) {
                RSA_set_method(rsa, get_pkcs11_rsa_method());
                RSA_set_ex_data(rsa, pkcs11_rsa_key_idx, pkd);
                EVP_PKEY_set1_RSA(k, rsa);
            }
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
            ((rv = funcs->C_GetAttributeValue(session, pub, ecdsa_attributes, 2)) == CKR_OK) &&
            ((ecdsa_attributes[0].pValue = malloc(ecdsa_attributes[0].ulValueLen)) != NULL) &&
            ((ecdsa_attributes[1].pValue = malloc(ecdsa_attributes[1].ulValueLen)) != NULL) &&
            ((rv = funcs->C_GetAttributeValue(session, pub, ecdsa_attributes, 2)) == CKR_OK)) {
            const unsigned char *ptr1 = ecdsa_attributes[0].pValue;
            const unsigned char *ptr2 = ecdsa_attributes[1].pValue;
            CK_ULONG len1 = ecdsa_attributes[0].ulValueLen;
            CK_ULONG len2 = ecdsa_attributes[1].ulValueLen;
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
                ptr2 = ecdsa_attributes[1].pValue;
            }

            if((d2i_ECParameters(&ecdsa, &ptr1, len1) == NULL) ||
               (o2i_ECPublicKey(&ecdsa, &ptr2, len2) == NULL)) {
                EC_KEY_free(ecdsa);
                ecdsa = NULL;
            }

            EC_KEY_set_private_key(ecdsa, BN_value_one());
            
            if(point) {
                ASN1_STRING_free(point);
            }

            if(ecdsa) {
                if((k = EVP_PKEY_new()) != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                    ECDSA_set_method(ecdsa, get_pkcs11_ecdsa_method());
                    ECDH_set_method(ecdsa, get_pkcs11_ecdh_method());
                    ECDSA_set_ex_data(ecdsa, pkcs11_ecdsa_key_idx, pkd);
#else
                    EC_KEY_set_method(ecdsa, get_pkcs11_ec_method());
                    EC_KEY_set_ex_data(ecdsa, pkcs11_ecdsa_key_idx, pkd);
#endif                    
                    EVP_PKEY_set1_EC_KEY(k, ecdsa);
                }
            }
        }

        free(ecdsa_public[0].pValue);
        free(ecdsa_attributes[0].pValue);
        free(ecdsa_attributes[1].pValue);
#endif
    }

    return k;
}

void unload_pkcs11_key(EVP_PKEY *k)
{
    if(k) {
        struct pkcs11_key_data *pkd = NULL;
        int t = EVP_PKEY_id(k);
        if(t == EVP_PKEY_RSA) {
            pkd = RSA_get_ex_data(EVP_PKEY_get1_RSA(k), pkcs11_rsa_key_idx);
#ifdef ENABLE_PKCS11_ECDSA
        } else if(t == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            pkd = ECDSA_get_ex_data(EVP_PKEY_get1_EC_KEY(k), pkcs11_ecdsa_key_idx);
#else
            pkd = EC_KEY_get_ex_data(EVP_PKEY_get1_EC_KEY(k), pkcs11_ecdsa_key_idx);
#endif
#endif
        }
        free(pkd);
        EVP_PKEY_free(k);
    }
}
#else

void init_crypto()
{
}

#endif
