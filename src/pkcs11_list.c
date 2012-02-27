/*
 * Copyright (C) 2011 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <unistd.h>
#include <getopt.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

#include "pkcs11_util.h"
#include "pkcs11_display.h"

void fillAttribute(CK_ATTRIBUTE *attr, CK_ATTRIBUTE_TYPE type,
			  CK_VOID_PTR pvoid, CK_ULONG ulong)
{
	attr->type = type;
	attr->pValue =  pvoid;
	attr->ulValueLen = ulong;
}

CK_RV setKeyId(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session,
               CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey,
               CK_ATTRIBUTE_PTR attrs)
{
	CK_RV rv = CKR_HOST_MEMORY;
    CK_BYTE *tmp = NULL;
    CK_ATTRIBUTE kid[1];

    if ((tmp = (CK_BYTE *)malloc(SHA_DIGEST_LENGTH)) != NULL) {
        SHA1((unsigned char*)attrs[0].pValue, attrs[0].ulValueLen, tmp);
        kid[0].type = CKA_ID;
        kid[0].pValue = tmp;
        kid[0].ulValueLen = SHA_DIGEST_LENGTH;

        rv = p11->C_SetAttributeValue(session, hPublicKey , kid, 1);

        if(rv != CKR_OK) {
            free(tmp);
            show_error(stdout, "C_SetAttributeValue", rv );
            goto done;
        }
        rv = p11->C_SetAttributeValue(session, hPrivateKey, kid, 1);
        free(tmp);
        if(rv != CKR_OK) {
            show_error(stdout, "C_SetAttributeValue", rv );
            goto done;
        }
    }

 done:
	return rv;
}

CK_RV generateRsaKeyPair(CK_FUNCTION_LIST_PTR p11,
                         CK_SESSION_HANDLE session,
                         CK_ULONG size)
{
	CK_RV rv = CKR_HOST_MEMORY;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_BYTE exponent[3] = { 0x01, 0x00, 0x01 };
    CK_BBOOL t = TRUE;
    CK_ATTRIBUTE attrs[2];
    CK_OBJECT_CLASS	prv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pub = CKO_PUBLIC_KEY;
    CK_KEY_TYPE type = CKK_RSA;
    CK_ATTRIBUTE publicKeyTemplate[8] = {
        { CKA_CLASS ,          &pub,      sizeof(pub)      },
        { CKA_KEY_TYPE,        &type,     sizeof(type)     },
        { CKA_TOKEN,           &t,        sizeof(CK_BBOOL) },
        { CKA_ENCRYPT,         &t,        sizeof(CK_BBOOL) },
        { CKA_VERIFY,          &t,        sizeof(CK_BBOOL) },
        { CKA_WRAP,            &t,        sizeof(CK_BBOOL) },
        { CKA_MODULUS_BITS,    &size,     sizeof(size)     },
        { CKA_PUBLIC_EXPONENT, &exponent, sizeof(exponent) },
    };
    CK_ATTRIBUTE privateKeyTemplate[8] = {
        { CKA_CLASS,      &prv,       sizeof(prv)       },
        { CKA_KEY_TYPE,   &type,      sizeof(type)      },
        { CKA_TOKEN,      &t,         sizeof(CK_BBOOL)  },
        { CKA_PRIVATE,    &t,         sizeof(CK_BBOOL)  },
        { CKA_SENSITIVE,  &t,         sizeof(CK_BBOOL)  },
        { CKA_DECRYPT,    &t,         sizeof(CK_BBOOL)  },
        { CKA_SIGN,       &t,         sizeof(CK_BBOOL)  },
        { CKA_UNWRAP,     &t,         sizeof(CK_BBOOL)  },
    };

	if(!p11) {
        goto done;
    }

    if((rv = p11->C_GenerateKeyPair
        (session, &mechanism, publicKeyTemplate, 8,
         privateKeyTemplate, 8, &hPublicKey, &hPrivateKey)) != CKR_OK ) {
        show_error(stdout, "C_GenerateKeyPair", rv );
        goto done;
    }

    if((hPublicKey  == CK_INVALID_HANDLE) ||
       (hPrivateKey == CK_INVALID_HANDLE)) {
        rv = CKR_HOST_MEMORY; /* */
        show_error(stdout, "C_GenerateKeyPair", rv );
        goto done;
    }

    fillAttribute(&attrs[0], CKA_PUBLIC_EXPONENT, NULL, 0);
    fillAttribute(&attrs[1], CKA_MODULUS,         NULL, 0);

    if ((rv = p11->C_GetAttributeValue
         (session, hPublicKey, attrs, 2)) != CKR_OK) {
        show_error(stdout, "C_GetAttributeValue", rv );
        goto done;
    }

    if (((attrs[0].pValue = malloc(attrs[0].ulValueLen)) == NULL) ||
        ((attrs[1].pValue = malloc(attrs[1].ulValueLen)) == NULL)) {
        rv = CKR_HOST_MEMORY;
        show_error(stdout, "C_GetAttributeValue", rv );
        goto done;
    }

    if ((rv = p11->C_GetAttributeValue
         (session, hPublicKey, attrs, 2)) != CKR_OK) {
        show_error(stdout, "C_GetAttributeValue", rv );
        goto done;
    }

    rv = setKeyId(p11, session, hPublicKey, hPrivateKey, attrs);

 done:
	return rv;
}

static unsigned char prime256v1_oid[] = { 0x06, 0x08, 0x2a, 0x86, 0x48,
                                          0xce, 0x3d, 0x03, 0x01, 0x07 };
static unsigned char prime256v1_full[] =
    { 0x30,0x81,0xf7,0x02,0x01,0x01,0x30,0x2c,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x01,
      0x01,0x02,0x21,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0x30,0x5b,0x04,0x20,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,0x04,0x20,0x5a,0xc6,0x35,0xd8,0xaa,0x3a,
      0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,0x65,0x1d,0x06,0xb0,0xcc,0x53,
      0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b,0x03,0x15,0x00,0xc4,0x9d,0x36,
      0x08,0x86,0xe7,0x04,0x93,0x6a,0x66,0x78,0xe1,0x13,0x9d,0x26,0xb7,0x81,0x9f,0x7e,
      0x90,0x04,0x41,0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,
      0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,
      0xd8,0x98,0xc2,0x96,0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,
      0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,
      0x37,0xbf,0x51,0xf5,0x02,0x21,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,
      0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51,0x02,0x01,0x01 };

static unsigned char secp384r1_oid[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static unsigned char secp384r1_full[] =
    { 0x30,0x82,0x01,0x57,0x02,0x01,0x01,0x30,0x3c,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,
      0x01,0x01,0x02,0x31,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0xff,0xff,0xff,0xff,0x30,0x7b,0x04,0x30,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xfc,0x04,0x30,0xb3,0x31,0x2f,0xa7,0xe2,
      0x3e,0xe7,0xe4,0x98,0x8e,0x05,0x6b,0xe3,0xf8,0x2d,0x19,0x18,0x1d,0x9c,0x6e,0xfe,
      0x81,0x41,0x12,0x03,0x14,0x08,0x8f,0x50,0x13,0x87,0x5a,0xc6,0x56,0x39,0x8d,0x8a,
      0x2e,0xd1,0x9d,0x2a,0x85,0xc8,0xed,0xd3,0xec,0x2a,0xef,0x03,0x15,0x00,0xa3,0x35,
      0x92,0x6a,0xa3,0x19,0xa2,0x7a,0x1d,0x00,0x89,0x6a,0x67,0x73,0xa4,0x82,0x7a,0xcd,
      0xac,0x73,0x04,0x61,0x04,0xaa,0x87,0xca,0x22,0xbe,0x8b,0x05,0x37,0x8e,0xb1,0xc7,
      0x1e,0xf3,0x20,0xad,0x74,0x6e,0x1d,0x3b,0x62,0x8b,0xa7,0x9b,0x98,0x59,0xf7,0x41,
      0xe0,0x82,0x54,0x2a,0x38,0x55,0x02,0xf2,0x5d,0xbf,0x55,0x29,0x6c,0x3a,0x54,0x5e,
      0x38,0x72,0x76,0x0a,0xb7,0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,0x98,
      0xbf,0x92,0x92,0xdc,0x29,0xf8,0xf4,0x1d,0xbd,0x28,0x9a,0x14,0x7c,0xe9,0xda,0x31,
      0x13,0xb5,0xf0,0xb8,0xc0,0x0a,0x60,0xb1,0xce,0x1d,0x7e,0x81,0x9d,0x7a,0x43,0x1d,
      0x7c,0x90,0xea,0x0e,0x5f,0x02,0x31,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xc7,0x63,0x4d,0x81,0xf4,0x37,0x2d,0xdf,0x58,0x1a,0x0d,0xb2,0x48,0xb0,0xa7,0x7a,
      0xec,0xec,0x19,0x6a,0xcc,0xc5,0x29,0x73,0x02,0x01,0x01 };

static unsigned char secp521r1_oid[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
static unsigned char secp521r1_full[] =
    { 0x30,0x82,0x01,0xc2,0x02,0x01,0x01,0x30,0x4d,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,
      0x01,0x01,0x02,0x42,0x01,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0x30,0x81,0x9e,0x04,0x42,0x01,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,0x04,0x41,0x51,
      0x95,0x3e,0xb9,0x61,0x8e,0x1c,0x9a,0x1f,0x92,0x9a,0x21,0xa0,0xb6,0x85,0x40,0xee,
      0xa2,0xda,0x72,0x5b,0x99,0xb3,0x15,0xf3,0xb8,0xb4,0x89,0x91,0x8e,0xf1,0x09,0xe1,
      0x56,0x19,0x39,0x51,0xec,0x7e,0x93,0x7b,0x16,0x52,0xc0,0xbd,0x3b,0xb1,0xbf,0x07,
      0x35,0x73,0xdf,0x88,0x3d,0x2c,0x34,0xf1,0xef,0x45,0x1f,0xd4,0x6b,0x50,0x3f,0x00,
      0x03,0x15,0x00,0xd0,0x9e,0x88,0x00,0x29,0x1c,0xb8,0x53,0x96,0xcc,0x67,0x17,0x39,
      0x32,0x84,0xaa,0xa0,0xda,0x64,0xba,0x04,0x81,0x85,0x04,0x00,0xc6,0x85,0x8e,0x06,
      0xb7,0x04,0x04,0xe9,0xcd,0x9e,0x3e,0xcb,0x66,0x23,0x95,0xb4,0x42,0x9c,0x64,0x81,
      0x39,0x05,0x3f,0xb5,0x21,0xf8,0x28,0xaf,0x60,0x6b,0x4d,0x3d,0xba,0xa1,0x4b,0x5e,
      0x77,0xef,0xe7,0x59,0x28,0xfe,0x1d,0xc1,0x27,0xa2,0xff,0xa8,0xde,0x33,0x48,0xb3,
      0xc1,0x85,0x6a,0x42,0x9b,0xf9,0x7e,0x7e,0x31,0xc2,0xe5,0xbd,0x66,0x01,0x18,0x39,
      0x29,0x6a,0x78,0x9a,0x3b,0xc0,0x04,0x5c,0x8a,0x5f,0xb4,0x2c,0x7d,0x1b,0xd9,0x98,
      0xf5,0x44,0x49,0x57,0x9b,0x44,0x68,0x17,0xaf,0xbd,0x17,0x27,0x3e,0x66,0x2c,0x97,
      0xee,0x72,0x99,0x5e,0xf4,0x26,0x40,0xc5,0x50,0xb9,0x01,0x3f,0xad,0x07,0x61,0x35,
      0x3c,0x70,0x86,0xa2,0x72,0xc2,0x40,0x88,0xbe,0x94,0x76,0x9f,0xd1,0x66,0x50,0x02,
      0x42,0x01,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xfa,0x51,0x86,0x87,0x83,0xbf,0x2f,0x96,0x6b,0x7f,0xcc,0x01,0x48,0xf7,
      0x09,0xa5,0xd0,0x3b,0xb5,0xc9,0xb8,0x89,0x9c,0x47,0xae,0xbb,0x6f,0xb7,0x1e,0x91,
      0x38,0x64,0x09,0x02,0x01,0x01 };

CK_RV ecdsaNeedsEcParams(CK_FUNCTION_LIST *funcs,
                         CK_SLOT_ID slot_id, CK_BBOOL *full)
{
    CK_RV             rc;
    CK_MECHANISM_INFO minfo;

    rc = funcs->C_GetMechanismInfo(slot_id, CKM_EC_KEY_PAIR_GEN, &minfo);
    if(rc != CKR_OK) {
        show_error(stdout, "C_GetMechanismInfo", rc );
        goto done;
    }

    if(!(minfo.flags & CKF_EC_F_P)) {
        rc = CKR_DOMAIN_PARAMS_INVALID;
        show_error(stdout, "C_GetMechanismInfo", rc );
        goto done;
    }

    if(minfo.flags & (CKF_EC_ECPARAMETERS|CKF_EC_NAMEDCURVE)) {
        *full = minfo.flags & CKF_EC_NAMEDCURVE ? CK_FALSE : CK_TRUE;
    } else {
        rc = CKR_DOMAIN_PARAMS_INVALID;
    }

 done:
    return rc;
}

CK_RV generateEcdsaKeyPair(CK_FUNCTION_LIST_PTR p11,
                           CK_SESSION_HANDLE session,
                           char *name, CK_BBOOL full)
{
	CK_RV rv = CKR_HOST_MEMORY;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_MECHANISM mechanism = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_BBOOL t = TRUE;
    CK_ATTRIBUTE attrs[1];
    CK_ATTRIBUTE pubTemplate[2] = {
        { CKA_EC_PARAMS,  NULL, 0                 },
        { CKA_TOKEN,      &t,   sizeof(CK_BBOOL)  }
    };
    CK_ATTRIBUTE privTemplate[5] = {
        { CKA_EC_PARAMS,  NULL, 0                 },
        { CKA_TOKEN,      &t,   sizeof(CK_BBOOL)  },
        { CKA_PRIVATE,    &t,   sizeof(CK_BBOOL)  },
        { CKA_SENSITIVE,  &t,   sizeof(CK_BBOOL)  },
        { CKA_SIGN,       &t,   sizeof(CK_BBOOL)  }
    };

	if(!p11) {
        goto done;
    }

    if(!name) {
        rv = CKR_DOMAIN_PARAMS_INVALID;
        goto done;
    } else if(!strcmp(name, "prime256v1") || !strcmp(name, "secp256r1") ||
              !strcmp(name, "nistp256") ||  !strcmp(name, "ansiX9p256r1")) {
        privTemplate[0].pValue = full ? prime256v1_full : prime256v1_oid;
        privTemplate[0].ulValueLen = full ?
            sizeof(prime256v1_full) : sizeof(prime256v1_oid);
    } else if(!strcmp(name, "secp384r1") || !strcmp(name, "prime384v1") ||
              !strcmp(name, "nistp384") || !strcmp(name, "ansiX9p384r1")) {
        privTemplate[0].pValue = full ? secp384r1_full : secp384r1_oid;
        privTemplate[0].ulValueLen = full ?
            sizeof(secp384r1_full) : sizeof(secp384r1_oid);
    } else if(!strcmp(name, "secp521r1") || !strcmp(name, "prime521v1") ||
              !strcmp(name, "nistp521") || !strcmp(name, "ansiX9p521r1")) {
        privTemplate[0].pValue = full ? secp521r1_full : secp521r1_oid;
        privTemplate[0].ulValueLen = full ?
            sizeof(secp521r1_full) : sizeof(secp521r1_oid);
    } else {
        rv = CKR_DOMAIN_PARAMS_INVALID;
        goto done;
    }
    pubTemplate[0].pValue = privTemplate[0].pValue;
    pubTemplate[0].ulValueLen = privTemplate[0].ulValueLen;

    if((rv = p11->C_GenerateKeyPair
        (session, &mechanism, pubTemplate, 2,
         privTemplate, 5, &hPublicKey, &hPrivateKey)) != CKR_OK ) {
        show_error(stdout, "C_GenerateKeyPair", rv );
        goto done;
    }

    if((hPublicKey  == CK_INVALID_HANDLE) ||
       (hPrivateKey == CK_INVALID_HANDLE)) {
        rv = CKR_HOST_MEMORY; /* Maybe there's something clearer */
        show_error(stdout, "C_GenerateKeyPair", rv );
        goto done;
    }

    fillAttribute(&attrs[0], CKA_EC_POINT, NULL, 0);
    if ((rv = p11->C_GetAttributeValue
         (session, hPublicKey, attrs, 1)) != CKR_OK) {
        show_error(stdout, "C_GetAttributeValue", rv );
        goto done;
    }

    if (((attrs[0].pValue = malloc(attrs[0].ulValueLen)) == NULL)) {
        rv = CKR_HOST_MEMORY;
        show_error(stdout, "C_GetAttributeValue", rv );
        goto done;
    }

    if ((rv = p11->C_GetAttributeValue
         (session, hPublicKey, attrs, 1)) != CKR_OK) {
        show_error(stdout, "C_GetAttributeValue", rv );
        goto done;
    }

    rv = setKeyId(p11, session, hPublicKey, hPrivateKey, attrs);

 done:
	return rv;
}

int do_list_token_objects(CK_FUNCTION_LIST *funcs,
                          CK_SLOT_ID        SLOT_ID,
                          CK_BYTE          *user_pin,
                          CK_ULONG          user_pin_len)
{
    CK_RV             rc;
    CK_FLAGS          flags;
    CK_ULONG          i, j, k, l;
    CK_SESSION_HANDLE h_session;
    CK_OBJECT_HANDLE  obj;

    if(user_pin) {
        /* create a USER/SO R/W session */
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            rc = FALSE;
            goto done;
        }

        rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
        if (rc != CKR_OK) {
            show_error(stdout, "C_Login", rc );
            rc = FALSE;
            goto done;
        }
    } else {
        /* create a Public R/W session */
        flags = CKF_SERIAL_SESSION;
        rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            rc = FALSE;
            goto done;
        }
    }

    rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc );
        rc = FALSE;
        goto done;
    }

    j = 0;

    do {
        rc = funcs->C_FindObjects( h_session, &obj, 1, &i );
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjects", rc );
            rc = FALSE;
            goto done;
        }
        if(i) {
            CK_ATTRIBUTE attribute;

            rc = funcs->C_GetObjectSize( h_session, obj, &k );
            if (rc != CKR_OK) {
                if(rc != CKR_FUNCTION_NOT_SUPPORTED) {
                    show_error(stdout, "C_GetObjectSize", rc );
                    rc = FALSE;
                    goto done;
                }
                printf("----------------\nObject %ld\n", j);
            } else {
                printf("----------------\nObject %ld has size %ld\n", j, k);
            }

            j++;

            for(k = 0, l = 0; k < ck_attribute_num; k++) {
                attribute.type = ck_attribute_specs[k].type;
                attribute.pValue = NULL;
                attribute.ulValueLen = 0;

                rc = funcs->C_GetAttributeValue( h_session, obj, &attribute, 1);
                if ((rc == CKR_OK) && ((CK_LONG)attribute.ulValueLen != -1)) {
                    attribute.pValue = (CK_VOID_PTR) malloc(attribute.ulValueLen);

                    rc = funcs->C_GetAttributeValue(h_session, obj, &attribute, 1);
                    if (rc == CKR_OK) {
                        printf("(%02ld) %s ", l++, ck_attribute_specs[k].name);

                        ck_attribute_specs[k].display
                            (stdout, attribute.type, attribute.pValue,
                             attribute.ulValueLen, ck_attribute_specs[k].arg);
                    }
                    free(attribute.pValue);
                } else if(rc == CKR_ATTRIBUTE_SENSITIVE) {
                    printf("(%02ld) %s is sensitive\n", l++,
                           ck_attribute_specs[k].name);
                } else if((rc != CKR_ATTRIBUTE_TYPE_INVALID) &&
                          (rc != CKR_TEMPLATE_INCONSISTENT)) {
                    show_error(stdout, "C_GetAttributeValue", rc );
                    rc = FALSE;
                    goto done;
                }
            }
        }
    } while (i);

    rc = funcs->C_FindObjectsFinal( h_session );
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc );
        rc = FALSE;
        goto done;
    }

    printf("Found: %ld objects\n", j);
    rc = TRUE;

 done:
    if(user_pin) {
        funcs->C_CloseAllSessions( SLOT_ID );
    }
    return rc;
}

int do_GetSlotInfo(CK_FUNCTION_LIST *funcs,
                   CK_SLOT_ID slot_id)
{
    CK_SLOT_INFO  info;
    CK_RV         rc;

    rc = funcs->C_GetSlotInfo( slot_id, &info );
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc );
        return FALSE;
    }

    printf("CK_SLOT_INFO for slot #%ld:  \n", slot_id);
    print_slot_info(stdout, &info);
    printf("\n\n");

    return TRUE;
}

int do_GetTokenInfo(CK_FUNCTION_LIST *funcs,
                    CK_SLOT_ID slot_id)
{
    CK_TOKEN_INFO  info;
    CK_RV          rc;

    rc = funcs->C_GetTokenInfo( slot_id, &info );
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc );
        return FALSE;
    }

    printf("CK_TOKEN_INFO for slot #%ld:  \n", slot_id);
    print_token_info(stdout, &info);
    printf("\n\n");

    return TRUE;
}

int do_GetTokenMech(CK_FUNCTION_LIST *funcs,
                    CK_SLOT_ID slot_id)
{
    CK_RV             rc;
    CK_MECHANISM_INFO minfo;
    CK_MECHANISM_TYPE_PTR pMechanismList;
    CK_ULONG          imech, ulMechCount;

    rc = funcs->C_GetMechanismList(slot_id, NULL, &ulMechCount);

    pMechanismList = (CK_MECHANISM_TYPE *) malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE));
    if (!pMechanismList) {
        fprintf(stderr, "Failed on line %d\n", __LINE__);
        return CKR_HOST_MEMORY;
    }

    rc = funcs->C_GetMechanismList(slot_id, pMechanismList, &ulMechCount);
    if (rc != CKR_OK) {
        show_error(stdout, "C_GetMechanismList", rc );
        return rc;
    }

    for (imech = 0; imech < ulMechCount; imech++) {
        rc = funcs->C_GetMechanismInfo(slot_id, pMechanismList[imech], &minfo);
        print_mech_info(stdout, pMechanismList[imech], &minfo);
    }

    free(pMechanismList);
    return rc;
}

char *app_name = "obj_list";

const struct option options[] = {
    { "show-info",          0, 0,           'I' },
    { "list-slots",         0, 0,           'L' },
    { "list-mechanisms",    0, 0,           'M' },
    { "list-objects",       0, 0,           'O' },
    { "help",               0, 0,           'h' },
    { "login",              0, 0,           'l' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "genkey",             1, 0,           'g' },
    { 0, 0, 0, 0 }
};

const char *option_help[] = {
    "Show global token information",
    "List slots available on the token",
    "List mechanisms supported by the token",
    "List objects contained in the token",
    "Print this help and exit",
    "Log into the token first (not needed when using --pin)",
    "Supply PIN on the command line (if used in scripts: careful!)",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Generate key",
};

void print_usage_and_die(void)
{
    int i = 0;
    printf("Usage: %s [OPTIONS]\nOptions:\n", app_name);

    while (options[i].name) {
        char buf[40], tmp[5];
        const char *arg_str;

        /* Skip "hidden" options */
        if (option_help[i] == NULL) {
            i++;
            continue;
        }

        if (options[i].val > 0 && options[i].val < 128)
            sprintf(tmp, ", -%c", options[i].val);
        else
            tmp[0] = 0;
        switch (options[i].has_arg) {
            case 1:
                arg_str = " <arg>";
                break;
            case 2:
                arg_str = " [arg]";
                break;
            default:
                arg_str = "";
                break;
        }
        sprintf(buf, "--%s%s%s", options[i].name, tmp, arg_str);
        if (strlen(buf) > 29) {
            printf("  %s\n", buf);
            buf[0] = '\0';
        }
        printf("  %-29s %s\n", buf, option_help[i]);
        i++;
    }
    exit(2);
}

#define NEED_SESSION_RO 0x01
#define NEED_SESSION_RW 0x02

int main( int argc, char **argv )
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_BYTE           opt_pin[20] = "";
    CK_INFO           info;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL;
    char *gen_param = NULL;
    int long_optind = 0;
    int do_show_info = 0;
    int do_list_slots = 0;
    int do_list_mechs = 0;
    int do_list_objects = 0;
    int need_session = 0;
    int opt_login = 0;
    int action_count = 0;
    int genkey = 0;

    char c;

    if((argc == 2) && ((opt_pin_len = strlen(argv[1])) < 20)) {
        memcpy( opt_pin, argv[1] , opt_pin_len );
    } else {
        opt_pin_len = 0;
    }

#ifdef HAVE_OPENSSL
    if (OPENSSL_VERSION_NUMBER > 0x00907000L) {
        OpenSSL_add_all_algorithms();
    } else {
        OPENSSL_add_all_algorithms_noconf();
    }
#endif

    while (1) {
        c = getopt_long(argc, argv, "ILMOhlp:s:g:m:",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'I':
                do_show_info = 1;
                action_count++;
                break;
            case 'L':
                do_list_slots = 1;
                action_count++;
                break;
            case 'M':
                do_list_mechs = 1;
                action_count++;
                break;
            case 'O':
                need_session |= NEED_SESSION_RO;
                do_list_objects = 1;
                action_count++;
                break;
            case 'l':
                need_session |= NEED_SESSION_RW;
                opt_login = 1;
                break;
            case 'p':
                need_session |= NEED_SESSION_RW;
                opt_login = 1;
                opt_pin_len = strlen(optarg);
                opt_pin_len = (opt_pin_len < 20) ? opt_pin_len : 19;
                memcpy( opt_pin, optarg, opt_pin_len );
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'g':
                need_session |= NEED_SESSION_RW;
                gen_param = optarg;
                genkey = 1;
                break;
            case 'h':
            default:
                print_usage_and_die();
        }
    }

    funcs = pkcs11_get_function_list( opt_module );
    if (!funcs) {
        printf("Could not get function list.\n");
        return -1;
    }

    rc = pkcs11_initialize(funcs);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Initialize", rc );
        return rc;
    }

    if(do_show_info) {
        rc = funcs->C_GetInfo(&info);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GetInfo", rc );
            return rc;
        } else {
            print_ck_info(stdout,&info);
        }
    }

    if(opt_slot != -1) {
        pslots = &opt_slot;
        nslots = 1;
    } else {
        if(do_list_slots) {
            rc = funcs->C_GetSlotList(0, NULL_PTR, &nslots);
            if (rc != CKR_OK) {
                show_error(stdout, "C_GetSlotList", rc );
                return rc;
            }
            pslots = malloc(sizeof(CK_SLOT_ID) * nslots);
            rc = funcs->C_GetSlotList(0, pslots, &nslots);
            if (rc != CKR_OK) {
                show_error(stdout, "C_GetSlotList", rc );
                return rc;
            }
        }
    }

    for (islot = 0; islot < nslots; islot++) {
        if (do_list_slots) {
            do_GetSlotInfo(funcs, pslots[islot]);
            do_GetTokenInfo(funcs, pslots[islot]);
        }
        if(do_list_mechs) {
            do_GetTokenMech(funcs, pslots[islot]);
        }

        if(do_list_objects) {
            if(opt_pin_len) {
                do_list_token_objects(funcs, pslots[islot],
                                      opt_pin, opt_pin_len);
            } else {
                do_list_token_objects(funcs, pslots[islot], NULL, 0);
            }
        }
        if(genkey) {
            char             *tmp;
            long              keysize;
            CK_SESSION_HANDLE h_session;
            CK_FLAGS          flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
            rc = funcs->C_OpenSession( pslots[islot], flags, NULL, NULL, &h_session );
            if(opt_pin_len) {
                rc = funcs->C_Login( h_session, CKU_USER, opt_pin, opt_pin_len );
            }
            fprintf(stdout, "Generating key with param '%s'\n", gen_param);
            keysize = strtol(gen_param, &tmp, 10);
            if(gen_param != tmp) {
                fprintf(stdout, "Generating RSA key with size %ld\n", keysize);
                rc = generateRsaKeyPair(funcs, h_session, keysize);
            } else {
                CK_BBOOL full;
                rc = ecdsaNeedsEcParams(funcs, pslots[islot], &full);
                if(rc == CKR_OK) {
                    fprintf(stdout, "Generating ECDSA key with curve '%s' "
                            "in slot %ld with %s\n", gen_param, pslots[islot],
                            full ? "EC Parameters" : "Named Curve");
                    rc = generateEcdsaKeyPair(funcs, h_session, gen_param, full);
                }
            }
        }
    }

    rc = funcs->C_Finalize( NULL );
    return rc;
}
