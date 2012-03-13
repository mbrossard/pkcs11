/*
 * Copyright (C) 2011 Mathias Brossard <mathias@brossard.org>
 */

#ifdef HAVE_OPENSSL
#include <openssl/x509.h>
#endif
#include "pkcs11_display.h"

/* Historical Netscape */
#define CKM_NETSCAPE_PBE_SHA1_DES_CBC         0x80000002
#define CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC  0x80000003
#define CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC  0x80000004
#define CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC 0x80000005
#define CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4      0x80000006
#define CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4     0x80000007
#define CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC 0x80000008
#define CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN    0x80000009
#define CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN     0x8000000a
#define CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN     0x8000000b
#define CKM_TLS_PRF_GENERAL                   0x80000373

/* FAKE PKCS #11 defines */
#define NSSCK_VENDOR_NSS            0x4E534350 /* NSCP */
#define CKM_FAKE_RANDOM             0x80000efeUL
#define CKM_INVALID_MECHANISM       0xffffffffUL
#define CKM_NSS (CKM_VENDOR_DEFINED|NSSCK_VENDOR_NSS)

#define CKM_NSS_AES_KEY_WRAP        (CKM_NSS + 1)
#define CKM_NSS_AES_KEY_WRAP_PAD    (CKM_NSS + 2)
#define CKM_NSS_HKDF_SHA1           (CKM_NSS + 3)
#define CKM_NSS_HKDF_SHA256         (CKM_NSS + 4)
#define CKM_NSS_HKDF_SHA384         (CKM_NSS + 5)
#define CKM_NSS_HKDF_SHA512         (CKM_NSS + 6)
#define CKM_NSS_JPAKE_ROUND1_SHA1   (CKM_NSS + 7)
#define CKM_NSS_JPAKE_ROUND1_SHA256 (CKM_NSS + 8)
#define CKM_NSS_JPAKE_ROUND1_SHA384 (CKM_NSS + 9)
#define CKM_NSS_JPAKE_ROUND1_SHA512 (CKM_NSS + 10)
#define CKM_NSS_JPAKE_ROUND2_SHA1   (CKM_NSS + 11)
#define CKM_NSS_JPAKE_ROUND2_SHA256 (CKM_NSS + 12)
#define CKM_NSS_JPAKE_ROUND2_SHA384 (CKM_NSS + 13)
#define CKM_NSS_JPAKE_ROUND2_SHA512 (CKM_NSS + 14)
#define CKM_NSS_JPAKE_FINAL_SHA1    (CKM_NSS + 15)
#define CKM_NSS_JPAKE_FINAL_SHA256  (CKM_NSS + 16)
#define CKM_NSS_JPAKE_FINAL_SHA384  (CKM_NSS + 17)
#define CKM_NSS_JPAKE_FINAL_SHA512  (CKM_NSS + 18)

#define CKK_GOSTR3410 0x00000030
#define CKK_GOSTR3411 0x00000031
#define CKK_GOST28147 0x00000032

#define CKM_GOSTR3410_KEY_PAIR_GEN   0x00001200
#define CKM_GOSTR3410                0x00001201
#define CKM_GOSTR3410_WITH_GOSTR3411 0x00001202
#define CKM_GOSTR3410_KEY_WRAP       0x00001203
#define CKM_GOSTR3410_DERIVE         0x00001204
#define CKM_GOSTR3411                0x00001210
#define CKM_GOSTR3411_HMAC           0x00001211
#define CKM_GOST28147_KEY_GEN        0x00001220
#define CKM_GOST28147_ECB            0x00001221
#define CKM_GOST28147                0x00001222
#define CKM_GOST28147_MAC            0x00001223
#define CKM_GOST28147_KEY_WRAP       0x00001224

#define CKA_GOSTR3410PARAMS         0x00000250
#define CKA_GOSTR3411PARAMS         0x00000251
#define CKA_GOST28147PARAMS         0x00000252

void print_enum(FILE *f, CK_ULONG type, CK_VOID_PTR value,
                CK_ULONG size, CK_VOID_PTR arg)
{
    enum_spec *spec = (enum_spec*)arg;
    CK_ULONG i;
    CK_ULONG ctype = *((CK_ULONG_PTR)value);

    for(i = 0; i < spec->size; i++) {
        if(spec->specs[i].type == ctype) {
            fprintf(f, "%s\n", spec->specs[i].name);
            return;
        }
    }
    fprintf(f, "Value %lX not found for type %s\n", ctype, spec->name);
}

void print_boolean(FILE *f, CK_ULONG type, CK_VOID_PTR value,
                   CK_ULONG size, CK_VOID_PTR arg)
{
    CK_BYTE i = *((CK_BYTE *)value);
    fprintf(f, i ? "True\n" : "False\n");
}

void print_generic(FILE *f, CK_ULONG type, CK_VOID_PTR value,
                   CK_ULONG size, CK_VOID_PTR arg)
{
    CK_ULONG i;
    if(size > 0) {
        fprintf(f, "[size : 0x%lX (%ld)]\n    ", size, size);
        for(i = 0; i < size; i++) {
            if (i != 0) {
                if ((i % 32) == 0)
                    fprintf(f, "\n    ");
                else if((i % 4) == 0)
                    fprintf(f, " ");
            }
            fprintf(f, "%02X", ((CK_BYTE *)value)[i]);
        }
    } else {
        fprintf(f, "EMPTY");
    }
    fprintf(f, "\n");
}

void print_dn(FILE *f, CK_ULONG type, CK_VOID_PTR value,
              CK_ULONG size, CK_VOID_PTR arg)
{
    print_generic(f, type, value, size, arg);
#ifdef HAVE_OPENSSL
    if(size && value) {
        X509_NAME *name;
        name = d2i_X509_NAME(NULL, (const unsigned char **)&value, size);
        if(name) {
            BIO *bio = BIO_new(BIO_s_file());
            BIO_set_fp(bio, f, BIO_NOCLOSE);
            fprintf(f, "    DN: ");
            X509_NAME_print(bio, name, XN_FLAG_RFC2253);
            fprintf(f, "\n");
            BIO_free(bio);
        }
    }
#endif
}

void print_print(FILE *f, CK_ULONG type, CK_VOID_PTR value,
                 CK_ULONG size, CK_VOID_PTR arg)
{
    CK_ULONG i, j;
    CK_BYTE  c;
    if(size > 0) {
        fprintf(f, "[size : 0x%lX (%ld)]\n    ", size, size);
        for(i = 0; i < size; i += j) {
            for(j = 0; ((i + j < size) && (j < 32)); j++) {
                if (((j % 4) == 0) && (j != 0)) fprintf(f, " ");
                c = ((CK_BYTE *)value)[i+j];
                fprintf(f, "%02X", c);
            }
            fprintf(f, "\n    ");
            for(j = 0; ((i + j < size) && (j < 32)); j++) {
                if (((j % 4) == 0) && (j != 0)) fprintf(f, " ");
                c = ((CK_BYTE *)value)[i + j];
                if((c > 32) && (c < 128)) {
                    fprintf(f, " %c", c);
                } else {
                    fprintf(f, " .");
                }
            }
            if(j == 32) fprintf(f, "\n    ");
        }
    } else {
        fprintf(f, "EMPTY");
    }
    fprintf(f, "\n");
}

#define CONSTANT(x) { x, #x }

enum_specs ck_cls_s[] = {
    CONSTANT(CKO_DATA),
    CONSTANT(CKO_CERTIFICATE),
    CONSTANT(CKO_PUBLIC_KEY),
    CONSTANT(CKO_PRIVATE_KEY),
    CONSTANT(CKO_SECRET_KEY),
    CONSTANT(CKO_HW_FEATURE),
    CONSTANT(CKO_DOMAIN_PARAMETERS),
    CONSTANT(CKO_MECHANISM),
    CONSTANT(CKO_VENDOR_DEFINED)
};

enum_specs ck_crt_s[] = {
    CONSTANT(CKC_X_509),
    CONSTANT(CKC_X_509_ATTR_CERT),
    CONSTANT(CKC_WTLS),
    CONSTANT(CKC_VENDOR_DEFINED)
};

enum_specs ck_hwf_s[] = {
    CONSTANT(CKH_MONOTONIC_COUNTER),
    CONSTANT(CKH_CLOCK),
    CONSTANT(CKH_VENDOR_DEFINED)
};

enum_specs ck_key_s[] = {
    CONSTANT(CKK_RSA),
    CONSTANT(CKK_DSA),
    CONSTANT(CKK_DH),
    CONSTANT(CKK_EC),
    CONSTANT(CKK_X9_42_DH),
    CONSTANT(CKK_KEA),
    CONSTANT(CKK_GENERIC_SECRET),
    CONSTANT(CKK_RC2),
    CONSTANT(CKK_RC4),
    CONSTANT(CKK_DES),
    CONSTANT(CKK_DES2),
    CONSTANT(CKK_DES3),
    CONSTANT(CKK_CAST),
    CONSTANT(CKK_CAST3),
    CONSTANT(CKK_CAST128),
    CONSTANT(CKK_RC5),
    CONSTANT(CKK_IDEA),
    CONSTANT(CKK_SKIPJACK),
    CONSTANT(CKK_BATON),
    CONSTANT(CKK_JUNIPER),
    CONSTANT(CKK_CDMF),
    CONSTANT(CKK_AES),
    CONSTANT(CKK_BLOWFISH),
    CONSTANT(CKK_TWOFISH),
    /* Add Camellia & Seed */
    CONSTANT(CKK_GOSTR3410),
    CONSTANT(CKK_GOSTR3411),
    CONSTANT(CKK_GOST28147),
    CONSTANT(CKK_VENDOR_DEFINED)
};

enum_specs ck_mec_s[] = {
    CONSTANT(CKM_RSA_PKCS_KEY_PAIR_GEN),
    CONSTANT(CKM_RSA_PKCS),
    CONSTANT(CKM_RSA_9796),
    CONSTANT(CKM_RSA_X_509),
    CONSTANT(CKM_MD2_RSA_PKCS),
    CONSTANT(CKM_MD5_RSA_PKCS),
    CONSTANT(CKM_SHA1_RSA_PKCS),
    CONSTANT(CKM_RIPEMD128_RSA_PKCS),
    CONSTANT(CKM_RIPEMD160_RSA_PKCS),
    CONSTANT(CKM_RSA_PKCS_OAEP),
    CONSTANT(CKM_RSA_X9_31_KEY_PAIR_GEN),
    CONSTANT(CKM_RSA_X9_31),
    CONSTANT(CKM_SHA1_RSA_X9_31),
    CONSTANT(CKM_RSA_PKCS_PSS),
    CONSTANT(CKM_SHA1_RSA_PKCS_PSS),
    CONSTANT(CKM_DSA_KEY_PAIR_GEN),
    CONSTANT(CKM_DSA),
    CONSTANT(CKM_DSA_SHA1),
    CONSTANT(CKM_DH_PKCS_KEY_PAIR_GEN),
    CONSTANT(CKM_DH_PKCS_DERIVE),
    CONSTANT(CKM_X9_42_DH_KEY_PAIR_GEN),
    CONSTANT(CKM_X9_42_DH_DERIVE),
    CONSTANT(CKM_X9_42_DH_HYBRID_DERIVE),
    CONSTANT(CKM_X9_42_MQV_DERIVE),
    CONSTANT(CKM_SHA256_RSA_PKCS),
    CONSTANT(CKM_SHA384_RSA_PKCS),
    CONSTANT(CKM_SHA512_RSA_PKCS),
    CONSTANT(CKM_SHA256_RSA_PKCS_PSS),
    CONSTANT(CKM_SHA384_RSA_PKCS_PSS),
    CONSTANT(CKM_SHA512_RSA_PKCS_PSS),
    CONSTANT(CKM_RC2_KEY_GEN),
    CONSTANT(CKM_RC2_ECB),
    CONSTANT(CKM_RC2_CBC),
    CONSTANT(CKM_RC2_MAC),
    CONSTANT(CKM_RC2_MAC_GENERAL),
    CONSTANT(CKM_RC2_CBC_PAD),
    CONSTANT(CKM_RC4_KEY_GEN),
    CONSTANT(CKM_RC4),
    CONSTANT(CKM_DES_KEY_GEN),
    CONSTANT(CKM_DES_ECB),
    CONSTANT(CKM_DES_CBC),
    CONSTANT(CKM_DES_MAC),
    CONSTANT(CKM_DES_MAC_GENERAL),
    CONSTANT(CKM_DES_CBC_PAD),
    CONSTANT(CKM_DES2_KEY_GEN),
    CONSTANT(CKM_DES3_KEY_GEN),
    CONSTANT(CKM_DES3_ECB),
    CONSTANT(CKM_DES3_CBC),
    CONSTANT(CKM_DES3_MAC),
    CONSTANT(CKM_DES3_MAC_GENERAL),
    CONSTANT(CKM_DES3_CBC_PAD),
    CONSTANT(CKM_CDMF_KEY_GEN),
    CONSTANT(CKM_CDMF_ECB),
    CONSTANT(CKM_CDMF_CBC),
    CONSTANT(CKM_CDMF_MAC),
    CONSTANT(CKM_CDMF_MAC_GENERAL),
    CONSTANT(CKM_CDMF_CBC_PAD),
    CONSTANT(CKM_DES_OFB64),
    CONSTANT(CKM_DES_OFB8),
    CONSTANT(CKM_DES_CFB64),
    CONSTANT(CKM_DES_CFB8),
    CONSTANT(CKM_MD2),
    CONSTANT(CKM_MD2_HMAC),
    CONSTANT(CKM_MD2_HMAC_GENERAL),
    CONSTANT(CKM_MD5),
    CONSTANT(CKM_MD5_HMAC),
    CONSTANT(CKM_MD5_HMAC_GENERAL),
    CONSTANT(CKM_SHA_1),
    CONSTANT(CKM_SHA_1_HMAC),
    CONSTANT(CKM_SHA_1_HMAC_GENERAL),
    CONSTANT(CKM_RIPEMD128),
    CONSTANT(CKM_RIPEMD128_HMAC),
    CONSTANT(CKM_RIPEMD128_HMAC_GENERAL),
    CONSTANT(CKM_RIPEMD160),
    CONSTANT(CKM_RIPEMD160_HMAC),
    CONSTANT(CKM_RIPEMD160_HMAC_GENERAL),
    CONSTANT(CKM_SHA256),
    CONSTANT(CKM_SHA256_HMAC),
    CONSTANT(CKM_SHA256_HMAC_GENERAL),
    CONSTANT(CKM_SHA384),
    CONSTANT(CKM_SHA384_HMAC),
    CONSTANT(CKM_SHA384_HMAC_GENERAL),
    CONSTANT(CKM_SHA512),
    CONSTANT(CKM_SHA512_HMAC),
    CONSTANT(CKM_SHA512_HMAC_GENERAL),
    CONSTANT(CKM_CAST_KEY_GEN),
    CONSTANT(CKM_CAST_ECB),
    CONSTANT(CKM_CAST_CBC),
    CONSTANT(CKM_CAST_MAC),
    CONSTANT(CKM_CAST_MAC_GENERAL),
    CONSTANT(CKM_CAST_CBC_PAD),
    CONSTANT(CKM_CAST3_KEY_GEN),
    CONSTANT(CKM_CAST3_ECB),
    CONSTANT(CKM_CAST3_CBC),
    CONSTANT(CKM_CAST3_MAC),
    CONSTANT(CKM_CAST3_MAC_GENERAL),
    CONSTANT(CKM_CAST3_CBC_PAD),
    CONSTANT(CKM_CAST5_KEY_GEN),
    CONSTANT(CKM_CAST128_KEY_GEN),
    CONSTANT(CKM_CAST5_ECB),
    CONSTANT(CKM_CAST128_ECB),
    CONSTANT(CKM_CAST5_CBC),
    CONSTANT(CKM_CAST128_CBC),
    CONSTANT(CKM_CAST5_MAC),
    CONSTANT(CKM_CAST128_MAC),
    CONSTANT(CKM_CAST5_MAC_GENERAL),
    CONSTANT(CKM_CAST128_MAC_GENERAL),
    CONSTANT(CKM_CAST5_CBC_PAD),
    CONSTANT(CKM_CAST128_CBC_PAD),
    CONSTANT(CKM_RC5_KEY_GEN),
    CONSTANT(CKM_RC5_ECB),
    CONSTANT(CKM_RC5_CBC),
    CONSTANT(CKM_RC5_MAC),
    CONSTANT(CKM_RC5_MAC_GENERAL),
    CONSTANT(CKM_RC5_CBC_PAD),
    CONSTANT(CKM_IDEA_KEY_GEN),
    CONSTANT(CKM_IDEA_ECB),
    CONSTANT(CKM_IDEA_CBC),
    CONSTANT(CKM_IDEA_MAC),
    CONSTANT(CKM_IDEA_MAC_GENERAL),
    CONSTANT(CKM_IDEA_CBC_PAD),
    CONSTANT(CKM_GENERIC_SECRET_KEY_GEN),
    CONSTANT(CKM_CONCATENATE_BASE_AND_KEY),
    CONSTANT(CKM_CONCATENATE_BASE_AND_DATA),
    CONSTANT(CKM_CONCATENATE_DATA_AND_BASE),
    CONSTANT(CKM_XOR_BASE_AND_DATA),
    CONSTANT(CKM_EXTRACT_KEY_FROM_KEY),
    CONSTANT(CKM_SSL3_PRE_MASTER_KEY_GEN),
    CONSTANT(CKM_SSL3_MASTER_KEY_DERIVE),
    CONSTANT(CKM_SSL3_KEY_AND_MAC_DERIVE),
    CONSTANT(CKM_SSL3_MASTER_KEY_DERIVE_DH),
    CONSTANT(CKM_TLS_PRE_MASTER_KEY_GEN),
    CONSTANT(CKM_TLS_MASTER_KEY_DERIVE),
    CONSTANT(CKM_TLS_KEY_AND_MAC_DERIVE),
    CONSTANT(CKM_TLS_MASTER_KEY_DERIVE_DH),
    CONSTANT(CKM_TLS_PRF),
    CONSTANT(CKM_SSL3_MD5_MAC),
    CONSTANT(CKM_SSL3_SHA1_MAC),
    CONSTANT(CKM_MD5_KEY_DERIVATION),
    CONSTANT(CKM_MD2_KEY_DERIVATION),
    CONSTANT(CKM_SHA1_KEY_DERIVATION),
    CONSTANT(CKM_SHA256_KEY_DERIVATION),
    CONSTANT(CKM_SHA384_KEY_DERIVATION),
    CONSTANT(CKM_SHA512_KEY_DERIVATION),
    CONSTANT(CKM_PBE_MD2_DES_CBC),
    CONSTANT(CKM_PBE_MD5_DES_CBC),
    CONSTANT(CKM_PBE_MD5_CAST_CBC),
    CONSTANT(CKM_PBE_MD5_CAST3_CBC),
    CONSTANT(CKM_PBE_MD5_CAST5_CBC),
    CONSTANT(CKM_PBE_MD5_CAST128_CBC),
    CONSTANT(CKM_PBE_SHA1_CAST5_CBC),
    CONSTANT(CKM_PBE_SHA1_CAST128_CBC),
    CONSTANT(CKM_PBE_SHA1_RC4_128),
    CONSTANT(CKM_PBE_SHA1_RC4_40),
    CONSTANT(CKM_PBE_SHA1_DES3_EDE_CBC),
    CONSTANT(CKM_PBE_SHA1_DES2_EDE_CBC),
    CONSTANT(CKM_PBE_SHA1_RC2_128_CBC),
    CONSTANT(CKM_PBE_SHA1_RC2_40_CBC),
    CONSTANT(CKM_PKCS5_PBKD2),
    CONSTANT(CKM_PBA_SHA1_WITH_SHA1_HMAC),
    CONSTANT(CKM_WTLS_PRE_MASTER_KEY_GEN),
    CONSTANT(CKM_WTLS_MASTER_KEY_DERIVE),
    CONSTANT(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC),
    CONSTANT(CKM_WTLS_PRF),
    CONSTANT(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
    CONSTANT(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
    CONSTANT(CKM_KEY_WRAP_LYNKS),
    CONSTANT(CKM_KEY_WRAP_SET_OAEP),
    CONSTANT(CKM_CMS_SIG),
    CONSTANT(CKM_SKIPJACK_KEY_GEN),
    CONSTANT(CKM_SKIPJACK_ECB64),
    CONSTANT(CKM_SKIPJACK_CBC64),
    CONSTANT(CKM_SKIPJACK_OFB64),
    CONSTANT(CKM_SKIPJACK_CFB64),
    CONSTANT(CKM_SKIPJACK_CFB32),
    CONSTANT(CKM_SKIPJACK_CFB16),
    CONSTANT(CKM_SKIPJACK_CFB8),
    CONSTANT(CKM_SKIPJACK_WRAP),
    CONSTANT(CKM_SKIPJACK_PRIVATE_WRAP),
    CONSTANT(CKM_SKIPJACK_RELAYX),
    CONSTANT(CKM_KEA_KEY_PAIR_GEN),
    CONSTANT(CKM_KEA_KEY_DERIVE),
    CONSTANT(CKM_FORTEZZA_TIMESTAMP),
    CONSTANT(CKM_BATON_KEY_GEN),
    CONSTANT(CKM_BATON_ECB128),
    CONSTANT(CKM_BATON_ECB96),
    CONSTANT(CKM_BATON_CBC128),
    CONSTANT(CKM_BATON_COUNTER),
    CONSTANT(CKM_BATON_SHUFFLE),
    CONSTANT(CKM_BATON_WRAP),
    CONSTANT(CKM_EC_KEY_PAIR_GEN),
    CONSTANT(CKM_ECDSA),
    CONSTANT(CKM_ECDSA_SHA1),
    CONSTANT(CKM_ECDH1_DERIVE),
    CONSTANT(CKM_ECDH1_COFACTOR_DERIVE),
    CONSTANT(CKM_ECMQV_DERIVE),
    CONSTANT(CKM_JUNIPER_KEY_GEN),
    CONSTANT(CKM_JUNIPER_ECB128),
    CONSTANT(CKM_JUNIPER_CBC128),
    CONSTANT(CKM_JUNIPER_COUNTER),
    CONSTANT(CKM_JUNIPER_SHUFFLE),
    CONSTANT(CKM_JUNIPER_WRAP),
    CONSTANT(CKM_FASTHASH),
    CONSTANT(CKM_AES_KEY_GEN),
    CONSTANT(CKM_AES_ECB), 
    CONSTANT(CKM_AES_CBC),
    CONSTANT(CKM_AES_MAC),
    CONSTANT(CKM_AES_MAC_GENERAL),
    CONSTANT(CKM_AES_CBC_PAD),
    CONSTANT(CKM_BLOWFISH_KEY_GEN),
    CONSTANT(CKM_BLOWFISH_CBC),
    CONSTANT(CKM_TWOFISH_KEY_GEN),
    CONSTANT(CKM_TWOFISH_CBC),
    CONSTANT(CKM_CAMELLIA_KEY_GEN),
    CONSTANT(CKM_CAMELLIA_ECB),
    CONSTANT(CKM_CAMELLIA_CBC),
    CONSTANT(CKM_CAMELLIA_MAC),        
    CONSTANT(CKM_CAMELLIA_MAC_GENERAL),
    CONSTANT(CKM_CAMELLIA_CBC_PAD),
    CONSTANT(CKM_CAMELLIA_ECB_ENCRYPT_DATA),
    CONSTANT(CKM_CAMELLIA_CBC_ENCRYPT_DATA), 
    CONSTANT(CKM_SEED_KEY_GEN),
    CONSTANT(CKM_SEED_ECB),      
    CONSTANT(CKM_SEED_CBC),
    CONSTANT(CKM_SEED_MAC),
    CONSTANT(CKM_SEED_MAC_GENERAL),
    CONSTANT(CKM_SEED_CBC_PAD),
    CONSTANT(CKM_SEED_ECB_ENCRYPT_DATA),
    CONSTANT(CKM_SEED_CBC_ENCRYPT_DATA),
    CONSTANT(CKM_DES_ECB_ENCRYPT_DATA),
    CONSTANT(CKM_DES_CBC_ENCRYPT_DATA),
    CONSTANT(CKM_DES3_ECB_ENCRYPT_DATA),
    CONSTANT(CKM_DES3_CBC_ENCRYPT_DATA),
    CONSTANT(CKM_AES_ECB_ENCRYPT_DATA),
    CONSTANT(CKM_AES_CBC_ENCRYPT_DATA),
    CONSTANT(CKM_GOSTR3410_KEY_PAIR_GEN),
    CONSTANT(CKM_GOSTR3410),
    CONSTANT(CKM_GOSTR3410_WITH_GOSTR3411),
    CONSTANT(CKM_GOSTR3410_KEY_WRAP),
    CONSTANT(CKM_GOSTR3410_DERIVE),
    CONSTANT(CKM_GOSTR3411),
    CONSTANT(CKM_GOSTR3411_HMAC),
    CONSTANT(CKM_GOST28147_KEY_GEN),
    CONSTANT(CKM_GOST28147_ECB),
    CONSTANT(CKM_GOST28147),
    CONSTANT(CKM_GOST28147_MAC),
    CONSTANT(CKM_GOST28147_KEY_WRAP),
    CONSTANT(CKM_DSA_PARAMETER_GEN),
    CONSTANT(CKM_DH_PKCS_PARAMETER_GEN),
    CONSTANT(CKM_X9_42_DH_PARAMETER_GEN),
    CONSTANT(CKM_VENDOR_DEFINED),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_DES_CBC),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC),
    CONSTANT(CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN),
    CONSTANT(CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN),
    CONSTANT(CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN),
    CONSTANT(CKM_TLS_PRF_GENERAL),
    CONSTANT(CKM_NSS_AES_KEY_WRAP),
    CONSTANT(CKM_NSS_AES_KEY_WRAP_PAD),
    CONSTANT(CKM_NSS_HKDF_SHA1),
    CONSTANT(CKM_NSS_HKDF_SHA256),
    CONSTANT(CKM_NSS_HKDF_SHA384),
    CONSTANT(CKM_NSS_HKDF_SHA512),
    CONSTANT(CKM_NSS_JPAKE_ROUND1_SHA1),
    CONSTANT(CKM_NSS_JPAKE_ROUND1_SHA256),
    CONSTANT(CKM_NSS_JPAKE_ROUND1_SHA384),
    CONSTANT(CKM_NSS_JPAKE_ROUND1_SHA512),
    CONSTANT(CKM_NSS_JPAKE_ROUND2_SHA1),
    CONSTANT(CKM_NSS_JPAKE_ROUND2_SHA256),
    CONSTANT(CKM_NSS_JPAKE_ROUND2_SHA384),
    CONSTANT(CKM_NSS_JPAKE_ROUND2_SHA512),
    CONSTANT(CKM_NSS_JPAKE_FINAL_SHA1),
    CONSTANT(CKM_NSS_JPAKE_FINAL_SHA256),
    CONSTANT(CKM_NSS_JPAKE_FINAL_SHA384),
    CONSTANT(CKM_NSS_JPAKE_FINAL_SHA512)
};

enum_specs ck_err_s[] = {
    CONSTANT(CKR_OK),
    CONSTANT(CKR_CANCEL),
    CONSTANT(CKR_HOST_MEMORY),
    CONSTANT(CKR_SLOT_ID_INVALID),
    CONSTANT(CKR_GENERAL_ERROR),
    CONSTANT(CKR_FUNCTION_FAILED),
    CONSTANT(CKR_ARGUMENTS_BAD),
    CONSTANT(CKR_NO_EVENT),
    CONSTANT(CKR_NEED_TO_CREATE_THREADS),
    CONSTANT(CKR_CANT_LOCK),
    CONSTANT(CKR_ATTRIBUTE_READ_ONLY),
    CONSTANT(CKR_ATTRIBUTE_SENSITIVE),
    CONSTANT(CKR_ATTRIBUTE_TYPE_INVALID),
    CONSTANT(CKR_ATTRIBUTE_VALUE_INVALID),
    CONSTANT(CKR_DATA_INVALID),
    CONSTANT(CKR_DATA_LEN_RANGE),
    CONSTANT(CKR_DEVICE_ERROR),
    CONSTANT(CKR_DEVICE_MEMORY),
    CONSTANT(CKR_DEVICE_REMOVED),
    CONSTANT(CKR_ENCRYPTED_DATA_INVALID),
    CONSTANT(CKR_ENCRYPTED_DATA_LEN_RANGE),
    CONSTANT(CKR_FUNCTION_CANCELED),
    CONSTANT(CKR_FUNCTION_NOT_PARALLEL),
    CONSTANT(CKR_FUNCTION_NOT_SUPPORTED),
    CONSTANT(CKR_KEY_HANDLE_INVALID),
    CONSTANT(CKR_KEY_SIZE_RANGE),
    CONSTANT(CKR_KEY_TYPE_INCONSISTENT),
    CONSTANT(CKR_KEY_NOT_NEEDED),
    CONSTANT(CKR_KEY_CHANGED),
    CONSTANT(CKR_KEY_NEEDED),
    CONSTANT(CKR_KEY_INDIGESTIBLE),
    CONSTANT(CKR_KEY_FUNCTION_NOT_PERMITTED),
    CONSTANT(CKR_KEY_NOT_WRAPPABLE),
    CONSTANT(CKR_KEY_UNEXTRACTABLE),
    CONSTANT(CKR_MECHANISM_INVALID),
    CONSTANT(CKR_MECHANISM_PARAM_INVALID),
    CONSTANT(CKR_OBJECT_HANDLE_INVALID),
    CONSTANT(CKR_OPERATION_ACTIVE),
    CONSTANT(CKR_OPERATION_NOT_INITIALIZED),
    CONSTANT(CKR_PIN_INCORRECT),
    CONSTANT(CKR_PIN_INVALID),
    CONSTANT(CKR_PIN_LEN_RANGE),
    CONSTANT(CKR_PIN_EXPIRED),
    CONSTANT(CKR_PIN_LOCKED),
    CONSTANT(CKR_SESSION_CLOSED),
    CONSTANT(CKR_SESSION_COUNT),
    CONSTANT(CKR_SESSION_HANDLE_INVALID),
    CONSTANT(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
    CONSTANT(CKR_SESSION_READ_ONLY),
    CONSTANT(CKR_SESSION_EXISTS),
    CONSTANT(CKR_SESSION_READ_ONLY_EXISTS),
    CONSTANT(CKR_SESSION_READ_WRITE_SO_EXISTS),
    CONSTANT(CKR_SIGNATURE_INVALID),
    CONSTANT(CKR_SIGNATURE_LEN_RANGE),
    CONSTANT(CKR_TEMPLATE_INCOMPLETE),
    CONSTANT(CKR_TEMPLATE_INCONSISTENT),
    CONSTANT(CKR_TOKEN_NOT_PRESENT),
    CONSTANT(CKR_TOKEN_NOT_RECOGNIZED),
    CONSTANT(CKR_TOKEN_WRITE_PROTECTED),
    CONSTANT(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
    CONSTANT(CKR_UNWRAPPING_KEY_SIZE_RANGE),
    CONSTANT(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
    CONSTANT(CKR_USER_ALREADY_LOGGED_IN),
    CONSTANT(CKR_USER_NOT_LOGGED_IN),
    CONSTANT(CKR_USER_PIN_NOT_INITIALIZED),
    CONSTANT(CKR_USER_TYPE_INVALID),
    CONSTANT(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
    CONSTANT(CKR_USER_TOO_MANY_TYPES),
    CONSTANT(CKR_WRAPPED_KEY_INVALID),
    CONSTANT(CKR_WRAPPED_KEY_LEN_RANGE),
    CONSTANT(CKR_WRAPPING_KEY_HANDLE_INVALID),
    CONSTANT(CKR_WRAPPING_KEY_SIZE_RANGE),
    CONSTANT(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
    CONSTANT(CKR_RANDOM_SEED_NOT_SUPPORTED),
    CONSTANT(CKR_RANDOM_NO_RNG),
    CONSTANT(CKR_DOMAIN_PARAMS_INVALID),
    CONSTANT(CKR_BUFFER_TOO_SMALL),
    CONSTANT(CKR_SAVED_STATE_INVALID),
    CONSTANT(CKR_INFORMATION_SENSITIVE),
    CONSTANT(CKR_STATE_UNSAVEABLE),
    CONSTANT(CKR_CRYPTOKI_NOT_INITIALIZED),
    CONSTANT(CKR_CRYPTOKI_ALREADY_INITIALIZED),
    CONSTANT(CKR_MUTEX_BAD),
    CONSTANT(CKR_MUTEX_NOT_LOCKED),
    CONSTANT(CKR_VENDOR_DEFINED)
};

enum_specs ck_usr_s[] = {
    CONSTANT(CKU_SO),
    CONSTANT(CKU_USER)
};

enum_specs ck_sta_s[] = {
    CONSTANT(CKS_RO_PUBLIC_SESSION),
    CONSTANT(CKS_RO_USER_FUNCTIONS),
    CONSTANT(CKS_RW_PUBLIC_SESSION),
    CONSTANT(CKS_RW_USER_FUNCTIONS),
    CONSTANT(CKS_RW_SO_FUNCTIONS)
};

#define SZ_SPECS sizeof(enum_specs)

enum_spec ck_types[] = {
    { OBJ_T, ck_cls_s, sizeof(ck_cls_s) / SZ_SPECS, "CK_OBJECT_CLASS"     },
    { KEY_T, ck_key_s, sizeof(ck_key_s) / SZ_SPECS, "CK_KEY_TYPE"         },
    { CRT_T, ck_crt_s, sizeof(ck_crt_s) / SZ_SPECS, "CK_CERTIFICATE_TYPE" },
    { MEC_T, ck_mec_s, sizeof(ck_mec_s) / SZ_SPECS, "CK_MECHANISM_TYPE"   },
    { USR_T, ck_usr_s, sizeof(ck_usr_s) / SZ_SPECS, "CK_USER_TYPE"        },
    { STA_T, ck_sta_s, sizeof(ck_sta_s) / SZ_SPECS, "CK_STATE"            },
    { RV_T,  ck_err_s, sizeof(ck_err_s) / SZ_SPECS, "CK_RV"               },
};

enum_spec ck_key_t[] = { { KEY_T, ck_key_s, sizeof(ck_key_s) /
                           SZ_SPECS, "CK_KEY_TYPE" } };
enum_spec ck_cls_t[] = { { OBJ_T, ck_cls_s, sizeof(ck_cls_s) /
                           SZ_SPECS, "CK_OBJECT_CLASS" } };
enum_spec ck_crt_t[] = { { CRT_T, ck_crt_s, sizeof(ck_crt_s) /
                           SZ_SPECS, "CK_CERTIFICATE_TYPE" } };

#define ATTRIBUTE(x) x, #x

type_spec ck_attribute_specs[] = {
    { ATTRIBUTE(CKA_CLASS),                       print_enum,    ck_cls_t },
    { ATTRIBUTE(CKA_TOKEN),                       print_boolean, NULL },
    { ATTRIBUTE(CKA_PRIVATE),                     print_boolean, NULL },
    { ATTRIBUTE(CKA_LABEL),                       print_print,   NULL },
    { ATTRIBUTE(CKA_APPLICATION),                 print_print,   NULL },
    { ATTRIBUTE(CKA_VALUE),                       print_generic, NULL },
    { ATTRIBUTE(CKA_OBJECT_ID),                   print_generic, NULL },
    { ATTRIBUTE(CKA_CERTIFICATE_TYPE),            print_enum,    ck_crt_t },
    { ATTRIBUTE(CKA_ISSUER),                      print_dn,      NULL },
    { ATTRIBUTE(CKA_SERIAL_NUMBER),               print_generic, NULL },
    { ATTRIBUTE(CKA_AC_ISSUER),                   print_dn,      NULL },
    { ATTRIBUTE(CKA_OWNER),                       print_generic, NULL },
    { ATTRIBUTE(CKA_ATTR_TYPES),                  print_generic, NULL },
    { ATTRIBUTE(CKA_TRUSTED),                     print_generic, NULL },
    { ATTRIBUTE(CKA_CERTIFICATE_CATEGORY),        print_generic, NULL },
    { ATTRIBUTE(CKA_JAVA_MIDP_SECURITY_DOMAIN),   print_generic, NULL },
    { ATTRIBUTE(CKA_URL),                         print_generic, NULL },
    { ATTRIBUTE(CKA_HASH_OF_SUBJECT_PUBLIC_KEY),  print_generic, NULL },
    { ATTRIBUTE(CKA_HASH_OF_ISSUER_PUBLIC_KEY),   print_generic, NULL },
    { ATTRIBUTE(CKA_CHECK_VALUE),                 print_generic, NULL },
    { ATTRIBUTE(CKA_KEY_TYPE),                    print_enum,    ck_key_t },
    { ATTRIBUTE(CKA_SUBJECT),                     print_dn,      NULL },
    { ATTRIBUTE(CKA_ID),                          print_generic, NULL },
    { ATTRIBUTE(CKA_SENSITIVE),                   print_boolean, NULL },
    { ATTRIBUTE(CKA_ENCRYPT),                     print_boolean, NULL },
    { ATTRIBUTE(CKA_DECRYPT),                     print_boolean, NULL },
    { ATTRIBUTE(CKA_WRAP),                        print_boolean, NULL },
    { ATTRIBUTE(CKA_UNWRAP),                      print_boolean, NULL },
    { ATTRIBUTE(CKA_SIGN),                        print_boolean, NULL },
    { ATTRIBUTE(CKA_SIGN_RECOVER),                print_boolean, NULL },
    { ATTRIBUTE(CKA_VERIFY),                      print_boolean, NULL },
    { ATTRIBUTE(CKA_VERIFY_RECOVER),              print_boolean, NULL },
    { ATTRIBUTE(CKA_DERIVE),                      print_boolean, NULL },
    { ATTRIBUTE(CKA_START_DATE),                  print_generic, NULL },
    { ATTRIBUTE(CKA_END_DATE),                    print_generic, NULL },
    { ATTRIBUTE(CKA_MODULUS),                     print_generic, NULL },
    { ATTRIBUTE(CKA_MODULUS_BITS),                print_generic, NULL },
    { ATTRIBUTE(CKA_PUBLIC_EXPONENT),             print_generic, NULL },
    { ATTRIBUTE(CKA_PRIVATE_EXPONENT),            print_generic, NULL },
    { ATTRIBUTE(CKA_PRIME_1),                     print_generic, NULL },
    { ATTRIBUTE(CKA_PRIME_2),                     print_generic, NULL },
    { ATTRIBUTE(CKA_EXPONENT_1),                  print_generic, NULL },
    { ATTRIBUTE(CKA_EXPONENT_2),                  print_generic, NULL },
    { ATTRIBUTE(CKA_COEFFICIENT),                 print_generic, NULL },
    { ATTRIBUTE(CKA_PRIME),                       print_generic, NULL },
    { ATTRIBUTE(CKA_SUBPRIME),                    print_generic, NULL },
    { ATTRIBUTE(CKA_BASE),                        print_generic, NULL },
    { ATTRIBUTE(CKA_PRIME_BITS),                  print_generic, NULL },
    { ATTRIBUTE(CKA_SUBPRIME_BITS),               print_generic, NULL },
    { ATTRIBUTE(CKA_VALUE_BITS),                  print_generic, NULL },
    { ATTRIBUTE(CKA_VALUE_LEN),                   print_generic, NULL },
    { ATTRIBUTE(CKA_EXTRACTABLE),                 print_boolean, NULL },
    { ATTRIBUTE(CKA_LOCAL),                       print_boolean, NULL },
    { ATTRIBUTE(CKA_NEVER_EXTRACTABLE),           print_boolean, NULL },
    { ATTRIBUTE(CKA_ALWAYS_SENSITIVE),            print_boolean, NULL },
    { ATTRIBUTE(CKA_KEY_GEN_MECHANISM),           print_boolean, NULL },
    { ATTRIBUTE(CKA_MODIFIABLE),                  print_boolean, NULL },
    { ATTRIBUTE(CKA_EC_PARAMS),                   print_generic, NULL },
    { ATTRIBUTE(CKA_EC_POINT),                    print_generic, NULL },
    { ATTRIBUTE(CKA_SECONDARY_AUTH),              print_generic, NULL },
    { ATTRIBUTE(CKA_AUTH_PIN_FLAGS),              print_generic, NULL },
    { ATTRIBUTE(CKA_ALWAYS_AUTHENTICATE),         print_boolean, NULL },
    { ATTRIBUTE(CKA_WRAP_WITH_TRUSTED),           print_boolean, NULL },
    { ATTRIBUTE(CKA_WRAP_TEMPLATE),               print_generic, NULL },
    { ATTRIBUTE(CKA_UNWRAP_TEMPLATE),             print_generic, NULL },
    { ATTRIBUTE(CKA_GOSTR3410PARAMS),             print_generic, NULL },
    { ATTRIBUTE(CKA_GOSTR3411PARAMS),             print_generic, NULL },
    { ATTRIBUTE(CKA_GOST28147PARAMS),             print_generic, NULL },
    { ATTRIBUTE(CKA_HW_FEATURE_TYPE),             print_generic, NULL },
    { ATTRIBUTE(CKA_RESET_ON_INIT),               print_boolean, NULL },
    { ATTRIBUTE(CKA_HAS_RESET),                   print_boolean, NULL },
    { ATTRIBUTE(CKA_PIXEL_X),                     print_generic, NULL },
    { ATTRIBUTE(CKA_PIXEL_Y),                     print_generic, NULL },
    { ATTRIBUTE(CKA_RESOLUTION),                  print_generic, NULL },
    { ATTRIBUTE(CKA_CHAR_ROWS),                   print_generic, NULL },
    { ATTRIBUTE(CKA_CHAR_COLUMNS),                print_generic, NULL },
    { ATTRIBUTE(CKA_COLOR),                       print_generic, NULL },
    { ATTRIBUTE(CKA_BITS_PER_PIXEL),              print_generic, NULL },
    { ATTRIBUTE(CKA_CHAR_SETS),                   print_generic, NULL },
    { ATTRIBUTE(CKA_ENCODING_METHODS),            print_generic, NULL },
    { ATTRIBUTE(CKA_MIME_TYPES),                  print_generic, NULL },
    { ATTRIBUTE(CKA_MECHANISM_TYPE),              print_generic, NULL },
    { ATTRIBUTE(CKA_REQUIRED_CMS_ATTRIBUTES),     print_generic, NULL },
    { ATTRIBUTE(CKA_DEFAULT_CMS_ATTRIBUTES),      print_generic, NULL },
    { ATTRIBUTE(CKA_SUPPORTED_CMS_ATTRIBUTES),    print_generic, NULL },
    { ATTRIBUTE(CKA_ALLOWED_MECHANISMS),          print_generic, NULL }
};

CK_ULONG ck_attribute_num = sizeof(ck_attribute_specs)/sizeof(type_spec);

#include <stdio.h>

const char *lookup_enum_spec(enum_spec *spec, CK_ULONG value)
{
    CK_ULONG i;
    for(i = 0; i < spec->size; i++) {
        if(spec->specs[i].type == value) {
            return spec->specs[i].name;
        }
    }
    return NULL;
}

const char *lookup_enum(CK_ULONG type, CK_ULONG value)
{
    CK_ULONG i;
    for(i = 0; ck_types[i].type < ( sizeof(ck_types) / sizeof(enum_spec) ) ; i++) {
        if(ck_types[i].type == type) {
            return lookup_enum_spec(&(ck_types[i]), value);
        }
    }
    return NULL;
}

void show_error( FILE *f, char *str, CK_RV rc )
{
    fprintf(f, "%s returned:  %ld %s", str, rc, lookup_enum ( RV_T, rc ));
    fprintf(f, "\n");
}

void print_ck_info(FILE *f, CK_INFO *info)
{
    fprintf(f, "%20s:  %d.%d\n", "PKCS#11 Version",
            info->cryptokiVersion.major, info->cryptokiVersion.minor);
    fprintf(f, "%20s: '%32.32s'\n", "Manufacturer", info->manufacturerID);
    fprintf(f, "%20s:  %0lx\n", "Flags", info->flags);
    fprintf(f, "%20s: '%32.32s'\n", "Library Description", info->libraryDescription);
    fprintf(f, "%20s:  %d.%d\n", "Library Version",
            info->libraryVersion.major, info->libraryVersion.minor);
}

void print_slot_list(FILE *f, CK_SLOT_ID_PTR pSlotList, CK_ULONG ulCount)
{
    CK_ULONG          i;
    if(pSlotList) {
        for (i = 0; i < ulCount; i++) {
            fprintf(f, "Slot %ld\n", pSlotList[i]);
        }
    } else {
        fprintf(f, "Count is %ld\n", ulCount);
    }
}

void print_slot_info(FILE *f, CK_SLOT_INFO *info)
{
    int            i;
    enum_specs ck_flags[3] = {
        CONSTANT(CKF_TOKEN_PRESENT),
        CONSTANT(CKF_REMOVABLE_DEVICE),
        CONSTANT(CKF_HW_SLOT),
    };

    fprintf(f, "%20s: '%32.32s'\n", "Slot Description", info->slotDescription);
    fprintf(f, "%20s  '%32.32s'\n", "", info->slotDescription+32 );
    fprintf(f, "%20s: '%32.32s'\n", "Manufacturer", info->manufacturerID );
    fprintf(f, "%20s:  %d.%d\n", "Hardware Version",
            info->hardwareVersion.major, info->hardwareVersion.minor );
    fprintf(f, "%20s:  %d.%d\n", "Firmware Version",
            info->firmwareVersion.major, info->firmwareVersion.minor );
    fprintf(f, "%20s:  %0lx\n", "Flags", info->flags );
    for(i = 0; i < 3; i++) {
        if(info->flags & ck_flags[i].type) {
            fprintf(f, "%23s%s\n", "", ck_flags[i].name);
        }
    }
}

void print_token_info(FILE *f, CK_TOKEN_INFO *info)
{
    int            i;
    enum_specs ck_flags[18] = {
        CONSTANT(CKF_RNG),
        CONSTANT(CKF_WRITE_PROTECTED),
        CONSTANT(CKF_LOGIN_REQUIRED),
        CONSTANT(CKF_USER_PIN_INITIALIZED),
        CONSTANT(CKF_RESTORE_KEY_NOT_NEEDED),
        CONSTANT(CKF_CLOCK_ON_TOKEN),
        CONSTANT(CKF_PROTECTED_AUTHENTICATION_PATH),
        CONSTANT(CKF_DUAL_CRYPTO_OPERATIONS),
        CONSTANT(CKF_TOKEN_INITIALIZED),
        CONSTANT(CKF_SECONDARY_AUTHENTICATION),
        CONSTANT(CKF_USER_PIN_COUNT_LOW),
        CONSTANT(CKF_USER_PIN_FINAL_TRY),
        CONSTANT(CKF_USER_PIN_LOCKED),
        CONSTANT(CKF_USER_PIN_TO_BE_CHANGED),
        CONSTANT(CKF_SO_PIN_COUNT_LOW),
        CONSTANT(CKF_SO_PIN_FINAL_TRY),
        CONSTANT(CKF_SO_PIN_LOCKED),
        CONSTANT(CKF_SO_PIN_TO_BE_CHANGED)
    };

    fprintf(f, "%20s: '%32.32s'\n", "Label",                info->label);
    fprintf(f, "%20s: '%32.32s'\n", "Manufacturer",         info->manufacturerID);
    fprintf(f, "%20s: '%16.16s'\n", "Model",                info->model);
    fprintf(f, "%20s: '%16.16s'\n", "Serial Number",        info->serialNumber);
    fprintf(f, "%20s:  %ld\n",      "Max Session",          info->ulMaxSessionCount);
    fprintf(f, "%20s:  %ld\n",      "Session Count",        info->ulSessionCount);
    fprintf(f, "%20s:  %ld\n",      "Max R/W Session",      info->ulMaxRwSessionCount);
    fprintf(f, "%20s:  %ld\n",      "R/W Session",          info->ulRwSessionCount);
    fprintf(f, "%20s:  %ld\n",      "Max Pin Length",       info->ulMaxPinLen);
    fprintf(f, "%20s:  %ld\n",      "Min Pin Length",       info->ulMinPinLen);
    fprintf(f, "%20s:  %ld\n",      "Total Public Memory",  info->ulTotalPublicMemory);
    fprintf(f, "%20s:  %ld\n",      "Free Public Memory",   info->ulFreePublicMemory);
    fprintf(f, "%20s:  %ld\n",      "Total Private Memory", info->ulTotalPrivateMemory);
    fprintf(f, "%20s:  %ld\n",      "Free Private Memory",  info->ulFreePrivateMemory);
    fprintf(f, "%20s:  %d.%d\n",    "Hardware Version",
            info->hardwareVersion.major, info->hardwareVersion.minor);
    fprintf(f, "%20s:  %d.%d\n",    "FirmwareVersion",
            info->firmwareVersion.major, info->firmwareVersion.minor);
    fprintf(f, "%20s: '%16.16s'\n", "Time",                 info->utcTime);
    fprintf(f, "%20s:  %0lx\n",     "Flags",                info->flags);
    for(i = 0; i < 8; i++) {
        if(info->flags & ck_flags[i].type) {
            fprintf(f, "%23s%s\n", "", ck_flags[i].name);
        }
    }
}

void print_mech_list(FILE *f, CK_MECHANISM_TYPE_PTR pMechanismList,
                     CK_ULONG ulMechCount)
{
    CK_ULONG          imech;
    if(pMechanismList) {
        for (imech = 0; imech < ulMechCount; imech++) {
            const char *name = lookup_enum(MEC_T, pMechanismList[imech]);
            if (name) {
                fprintf(f, "%30s \n", name);
            } else {
                fprintf(f, " Unknown Mechanism (%08lx)  \n", pMechanismList[imech]);
            }
        }
    } else {
        fprintf(f, "Count is %ld\n", ulMechCount);
    }
}

void print_mech_info(FILE *f, CK_MECHANISM_TYPE type,
                     CK_MECHANISM_INFO_PTR minfo)
{
    const char *name = lookup_enum(MEC_T, type);
    CK_ULONG known_flags = CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_DIGEST|
        CKF_SIGN|CKF_SIGN_RECOVER|CKF_VERIFY|CKF_VERIFY_RECOVER|
        CKF_GENERATE|CKF_GENERATE_KEY_PAIR|CKF_WRAP|CKF_UNWRAP|
        CKF_DERIVE|CKF_EC_F_P|CKF_EC_F_2M|CKF_EC_ECPARAMETERS|
        CKF_EC_NAMEDCURVE|CKF_EC_UNCOMPRESS|CKF_EC_COMPRESS;


    if (name) {
        fprintf(f, "%-30s: ", name);
    } else {
        fprintf(f, "  Unknown Mechanism (%08lx): ", type);
    }
    printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
           (minfo->flags & CKF_HW)                ? "Hardware "   : "",
           (minfo->flags & CKF_ENCRYPT)           ? "Encrypt "    : "",
           (minfo->flags & CKF_DECRYPT)           ? "Decrypt "    : "",
           (minfo->flags & CKF_DIGEST)            ? "Digest "     : "",
           (minfo->flags & CKF_SIGN)              ? "Sign "       : "",
           (minfo->flags & CKF_SIGN_RECOVER)      ? "SigRecov "   : "",
           (minfo->flags & CKF_VERIFY)            ? "Verify "     : "",
           (minfo->flags & CKF_VERIFY_RECOVER)    ? "VerRecov "   : "",
           (minfo->flags & CKF_GENERATE)          ? "Generate "   : "",
           (minfo->flags & CKF_GENERATE_KEY_PAIR) ? "KeyPair "    : "",
           (minfo->flags & CKF_WRAP)              ? "Wrap "       : "",
           (minfo->flags & CKF_UNWRAP)            ? "Unwrap "     : "",
           (minfo->flags & CKF_DERIVE)            ? "Derive "     : "",
           (minfo->flags & CKF_EC_F_P)            ? "F(P) "       : "",
           (minfo->flags & CKF_EC_F_2M)           ? "F(2^M) "     : "",
           (minfo->flags & CKF_EC_ECPARAMETERS)   ? "EcParams "   : "",
           (minfo->flags & CKF_EC_NAMEDCURVE)     ? "NamedCurve " : "",
           (minfo->flags & CKF_EC_UNCOMPRESS)     ? "Uncompress " : "",
           (minfo->flags & CKF_EC_COMPRESS)       ? "Compress "   : "",
           (minfo->flags & ~known_flags)          ? "Unknown "    : "");
    fprintf(f, "%32s(min:%lu max:%lu flags:0x%06lX)\n", "",
            minfo->ulMinKeySize, minfo->ulMaxKeySize, minfo->flags);
}

void print_attribute_list(FILE *f, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG  ulCount)
{
    CK_ULONG j, k;
    for(j = 0; j < ulCount ; j++) {
        for(k = 0; k < ck_attribute_num; k++) {
            if(ck_attribute_specs[k].type == pTemplate[j].type) {
                fprintf(f, "    %s ", ck_attribute_specs[k].name);
                if(pTemplate[j].pValue) {
                    ck_attribute_specs[k].display
                        (f, pTemplate[j].type, pTemplate[j].pValue,
                         pTemplate[j].ulValueLen,
                         ck_attribute_specs[k].arg);
                } else {
                    fprintf(f, "has size %ld\n", pTemplate[j].ulValueLen); 
                }
                k = ck_attribute_num;
            }
        }
    }
}

void print_attribute_list_req(FILE *f, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG  ulCount)
{
    CK_ULONG j, k;
    for(j = 0; j < ulCount ; j++) {
        for(k = 0; k < ck_attribute_num; k++) {
            if(ck_attribute_specs[k].type == pTemplate[j].type) {
                fprintf(f, "    %s ", ck_attribute_specs[k].name);
                fprintf(f, "requested with %ld buffer\n", pTemplate[j].ulValueLen); 
                k = ck_attribute_num;
            }
        }
    }
}

void print_session_info(FILE *f, CK_SESSION_INFO *info)
{
    int            i;
    enum_specs ck_flags[2] = {
        CONSTANT(CKF_RW_SESSION),
        CONSTANT(CKF_SERIAL_SESSION)
    };

    fprintf(f, "%20s:  %ld\n", "Slot ID", info->slotID);
    fprintf(f, "%20s: '%32.32s'\n", "State",
            lookup_enum(STA_T, info->state));
    fprintf(f, "%20s:  %0lx\n", "Flags", info->flags);
    for(i = 0; i < 2; i++) {
        if(info->flags & ck_flags[i].type) {
            fprintf(f, "%32s%s\n", "", ck_flags[i].name);
        }
    }
    fprintf(f, "%20s:  %0lx\n", "Device Error", info->ulDeviceError );
}

int print_object_info(CK_FUNCTION_LIST *funcs, FILE *f, CK_ULONG j,
                      CK_SESSION_HANDLE h_session, CK_OBJECT_HANDLE  obj)
{
    CK_ULONG k, l;
    CK_ATTRIBUTE attribute;
    CK_RV rc;

    rc = funcs->C_GetObjectSize( h_session, obj, &k );
    if (rc != CKR_OK) {
        if(rc != CKR_FUNCTION_NOT_SUPPORTED) {
            show_error(stdout, "C_GetObjectSize", rc );
            rc = FALSE;
            goto done;
        }
        fprintf(f, "----------------\nObject %ld\n", j);
    } else {
        fprintf(f, "----------------\nObject %ld has size %ld\n", j, k);
    }

    for(k = 0, l = 0; k < ck_attribute_num; k++) {
        attribute.type = ck_attribute_specs[k].type;
        attribute.pValue = NULL;
        attribute.ulValueLen = 0;

        rc = funcs->C_GetAttributeValue( h_session, obj, &attribute, 1);
        if ((rc == CKR_OK) && ((CK_LONG)attribute.ulValueLen != -1)) {
            attribute.pValue = (CK_VOID_PTR) malloc(attribute.ulValueLen);

            rc = funcs->C_GetAttributeValue(h_session, obj, &attribute, 1);
            if (rc == CKR_OK) {
                fprintf(f, "(%02ld) %s ", l++, ck_attribute_specs[k].name);

                ck_attribute_specs[k].display
                    (stdout, attribute.type, attribute.pValue,
                     attribute.ulValueLen, ck_attribute_specs[k].arg);
            }
            free(attribute.pValue);
        } else if(rc == CKR_ATTRIBUTE_SENSITIVE) {
            fprintf(f, "(%02ld) %s is sensitive\n", l++,
                   ck_attribute_specs[k].name);
        } else if((rc != CKR_ATTRIBUTE_TYPE_INVALID) &&
                  (rc != CKR_TEMPLATE_INCONSISTENT)) {
            show_error(stdout, "C_GetAttributeValue", rc );
            rc = FALSE;
            goto done;
        }
    }

    rc = TRUE;
 done:
    return rc;
}
