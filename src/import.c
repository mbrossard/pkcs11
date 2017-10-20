/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"

#ifdef HAVE_OPENSSL

#include "key.h"
#include "common.h"
#include "crypto.h"
#include "pkcs11_display.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

static const char *app_name = "pkcs11-util import";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { "certificate",        1, 0,           'c' },
    { "key",                1, 0,           'k' },
    { "pkcs12",             1, 0,           'x' },
    { "password",           1, 0,           'P' },
    { "label",              1, 0,           'l' },
    { "id",                 1, 0,           'i' },
    { "verbose",            0, 0,           'v' },
    { "check",              0, 0,           'C' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
    "Path of certificate to import",
    "Path of key to import",
    "Path of PKCS#12 file to import",
    "Password for key or PKCS#12",
    "Label to set",
    "Identifier to set",
    "Verbose output",
    "Check key after import",
};

CK_RV import_key_wrap(CK_FUNCTION_LIST  *funcs, CK_SESSION_HANDLE h_session, EVP_PKEY *pkey,
                      CK_ATTRIBUTE_PTR template, CK_ULONG att_count, CK_KEY_TYPE type)
{
    CK_RV rc = CKR_OK;
    CK_BYTE iv[16];
    CK_MECHANISM mechanism;
    PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE, hpKey = CK_INVALID_HANDLE;
    CK_BYTE *ptr = NULL, *buffer = NULL;
    CK_ULONG pl = 0, cl = 0, il;
    BIO *mem = BIO_new(BIO_s_mem());

    if (!(pkcs8 = EVP_PKEY2PKCS8(pkey))) {
        fprintf(stdout, "Error converting key to PKCS#8\n");
        return rc;
    }

    i2d_PKCS8_PRIV_KEY_INFO_bio(mem, pkcs8);
    pl = BIO_get_mem_data(mem, &ptr);

    if (type == CKK_AES) {
        rc = generateSessionKey(funcs, h_session, CKK_AES, CKM_AES_KEY_GEN, 128 / 8, &hKey);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GenerateKey", rc);
            return rc;
        }
        mechanism.mechanism = CKM_AES_CBC_PAD;
        il = 16;
    } else if (type == CKK_DES3) {
        rc = generateSessionKey(funcs, h_session, CKK_DES3, CKM_DES3_KEY_GEN, 0, &hKey);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GenerateKey", rc);
            return rc;
        }
        mechanism.mechanism = CKM_DES3_CBC_PAD;
        il = 8;
    } else {
        return CKR_ARGUMENTS_BAD;
    }
    mechanism.pParameter = iv;
    mechanism.ulParameterLen = il;

    buffer = malloc(pl + 16);
    cl = pl + 16;

    rc = funcs->C_GenerateRandom(h_session, iv, il);
    if (rc != CKR_OK) {
        show_error(stdout, "C_GenerateRandom", rc);
        return rc;
    }

    rc = funcs->C_EncryptInit(h_session, &mechanism, hKey);
    if (rc != CKR_OK) {
        show_error(stdout, "C_EncryptInit", rc);
        return rc;
    }

    rc = funcs->C_Encrypt(h_session, ptr, pl, buffer, &cl);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Encrypt", rc);
        return rc;
    }

    rc = funcs->C_UnwrapKey(h_session, &mechanism, hKey, buffer,
                            cl, template, att_count, &hpKey);
    if (rc != CKR_OK) {
        show_error(stdout, "C_UnwrapKey", rc);
        return rc;
    }

    free(buffer);
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    PKCS8_PRIV_KEY_INFO_free(pkcs8);

    return rc;
}

CK_RV import_rsa(CK_FUNCTION_LIST  *funcs, CK_SESSION_HANDLE h_session, EVP_PKEY *pkey,
                 CK_BYTE_PTR opt_label, CK_ULONG opt_label_len,
                 CK_BYTE_PTR opt_id, CK_ULONG opt_id_len)
{
    CK_BBOOL true = CK_TRUE;
    CK_KEY_TYPE kt = CKK_RSA;
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ULONG att_count = 7;
    CK_ATTRIBUTE template[9] = {
        { CKA_CLASS,     &cls,      sizeof(cls)   },
        { CKA_KEY_TYPE,  &kt,       sizeof(kt)    },
        { CKA_TOKEN,     &true,     sizeof(true)  },
        { CKA_PRIVATE,   &true,     sizeof(true)  },
        { CKA_SENSITIVE, &true,     sizeof(true)  },
        { CKA_SIGN,      &true,     sizeof(true)  },
        { CKA_DECRYPT,   &true,     sizeof(true)  },
        { 0,             NULL_PTR, 0 },
        { 0,             NULL_PTR, 0 }
    };

    if(opt_label) {
        template[att_count].type       = CKA_LABEL;
        template[att_count].pValue     = opt_label;
        template[att_count].ulValueLen = opt_label_len;
        att_count += 1;
    }
    if(opt_id) {
        template[att_count].type       = CKA_ID;
        template[att_count].pValue     = opt_id;
        template[att_count].ulValueLen = opt_id_len;
        att_count += 1;
    }

    return import_key_wrap(funcs, h_session, pkey, template, att_count, CKK_AES);
}

CK_RV import_ecdsa(CK_FUNCTION_LIST  *funcs, CK_SESSION_HANDLE h_session, EVP_PKEY *pkey,
                   CK_BYTE_PTR opt_label, CK_ULONG opt_label_len,
                   CK_BYTE_PTR opt_id, CK_ULONG opt_id_len)
{
    CK_OBJECT_HANDLE hpKey1 = CK_INVALID_HANDLE, hpKey2 = CK_INVALID_HANDLE;
    CK_RV rc = CKR_OK;
    CK_BBOOL true = CK_TRUE;
    CK_KEY_TYPE kt = CKK_EC;
    CK_OBJECT_CLASS cls1 = CKO_PRIVATE_KEY;
    CK_ULONG att_private = 7;
    CK_ATTRIBUTE private_template[11] = {
        { CKA_CLASS,        &cls1,    sizeof(cls1)  },
        { CKA_KEY_TYPE,     &kt,      sizeof(kt)    },
        { CKA_TOKEN,        &true,    sizeof(true)  },
        { CKA_PRIVATE,      &true,    sizeof(true)  },
        { CKA_SENSITIVE,    &true,    sizeof(true)  },
        { CKA_SIGN,         &true,    sizeof(true)  },
        { CKA_DERIVE,       &true,    sizeof(true)  },
        { 0,                NULL_PTR, 0 },
        { 0,                NULL_PTR, 0 },
        { 0,                NULL_PTR, 0 },
        { 0,                NULL_PTR, 0 }
    };
    CK_OBJECT_CLASS cls2 = CKO_PUBLIC_KEY;
    CK_ULONG att_public = 5;
    CK_ATTRIBUTE public_template[9] = {
        { CKA_CLASS,        &cls2,     sizeof(cls2)  },
        { CKA_KEY_TYPE,     &kt,       sizeof(kt)    },
        { CKA_TOKEN,        &true,     sizeof(true)  },
        { CKA_VERIFY,       &true,     sizeof(true)  },
        { CKA_DERIVE,       &true,     sizeof(true)  },
        { 0,                NULL_PTR,  0 },
        { 0,                NULL_PTR,  0 },
        { 0,                NULL_PTR,  0 },
        { 0,                NULL_PTR,  0 }
    };
    CK_BYTE ec_params[256], ec_point[256], ec_value[256], id[20];
    CK_ULONG ec_params_len, ec_point_len, ec_value_len;
    const BIGNUM *bn = NULL;
    CK_BYTE_PTR ptr = NULL;
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);

    if(opt_id) {
        private_template[att_private].type       = CKA_ID;
        private_template[att_private].pValue     = opt_id;
        private_template[att_private].ulValueLen = opt_id_len;
        att_private += 1;
        public_template[att_public].type       = CKA_ID;
        public_template[att_public].pValue     = opt_id;
        public_template[att_public].ulValueLen = opt_id_len;
        att_public += 1;
    }

    if(opt_label) {
        private_template[att_private].type       = CKA_LABEL;
        private_template[att_private].pValue     = opt_label;
        private_template[att_private].ulValueLen = opt_label_len;
        att_private += 1;
        public_template[att_public].type       = CKA_LABEL;
        public_template[att_public].pValue     = opt_label;
        public_template[att_public].ulValueLen = opt_label_len;
        att_public += 1;
    }

    if(i2d_ECParameters(ec, NULL) > sizeof(ec_params)) {
        fprintf(stdout, "Error: EC parameters too large\n");
        return CKR_BUFFER_TOO_SMALL;
    }
    ptr = ec_params;
    ec_params_len = i2d_ECParameters(ec, &ptr);

    if(i2o_ECPublicKey(ec, NULL) > sizeof(ec_point)) {
        fprintf(stdout, "Error: EC point too large\n");
        return CKR_BUFFER_TOO_SMALL;
    }
    ptr = ec_point;
    //ptr += 2;
    ec_point_len = i2o_ECPublicKey(ec, &ptr);
    //ec_point[0] = 0x04;
    //ec_point[1] = 0x41;
    //ec_point_len += 2;
    fprintf(stdout, "EC point %ld\n", ec_point_len);

    bn = EC_KEY_get0_private_key(ec);
    if(BN_num_bytes(bn) > sizeof(ec_value)) {
        fprintf(stdout, "Error: EC value too large\n");
        return CKR_BUFFER_TOO_SMALL;
    }
    ec_value_len = BN_bn2bin(bn, ec_value);
    fprintf(stdout, "EC value %ld\n", ec_value_len);
    /* TODO: BN_free */
    
#ifdef HAVE_OPENSSL
    if(!opt_id) {
        SHA1(ec_point, ec_point_len, id);
        private_template[att_private].type       = CKA_ID;
        private_template[att_private].pValue     = id;
        private_template[att_private].ulValueLen = sizeof(id);
        att_private += 1;

        public_template[att_public].type       = CKA_ID;
        public_template[att_public].pValue     = id;
        public_template[att_public].ulValueLen = sizeof(id);
        att_public += 1;
    }
#endif
    
    private_template[att_private].type       = CKA_ECDSA_PARAMS;
    private_template[att_private].pValue     = ec_params;
    private_template[att_private].ulValueLen = ec_params_len;
    att_private += 1;

    private_template[att_private].type       = CKA_EC_POINT;
    private_template[att_private].pValue     = ec_point;
    private_template[att_private].ulValueLen = ec_point_len;
    att_private += 1;

    rc = import_key_wrap(funcs, h_session, pkey, private_template, att_private, CKK_DES3);
    if (rc != CKR_OK) {
        show_error(stdout, "DES3-wrapped Key Import ", rc);
    }

    if (rc != CKR_OK) {
        rc = import_key_wrap(funcs, h_session, pkey, private_template, att_private, CKK_AES);
        if (rc != CKR_OK) {
            show_error(stdout, "AES-wrapped Key Import", rc);
        }
    }
    
    private_template[att_private].type       = CKA_VALUE;
    private_template[att_private].pValue     = ec_value;
    private_template[att_private].ulValueLen = ec_value_len;
    att_private += 1;

    if (rc != CKR_OK) {
        rc = funcs->C_CreateObject(h_session, private_template, att_private, &hpKey1);
        /* TODO: OPENSSL_cleanse ec_value */
        if (rc != CKR_OK) {
            show_error(stdout, "C_CreateObject", rc);
            return rc;
        }
    }

    public_template[att_public].type       = CKA_ECDSA_PARAMS;
    public_template[att_public].pValue     = ec_params;
    public_template[att_public].ulValueLen = ec_params_len;
    att_public += 1;

    public_template[att_public].type       = CKA_EC_POINT;
    public_template[att_public].pValue     = ec_point;
    public_template[att_public].ulValueLen = ec_point_len;
    att_public += 1;

    rc = funcs->C_CreateObject(h_session, public_template, att_public, &hpKey2);
    if (rc != CKR_OK) {
        show_error(stdout, "C_CreateObject", rc);
        rc = funcs->C_DestroyObject(h_session, hpKey1);
        if (rc != CKR_OK) {
            show_error(stdout, "C_DestroyObject", rc);
            return rc;
        }
        return rc;
    }

    return rc;
}

int import(int argc, char **argv)
{
    CK_ULONG          nslots;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_SESSION_HANDLE h_session;
    CK_BYTE_PTR       opt_label = NULL;
    CK_ULONG          opt_label_len = 0;
    CK_BYTE_PTR       opt_id = NULL;
    CK_ULONG          opt_id_len = 0;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_ULONG          opt_slot = -1;
    CK_RV             rc = 0;
    char *opt_module = NULL, *opt_dir = NULL;
    char *opt_crt = NULL, *opt_key = NULL;
    char *opt_pkcs12 = NULL, *opt_password = NULL;
    X509 *crt = NULL;
    EVP_PKEY *pkey = NULL;
    int long_optind = 0, opt_verbose = 0;
    char c;

    init_crypto();

    while (1) {
        c = getopt_long(argc, argv, "d:hl:p:s:m:",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'c':
                opt_crt = optarg;
                break;
            case 'd':
                opt_dir = optarg;
                break;
            case 'k':
                opt_key = optarg;
                break;
            case 'l':
                if((opt_label = (CK_BYTE_PTR)optarg)) {
                    opt_label_len = strlen(optarg);
                }
                break;
            case 'i':
                if((opt_id = (CK_BYTE_PTR)optarg)) {
                    opt_id_len = strlen(optarg);
                }
                break;
            case 'p':
                opt_pin = (CK_UTF8CHAR_PTR) strdup(optarg);
                if(opt_pin) {
                    opt_pin_len = strlen(optarg);
                }
                break;
            case 'P':
                opt_password = optarg;
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'v':
                opt_verbose = 1;
                break;
            case 'x':
                opt_pkcs12 = optarg;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    if(!opt_module) {
        print_usage_and_die(app_name, options, option_help);
    }

    if (opt_crt) {
        BIO *crt_bio = BIO_new_file(opt_crt, "r");
        if(!crt_bio) {
            fprintf(stderr, "Error loading certificate file '%s'\n", opt_crt);
            return -1;
        }
        crt = PEM_read_bio_X509_AUX(crt_bio, NULL, NULL, NULL);
        if(!crt) {
            BIO_reset(crt_bio);
            crt = d2i_X509_bio(crt_bio, NULL);
        }
        if(!crt) {
            fprintf(stderr, "Error parsing certificate file '%s'\n", opt_crt);
            return -1;
        }
    }

    if (opt_key) {
        BIO *key_bio = BIO_new_file(opt_key, "r");
        if(!key_bio) {
            fprintf(stderr, "Error loading key file '%s'\n", opt_key);
            return -1;
        }

        pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
        if(!pkey) {
            BIO_reset(key_bio);
            pkey = d2i_PrivateKey_bio(key_bio, NULL);
        }
        if(!pkey) {
            fprintf(stderr, "Error parsing key file '%s'\n", opt_key);
            return -1;
        }
    }

    if(opt_pkcs12) {
        PKCS12 *p12;
        FILE *fp = NULL;

        if(opt_key) {
            fprintf(stderr, "Incompatible argument --key with --pkcs12\n");
            return -1;
        }
        if(opt_key) {
            fprintf(stderr, "Incompatible argument --crt with --pkcs12\n");
            return -1;
        }

        if(!opt_password) {
            fprintf(stderr, "Missing --password argument with --pkcs12\n");
            return -1;
        }

        if (!(fp = fopen(opt_pkcs12, "rb"))) {
            fprintf(stderr, "Error opening file %s\n", opt_pkcs12);
            return -1;
        }

        p12 = d2i_PKCS12_fp(fp, NULL);
        fclose (fp);
        if (!p12) {
            fprintf(stderr, "Error loading PKCS#12 file\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }

        if (!PKCS12_parse(p12, opt_password, &pkey, &crt, NULL)) {
            fprintf(stderr, "Error parsing PKCS#12 file\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }

        PKCS12_free(p12);
    }
    
    rc = pkcs11_load_init(opt_module, opt_dir, stdout, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stdout, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }

    if (opt_slot != -1) {
        CK_ULONG i = 0;
        while (i < nslots && pslots[i] != opt_slot) {
            i++;
        }
        if (i == nslots) {
            fprintf(stderr, "Unknown slot '%lu'\n", opt_slot);
            return -1;            
        }
    } else {
        if (nslots == 1) {
            opt_slot = pslots[0];
        } else {
            fprintf(stdout, "Found %ld slots, use --slot parameter to choose.\n", nslots);
            exit(-1);
        }
    }

    rc = pkcs11_login_session(funcs, stdout, opt_slot, &h_session,
                              CK_TRUE, CKU_USER, opt_pin, opt_pin_len);
    free(opt_pin);
    if (rc != CKR_OK) {
        return rc;
    }

    if (crt) {
        X509_NAME *subject = X509_get_subject_name(crt),
            *issuer = X509_get_issuer_name(crt);
        ASN1_INTEGER *serial = X509_get_serialNumber(crt);
        size_t cl = i2d_X509(crt, NULL), sl = i2d_X509_NAME(subject, NULL),
            il = i2d_X509_NAME(issuer, NULL), snl = i2d_ASN1_INTEGER(serial, NULL);
        unsigned char *cbuf = NULL, *sbuf = NULL, *ibuf = NULL,
            *snbuf = NULL, *ptr = NULL;

        if((cbuf = malloc(cl)) && (sbuf = malloc(sl)) &&
           (ibuf = malloc(il)) && (snbuf = malloc(snl))) {
            CK_BBOOL true = CK_TRUE;
            CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
            CK_CERTIFICATE_TYPE type = CKC_X_509;
            CK_OBJECT_HANDLE c_handle;
            CK_ULONG att_count = 7;
            CK_ATTRIBUTE crt_template[] = {
                { CKA_CERTIFICATE_TYPE, &type,   sizeof(type) },
                { CKA_SERIAL_NUMBER,    snbuf,   snl          },
                { CKA_SUBJECT,          sbuf,    sl           },
                { CKA_ISSUER,           ibuf,    il           },
                { CKA_VALUE,            cbuf,    cl           },
                { CKA_TOKEN,            &true,   sizeof(true) },
                { CKA_CLASS,            &cls,    sizeof(cls)  },
                { 0,                    NULL,    0            },
                { 0,                    NULL,    0            }
            };

            if(opt_label) {
                crt_template[att_count].type       = CKA_LABEL;
                crt_template[att_count].pValue     = opt_label;
                crt_template[att_count].ulValueLen = opt_label_len;
                att_count += 1;
            }
            if(opt_id) {
                crt_template[att_count].type       = CKA_ID;
                crt_template[att_count].pValue     = opt_id;
                crt_template[att_count].ulValueLen = opt_id_len;
                att_count += 1;
            }

            ptr = cbuf;
            i2d_X509(crt, &ptr);
            ptr = sbuf;
            i2d_X509_NAME(subject, &ptr);
            ptr = ibuf;
            i2d_X509_NAME(issuer, &ptr);
            ptr = snbuf;
            i2d_ASN1_INTEGER(serial, &ptr);

            rc = funcs->C_CreateObject(h_session, crt_template, att_count, &c_handle);
            if (rc != CKR_OK) {
                show_error(stdout, "C_CreateObject", rc);
                return rc;
            }
        }

        free(cbuf);
        free(sbuf);
        free(ibuf);
        free(snbuf);
        X509_free(crt);
        /* TODO: Find CKA_ID and CKA_LABEL */
    }

    if(pkey) {
        if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
            import_rsa(funcs, h_session, pkey, opt_label, opt_label_len,
                       opt_id, opt_id_len);
        } else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
            import_ecdsa(funcs, h_session, pkey, opt_label, opt_label_len,
                         opt_id, opt_id_len);
        } else {
            fprintf(stdout, "Error: unsupported key type\n");
        }
    }

    rc = pkcs11_close(stdout, funcs, h_session);
    return rc;
}

#endif
