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
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static const char *app_name = "pkcs11-util import";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { "certificate",        1, 0,           'c' },
    { "key",                1, 0,           'k' },
    { "label",              1, 0,           'l' },
    { "id",                 1, 0,           'i' },
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
    "Label to set",
    "Identifier to set",
};

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
    X509 *crt = NULL;
    EVP_PKEY *pkey = NULL;
    int long_optind = 0;
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
            case 'p':
                opt_pin = (CK_UTF8CHAR_PTR) strdup(optarg);
                if(opt_pin) {
                    opt_pin_len = strlen(optarg);
                }
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
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
                { CKA_CERTIFICATE_TYPE,   &type,   sizeof(type) },
                { CKA_SERIAL_NUMBER,      snbuf,   snl          },
                { CKA_SUBJECT,            sbuf,    sl           },
                { CKA_ISSUER,             ibuf,    il           },
                { CKA_VALUE,              cbuf,    cl           },
                { CKA_TOKEN,              &true,   sizeof(true) },
                { CKA_CLASS,              &cls,    sizeof(cls)  },
                { CKA_LABEL,              NULL,    0            }
            };

            if(opt_label) {
                crt_template[att_count].pValue     = opt_label;
                crt_template[att_count].ulValueLen = opt_label_len;
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
    }

    if(pkey) {
        PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
        CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE, hpKey = CK_INVALID_HANDLE;
        CK_BYTE *ptr = NULL, *buffer = NULL;
        CK_ULONG pl = 0, cl = 0;
        CK_BYTE iv[16];
        CK_MECHANISM mechanism = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
        CK_BBOOL true = CK_TRUE;
        CK_KEY_TYPE kt = CKK_RSA;
        CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
        CK_ULONG att_count = 7;
        CK_ATTRIBUTE template[9] = {
            { CKA_CLASS,       &cls,      sizeof(cls)   },
            { CKA_KEY_TYPE,    &kt,       sizeof(kt)    },
            { CKA_TOKEN,       &true,     sizeof(true)  },
            { CKA_PRIVATE,     &true,     sizeof(true)  },
            { CKA_SENSITIVE,   &true,     sizeof(true)  },
            { CKA_SIGN,        &true,     sizeof(true)  },
            { CKA_DECRYPT,     &true,     sizeof(true)  },
            { CKA_LABEL,       NULL_PTR, 0 },
            { CKA_ID,          NULL_PTR, 0 }
        };
        BIO *mem = BIO_new(BIO_s_mem());

        if(opt_label) {
            template[att_count].pValue     = opt_label;
            template[att_count].ulValueLen = opt_label_len;
            att_count += 1;
        }

        if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
            kt = CKK_RSA;
        } else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) { 
            kt = CKK_EC;
            template[7].type = CKA_DERIVE;
        } else {
            fprintf(stdout, "Error: unsupported key type\n");
            return rc;
        }

        if (!(pkcs8 = EVP_PKEY2PKCS8(pkey))) {
            fprintf(stdout, "Error converting key to PKCS#8\n");
            return rc;
        }

        i2d_PKCS8_PRIV_KEY_INFO_bio(mem, pkcs8);
        pl = BIO_get_mem_data(mem, &ptr);

        rc = generateSessionKey(funcs, h_session, CKK_AES, CKM_AES_KEY_GEN, 128 / 8, &hKey);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GenerateKey", rc);
            return rc;
        }

        buffer = malloc(pl + 16);
        cl = pl + 16;

        rc = funcs->C_GenerateRandom(h_session, iv, sizeof(iv));
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
    }

    rc = pkcs11_close(stdout, funcs, h_session);
    return rc;
}

#endif
