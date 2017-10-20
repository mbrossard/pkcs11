/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"
#include "crypto.h"
#include "network.h"
#include "pkcs11_display.h"

#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define KEY_ID_SIZE 64 /* 256 * 2 / 8 */

typedef struct {
    char id[KEY_ID_SIZE];
    EVP_PKEY *key;
} key_id_t;

int load_keys(CK_FUNCTION_LIST *funcs,
              CK_SESSION_HANDLE h_session,
              CK_KEY_TYPE       type,
              key_id_t        **out,
              CK_ULONG_PTR      len)
{
    CK_RV             rc;
    CK_ULONG          l, i, j = 0;
    CK_OBJECT_HANDLE  handles[1024];
    key_id_t         *keys = NULL;
    CK_OBJECT_CLASS   pkey = CKO_PRIVATE_KEY;
    const EVP_MD *hash = EVP_sha256();
    unsigned char md[EVP_MAX_MD_SIZE];
    char key_id[KEY_ID_SIZE + 1];
    CK_ATTRIBUTE search[2] = {
        { CKA_CLASS,    &pkey, sizeof(pkey)},
        { CKA_KEY_TYPE, &type, sizeof(type)     },
    };

    rc = funcs->C_FindObjectsInit(h_session, search, 2);
    if (rc != CKR_OK) {
        show_error(stderr, "C_FindObjectsInit", rc);
        return 1;
    }

    rc = funcs->C_FindObjects(h_session, handles, 1024, &l);
    if (rc != CKR_OK) {
        show_error(stderr, "C_FindObjects", rc);
        return 1;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stderr, "C_FindObjectsFinal", rc);
    }

    keys = (key_id_t*)calloc(l, sizeof(key_id_t));
    if(keys == NULL) {
        return 1;
    }

    fprintf(stderr, "Found: %ld objects\n", l);
    BIO *bio = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    for(i = 0; i < l; i++) {
        // print_object_info(funcs, stderr, i, h_session, handles[i]);
        keys[j].key = load_pkcs11_key(funcs, h_session, handles[i]);
        if(keys[j].key) {
            unsigned int k, l, n;
            BIO *s = BIO_new(BIO_s_null());
            BIO *h = BIO_new(BIO_f_md());
            BIO_set_md(h, hash);
            s = BIO_push(h, s);
            /*
            if(type == CKK_RSA) {
                i2d_RSAPublicKey_bio(s, EVP_PKEY_get1_RSA(keys[j].key));
                PEM_write_bio_RSAPrivateKey(bio, EVP_PKEY_get1_RSA(keys[j].key), NULL, NULL, 0, NULL, NULL);
            } if(type == CKK_EC) {
                i2d_EC_PUBKEY_bio(s, EVP_PKEY_get1_EC_KEY(keys[j].key));
                PEM_write_bio_ECPrivateKey(bio, EVP_PKEY_get1_EC_KEY(keys[j].key), NULL, NULL, 0, NULL, NULL);
            }
            */
            PEM_write_bio_PrivateKey(bio, keys[j].key, NULL, NULL, 0, NULL, NULL);
            n = BIO_gets(h, (char*)md, EVP_MAX_MD_SIZE);
            for(k = 0, l = 0; k < n; k++) {
                l += sprintf(key_id + l, "%02X", md[k]);
            }
            memcpy(keys[j].id, key_id, KEY_ID_SIZE);
            BIO_free_all(s);
            j += 1;
        }
    }
    if (bio) {
        BIO_free_all(bio);
    }

    if(out) {
        *out = keys;
    } else {
        for(i = 0; i < j; i++) {
            unload_pkcs11_key(keys[i].key);
        }
    }

    if(len) {
        *len = j;
    }

    return 0;
}

static char *app_name = "pkcs11d";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { "verbose",            0, 0,           'v' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
    "Display additional information",
};

int main(int argc, char **argv)
{
    CK_ULONG          nslots;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL, *opt_unix = NULL;
    struct sockaddr_un sockaddr;
    int long_optind = 0;
    int fd, verbose = 0, opt_port = 1234;
    key_id_t *rsa_keys, *ec_keys;
    CK_ULONG rsa_len = 0, ec_len = 0, i;

    init_crypto();

    while (1) {
        char c = getopt_long(argc, argv, "d:hp:s:m:vP:U:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
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
            case 'v':
                verbose = 1;
                break;
            case 'P':
                opt_port = atoi(optarg);
                break;
            case 'U':
                opt_unix = optarg;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    rc = pkcs11_load_init(opt_module, opt_dir, stderr, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stderr, &pslots, &nslots);
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

    fprintf(stderr, "Slot: %ld\n", opt_slot);
    rc = pkcs11_login_session(funcs, stderr, opt_slot, &h_session,
                              CK_TRUE, CKU_USER, opt_pin, opt_pin_len);
    if (rc != CKR_OK) {
        show_error(stderr, "Login", rc);
        return rc;
    }
    
    load_keys(funcs, h_session, CKK_RSA, &rsa_keys, &rsa_len);
    load_keys(funcs, h_session, CKK_EC,  &ec_keys,  &ec_len);

    if(opt_unix) {
        fd = nw_unix_server("pkcs11d.sock", &sockaddr, 0, 0, 0, 64);
    } else {
        fd = nw_tcp_server(opt_port, 0, 64);
    }

    do {
        struct sockaddr address;
        socklen_t a_len = sizeof(address);
        int s = accept(fd, &address, &a_len);
        BIO *b = BIO_new_socket(s, BIO_NOCLOSE);
        BIO *buf = BIO_new(BIO_f_buffer());
        b = BIO_push(buf, b);
        char buffer[4096], output[4096], keyid[KEY_ID_SIZE + 1];
        int l, slen = 0, plen = 0;
        CK_KEY_TYPE type;
        CK_ATTRIBUTE_TYPE operation;
        EVP_PKEY *pkey = NULL;

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l <= 0) {
            fprintf(stderr, "Error reading query line\n");
            goto end;
        }

        if(strncmp(buffer, "POST /sign/rsa/", 15) == 0) {
            memcpy(keyid, buffer + 15, KEY_ID_SIZE - 1);
            type = CKK_RSA;
            operation = CKA_SIGN;
        } else if(strncmp(buffer, "POST /decrypt/rsa/", 18) == 0) {
            memcpy(keyid, buffer + 18, KEY_ID_SIZE - 1);
            type = CKK_RSA;
            operation = CKA_DECRYPT;
        } else if(strncmp(buffer, "POST /sign/ec/", 14) == 0) {
            memcpy(keyid, buffer + 14, KEY_ID_SIZE - 1);
            type = CKK_EC;
            operation = CKA_SIGN;
        } else if(strncmp(buffer, "POST /decrypt/ec/", 17) == 0) {
            memcpy(keyid, buffer + 17, KEY_ID_SIZE - 1);
            type = CKK_EC;
            operation = CKA_DECRYPT;
        } else {
            fprintf(stderr, "Invalid query line = %s\n", buffer);
            goto end;
        }
        keyid[KEY_ID_SIZE] = '\0';
        fprintf(stderr, "Key ID = %s\n", keyid);

        l = BIO_gets(b, buffer, sizeof(buffer));
        if((l <= 0) || strncmp(buffer, "Content-Length: ", 16) != 0) {
            fprintf(stderr, "Invalid content length line = %s\n", buffer);
            goto end;
        }
        plen = atoi(buffer + 16);
        fprintf(stderr, "Payload size = %d\n", plen);

        l = BIO_gets(b, buffer, sizeof(buffer));
        /* TODO: add check */

        l = BIO_read(b, buffer, plen);
        if(l < plen) {
            fprintf(stderr, "Error reading payload\n");
            goto end;
        }
        fprintf(stderr, "Read payload size = %d (%d)\n", l, plen);

        if(type == CKK_RSA) {
            for(i = 0; (i < rsa_len) && (pkey == NULL); i++) {
                if(strncmp(rsa_keys[i].id, keyid, KEY_ID_SIZE - 1) == 0) {
                    pkey = rsa_keys[i].key;
                }
            }
        } else if(type == CKK_EC) {
            for(i = 0; (i < ec_len) && (pkey == NULL); i++) {
                if(strncmp(ec_keys[i].id, keyid, KEY_ID_SIZE - 1) == 0) {
                    pkey = ec_keys[i].key;
                }
            }
        }
        if(pkey == NULL) {
            fprintf(stderr, "Key '%s' not found\n", keyid);
            goto end;
        } else if(verbose) {
            fprintf(stderr, "Key '%s'found\n", keyid);
        }
        
        if(type == CKK_RSA && operation == CKA_SIGN) {
            l = RSA_private_encrypt(plen, (unsigned char *)buffer, (unsigned char *)output,
                                    EVP_PKEY_get1_RSA(pkey), RSA_PKCS1_PADDING);
            if(verbose) {
                fprintf(stderr, "RSA signature operation with key '%s'\n", keyid);
            }
        } else if(type == CKK_RSA && operation == CKA_DECRYPT) {
            l = RSA_private_decrypt(plen, (unsigned char *)buffer, (unsigned char *)output,
                                    EVP_PKEY_get1_RSA(pkey), RSA_PKCS1_PADDING);
            if(verbose) {
                fprintf(stderr, "RSA decryption operation with key '%s'\n", keyid);
            }
        } else if (type == CKK_EC && operation == CKA_SIGN) {
            unsigned char *ptr = (unsigned char *)output;
            ECDSA_SIG *s = ECDSA_do_sign((unsigned char *)buffer, plen, EVP_PKEY_get1_EC_KEY(pkey));
            l = i2d_ECDSA_SIG(s, &ptr);
            ECDSA_SIG_free(s);
            if(verbose) {
                fprintf(stderr, "ECDSA signature operation with key '%s'\n", keyid);
            }
        } else if(type == CKK_EC && operation == CKA_DECRYPT) {
            const EC_GROUP *group = EC_KEY_get0_group(EVP_PKEY_get1_EC_KEY(pkey));
            EC_POINT *p = EC_POINT_new(group);
            /*
            int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
                                   const unsigned char *buf, size_t len, BN_CTX *ctx);
            */
            EC_POINT_oct2point(group, p, (unsigned char *)buffer, plen, NULL);
            
            /*
            l = ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                                 EC_KEY *ecdh, void *(*KDF) (const void *in, size_t inlen,
                                 void *out, size_t *outlen));
            */
            l = ECDH_compute_key((void *)output, sizeof(output), p, EVP_PKEY_get1_EC_KEY(pkey), 0);
            if(verbose) {
                fprintf(stderr, "ECDH decryption operation with keyid '%s'\n", keyid);
            }
        } else {
            if(verbose) {
                fprintf(stderr, "Invalid operation requested\n");
            }
            goto end;
        }

        slen = l;
        if(l <= 0) {
            if(verbose) {
                fprintf(stderr, "Error unsuccessful\n");
            }
            goto end;
        } else if(verbose) {
            fprintf(stderr, "Operation successful\n");
        }
        fprintf(stderr, "Response size = %d\n", l);

        BIO_printf(b, "200 Ok\r\n");
        BIO_printf(b, "Content-Length: %d\r\n\r\n", slen);

        l = BIO_write(b, output, slen);
        if(l > 0) {
            fprintf(stderr, "Write size = %d\n", l);
        } else {
            fprintf(stderr, "Oups\n");
        }

        BIO_flush(b);

        i= 0;
        /*
        for(i = 0; i < rsa_len; i++) {
            BIO_write(b, rsa_keys[i].id, KEY_ID_SIZE);
            BIO_write(b, "\n", 1);
            PEM_write_bio_RSAPrivateKey(b, EVP_PKEY_get1_RSA(rsa_keys[i].key), NULL, NULL, 0, NULL, NULL);
        }
        for(i = 0; i < ec_len; i++) {
            BIO_write(b, ec_keys[i].id, KEY_ID_SIZE);
            BIO_write(b, "\n", 1);
            PEM_write_bio_ECPrivateKey(b, EVP_PKEY_get1_EC_KEY(ec_keys[i].key), NULL, NULL, 0, NULL, NULL);
        }
        */

        sleep(1);

    end:
        close(s);
        BIO_free(b);
    } while(1);

    close(fd);

    if(opt_pin) {
        funcs->C_CloseAllSessions(opt_slot);
        free(opt_pin);
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stderr, "C_Finalize", rc);
        return rc;
    }
    
    return rc;
}
