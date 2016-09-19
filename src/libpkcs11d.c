#include <stdio.h>
#include <string.h>

#include "config.h"

#include <openssl/ossl_typ.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
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

#if OPENSSL_VERSION_NUMBER < 0x10100005L
#define EVP_PKEY_id(pkey) pkey->type
#endif

#define ENGINE_ID   "pkcs11d"
#define ENGINE_NAME "pkcs11d"

#define KEY_ID_SIZE 64 /* 256 * 2 / 8 */

struct pkcs11d_data {
    char id[KEY_ID_SIZE + 1];
};

static int engine_init(ENGINE * engine)
{
	(void)engine;
	return 1;
}

static int engine_destroy(ENGINE * engine)
{
	(void)engine;
	return 1;
}

static int engine_finish(ENGINE * engine)
{
	(void)engine;
	return 1;
}

static int engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ())
{
	(void)e;
	(void)cmd;
	(void)i;
	(void)p;
	(void)f;
	return 0;
}

static const ENGINE_CMD_DEFN engine_cmd_defns[] = {
	{0, NULL, NULL, 0}
};

/* RSA */
static int pkcs11d_rsa_key_idx = -1;

static int pkcs11d_rsa_private_common(const char *op, int flen, const unsigned char *from,
                                      unsigned char *to, RSA *rsa, int padding)
{
    struct pkcs11d_data *pkd = NULL;
    int rval = -1;

    if(((pkd = RSA_get_ex_data(rsa, pkcs11d_rsa_key_idx)) != NULL)) {
        BIO *b = BIO_new_connect("127.0.0.1");
        BIO *buf = BIO_new(BIO_f_buffer());
        char buffer[4096];
        int l, slen = 0;

        BIO_set_conn_port(b, "1234");
        b = BIO_push(buf, b);

        /* Insert implementation here */

        BIO_printf(b, "POST /%s/rsa/%s HTTP/1.0\r\n", op, pkd->id);
        BIO_printf(b, "Content-Length: %d\r\n\r\n", flen);
        BIO_write(b, from, flen);
        BIO_flush(b);

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l <= 0) {
            goto end;
        } else {
            /* TODO: Check error code */
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l > 0) {
            buffer[sizeof(buffer) - 1] = '\0';
            if(strncmp(buffer, "Content-Length: ", 16) == 0) {
                slen = atoi(buffer + 16);
            }
            if(slen <= 0) {
                goto end;
            }
        } else {
            goto end;
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        l = BIO_read(b, buffer, slen);

        if(l > 0) {
            memcpy(to, buffer, l);
            rval = l;
        }

    end:
        BIO_free_all(b);
    }

	return rval;
}

static int pkcs11d_rsa_private_encrypt(int flen, const unsigned char *from,
                                       unsigned char *to, RSA *rsa, int padding)
{
    return pkcs11d_rsa_private_common("sign", flen, from, to, rsa, padding);
}

static int pkcs11d_rsa_private_decrypt(int flen, const unsigned char *from,
                                       unsigned char *to, RSA *rsa, int padding)
{
    return pkcs11d_rsa_private_common("decrypt", flen, from, to, rsa, padding);
}

static RSA_METHOD *engine_rsa_method(void)
{
	static RSA_METHOD *pkcs11d_rsa_method = NULL;
	if(pkcs11d_rsa_key_idx == -1) {
		pkcs11d_rsa_key_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11d_rsa_method == NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100005L        
		const RSA_METHOD *def = RSA_get_default_method();
		pkcs11d_rsa_method = calloc(1, sizeof(*pkcs11d_rsa_method));
		memcpy(pkcs11d_rsa_method, def, sizeof(*pkcs11d_rsa_method));
		pkcs11d_rsa_method->name = "pkcs11d";
		pkcs11d_rsa_method->rsa_priv_enc = pkcs11d_rsa_private_encrypt;
		pkcs11d_rsa_method->rsa_priv_dec = pkcs11d_rsa_private_decrypt;
#else
        pkcs11d_rsa_method = RSA_meth_dup(RSA_get_default_method());
        RSA_meth_set1_name(pkcs11d_rsa_method, "pkcs11d");
        RSA_meth_set_priv_enc(pkcs11d_rsa_method, pkcs11d_rsa_private_encrypt);
        RSA_meth_set_priv_dec(pkcs11d_rsa_method, pkcs11d_rsa_private_decrypt);
#endif
	}
	return pkcs11d_rsa_method;
}

#ifndef OPENSSL_NO_EC

static int pkcs11d_ec_key_idx = -1;

#ifdef ENABLE_PKCS11_ECDSA
/* ECDSA */
static ECDSA_SIG *pkcs11d_ecdsa_sign(const unsigned char *dgst, int dgst_len,
                                     const BIGNUM *inv, const BIGNUM *rp,
                                     EC_KEY *ec) {
    struct pkcs11d_data *pkd = NULL;
    ECDSA_SIG *rval = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    pkd = ECDSA_get_ex_data(ec, pkcs11d_ec_key_idx);
#else
    pkd = EC_KEY_get_ex_data(ec, pkcs11d_ec_key_idx);
#endif

    if(pkd != NULL) {
        BIO *b = BIO_new_connect("127.0.0.1");
        BIO *buf = BIO_new(BIO_f_buffer());
        char buffer[4096];
        int l, slen = 0;

        BIO_set_conn_port(b, "1234");
        b = BIO_push(buf, b);
        
        BIO_printf(b, "POST /sign/ec/%s HTTP/1.0\r\n", pkd->id);
        BIO_printf(b, "Content-Length: %d\r\n\r\n", dgst_len);
        BIO_write(b, dgst, dgst_len);
        BIO_flush(b);

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l <= 0) {
            goto end;
        } else {
            /* TODO: Check error code */
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l > 0) {
            buffer[sizeof(buffer) - 1] = '\0';
            if(strncmp(buffer, "Content-Length: ", 16) == 0) {
                slen = atoi(buffer + 16);
            }
            if(slen <= 0) {
                goto end;
            }
        } else {
            goto end;
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        l = BIO_read(b, buffer, slen);

        const unsigned char *ptr = (const unsigned char *)buffer;
        rval = d2i_ECDSA_SIG(NULL, &ptr, slen);

    end:
        BIO_free_all(b);
    }
    return rval;
}
#endif

#ifndef OPENSSL_NO_ECDH

static int pkcs11d_ecdh_derive(unsigned char *out, size_t outlen,
                               const EC_POINT *peer_point, const EC_KEY *ecdh)
{
    struct pkcs11d_data *pkd = NULL;
    int rval = -1;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    pkd = ECDH_get_ex_data((EC_KEY *)ecdh, pkcs11d_ec_key_idx);
#else
    pkd = EC_KEY_get_ex_data(ecdh, pkcs11d_ec_key_idx);
#endif

    if(pkd != NULL) {
        BIO *b = BIO_new_connect("127.0.0.1");
        BIO *buf = BIO_new(BIO_f_buffer());
        char buffer[4096];
        int l, slen = 0;

        const EC_GROUP *group = EC_KEY_get0_group(ecdh);        
        slen = EC_POINT_point2oct(group, peer_point, POINT_CONVERSION_UNCOMPRESSED,
                                  (unsigned char *) buffer, sizeof(buffer), NULL);

        BIO_set_conn_port(b, "1234");
        b = BIO_push(buf, b);

        BIO_printf(b, "POST /decrypt/ec/%s HTTP/1.0\r\n", pkd->id);
        BIO_printf(b, "Content-Length: %d\r\n\r\n", slen);
        BIO_write(b, buffer, slen);
        BIO_flush(b);

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l <= 0) {
            goto end;
        }
        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l > 0) {
            slen = 0;
            buffer[sizeof(buffer) - 1] = '\0';
            if(strncmp(buffer, "Content-Length: ", 16) == 0) {
                slen = atoi(buffer + 16);
            }
            if(slen <= 0) {
                goto end;
            }
        } else {
            goto end;
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        l = BIO_read(b, buffer, slen);

        if(l > 0) {
            memcpy(out, buffer, l);
            rval = l;
        }

    end:
        BIO_free_all(b);
    }
    return rval;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100004L
static int pkcs11d_compute_key(unsigned char **out, size_t *outlen,
                               const EC_POINT *point, const EC_KEY *ec_key)
{
    unsigned char buffer[4096];
    int l = pkcs11d_ecdh_derive(buffer, sizeof(buffer), point, ec_key);

    if(l <= 0) {
        return 0;
    }

    if((*out = (unsigned char *)malloc(l)) == NULL) {
        return 0;
    }
    memcpy(*out, buffer, l);
    *outlen = l;
    return 1;
}

#else

static int pkcs11d_compute_key(void *out, size_t outlen,
                               const EC_POINT *point, const EC_KEY *ec_key,
                               void *(*KDF) (const void *in, size_t inlen,
                                             void *out, size_t *outlen))
{
    unsigned char buffer[4096];
    int l = pkcs11d_ecdh_derive(buffer, sizeof(buffer), point, ec_key);


	if (KDF) {
		if (KDF(buffer, l, out, &outlen) == NULL) {
			return -1;
		}
	} else {
		if (outlen > l) { 
			outlen = l;
        }
		memcpy(out, buffer, outlen);
	}

    return outlen;
}
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#ifdef ENABLE_PKCS11_ECDSA
static ECDSA_METHOD *engine_ecdsa_method(void)
{
    static ECDSA_METHOD *pkcs11d_ecdsa_method = NULL;
	if(pkcs11d_ec_key_idx == -1) {
		pkcs11d_ec_key_idx = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11d_ecdsa_method == NULL) {
		const ECDSA_METHOD *def = ECDSA_get_default_method();
#ifdef ECDSA_F_ECDSA_METHOD_NEW
		pkcs11d_ecdsa_method = ECDSA_METHOD_new((ECDSA_METHOD *)def);
		ECDSA_METHOD_set_name(pkcs11d_ecdsa_method, "pkcs11d");
		ECDSA_METHOD_set_sign(pkcs11d_ecdsa_method, pkcs11d_ecdsa_sign);
#else
		pkcs11d_ecdsa_method = calloc(1, sizeof(*pkcs11d_ecdsa_method));
		memcpy(pkcs11d_ecdsa_method, def, sizeof(*pkcs11d_ecdsa_method));
		pkcs11_ecdsa_method->name = "pkcs11d";
		pkcs11_ecdsa_method->ecdsa_do_sign = pkcs11d_ecdsa_sign;
#endif
	}
	return pkcs11d_ecdsa_method;
}
#endif

#ifndef OPENSSL_NO_ECDH
static ECDH_METHOD *engine_ecdh_method(void)
{
	return NULL;
}
#endif

#else

static EC_KEY_METHOD *engine_ec_method(void)
{
    static EC_KEY_METHOD *pkcs11d_ec_method = NULL;
	if(pkcs11d_ec_key_idx == -1) {
		pkcs11d_ec_key_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11d_ec_method == NULL) {
        int (*sig)(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
                    unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey) = NULL;
		pkcs11d_ec_method = EC_KEY_METHOD_new(EC_KEY_get_default_method());
        EC_KEY_METHOD_get_sign(pkcs11d_ec_method, &sig, NULL, NULL);
		EC_KEY_METHOD_set_sign(pkcs11d_ec_method, sig, NULL, pkcs11d_ecdsa_sign);
	}
	return pkcs11d_ec_method;
}
#endif

#endif /* OPENSSL_NO_EC */

static EVP_PKEY *engine_load_private_key(ENGINE * e, const char *path,
                                         UI_METHOD * ui_method, void *callback_data)
{
    EVP_PKEY *pkey = NULL;
    BIO *key = BIO_new_file(path, "r");
    if(key) {
        pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);

        if(pkey) {
            unsigned int k, l, n;
            unsigned char md[EVP_MAX_MD_SIZE];
            char key_id[KEY_ID_SIZE + 1];
            const EVP_MD *hash = EVP_sha256();
            BIO *s = BIO_new(BIO_s_null());
            BIO *h = BIO_new(BIO_f_md());
            BIO_set_md(h, hash);
            s = BIO_push(h, s);

            if(EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
                i2d_RSAPublicKey_bio(s, EVP_PKEY_get1_RSA(pkey));
            } else if(EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
                i2d_EC_PUBKEY_bio(s, EVP_PKEY_get1_EC_KEY(pkey));
            }
            n = BIO_gets(h, (char*)md, EVP_MAX_MD_SIZE);
            for(k = 0, l = 0; k < n; k++) {
                l += sprintf(key_id + l, "%02X", md[k]);
            }
            fprintf(stderr, "key id=%s\n", key_id);
            struct pkcs11d_data *pd = (struct pkcs11d_data *) malloc(sizeof(struct pkcs11d_data));
            memcpy(pd->id, key_id, sizeof(key_id));
            
            if(EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
                RSA_set_method(EVP_PKEY_get1_RSA(pkey), engine_rsa_method());
                RSA_set_ex_data(EVP_PKEY_get1_RSA(pkey), pkcs11d_rsa_key_idx, pd);
            } else if(EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                ECDSA_set_method(EVP_PKEY_get1_EC_KEY(pkey), engine_ecdsa_method());
                ECDH_set_method(EVP_PKEY_get1_EC_KEY(pkey), engine_ecdh_method());
                ECDSA_set_ex_data(EVP_PKEY_get1_EC_KEY(pkey), pkcs11d_ec_key_idx, pd);
#else
                EC_KEY_set_method(EVP_PKEY_get1_EC_KEY(pkey), engine_ec_method());
                EC_KEY_set_ex_data(EVP_PKEY_get1_EC_KEY(pkey), pkcs11d_ec_key_idx, pd);
#endif
            }
        }
        BIO_free(key);
    }
    return pkey;
}

static EVP_PKEY *engine_load_public_key(ENGINE * e, const char *path,
                                        UI_METHOD * ui_method, void *callback_data)
{
    return engine_load_private_key(e, path, ui_method, callback_data);
}

static int bind_fn(ENGINE * e, const char *id)
{
    if (!ENGINE_set_id(e, ENGINE_ID) ||
        !ENGINE_set_name(e, ENGINE_NAME) ||
        !ENGINE_set_init_function(e, engine_init) ||
        !ENGINE_set_destroy_function(e, engine_destroy) ||
        !ENGINE_set_finish_function(e, engine_finish) ||
        !ENGINE_set_ctrl_function(e, engine_ctrl) ||
        !ENGINE_set_cmd_defns(e, engine_cmd_defns) ||
#ifndef OPENSSL_NO_RSA
        !ENGINE_set_RSA(e, engine_rsa_method()) ||
#endif
#ifndef OPENSSL_NO_EC
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef ENABLE_PKCS11_ECDSA
        !ENGINE_set_ECDSA(e, engine_ecdsa_method()) ||
#endif
#ifndef OPENSSL_NO_ECDH
        !ENGINE_set_ECDH(e, engine_ecdh_method()) ||
#endif
#else
        !ENGINE_set_EC(e, engine_ec_method()) ||
#endif
#endif
        !ENGINE_set_load_pubkey_function(e, engine_load_public_key) ||
        !ENGINE_set_load_privkey_function(e, engine_load_private_key)) {
		fprintf(stderr, "Error setting engine functions\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
