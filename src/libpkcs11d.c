#include <stdio.h>
#include <string.h>

#include <openssl/ossl_typ.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#ifndef OPENSSL_NO_ECDSA
#include <openssl/ecdsa.h>
#endif
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#endif

#include "network.h"
#include "network.c"

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
        struct sockaddr_in inetaddr;
        int fd = nw_tcp_client("127.0.0.1", 1234, &inetaddr);
        BIO *b = BIO_new_socket(fd, BIO_NOCLOSE);
        BIO *buf = BIO_new(BIO_f_buffer());
        b = BIO_push(buf, b);
        char buffer[4096];
        int l, slen = 0;

        /* Insert implementation here */

        BIO_printf(b, "POST /%s/rsa/%s HTTP/1.0\r\n", op, pkd->id);
        BIO_printf(b, "Content-Length: %d\r\n\r\n", flen);
        BIO_write(b, from, flen);
        BIO_flush(b);

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l <= 0) {
            goto end;
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        if(l > 0) {
            if(strncmp(buffer, "Content-Length: ", 16) == 0) {
                slen = atoi(buffer + 16);
            }
        }

        l = BIO_gets(b, buffer, sizeof(buffer));
        l = BIO_read(b, buffer, slen);

        if(l > 0) {
            memcpy(to, buffer, l);
            rval = l;
        }

    end:
        BIO_free(b);
        close(fd);
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
		const RSA_METHOD *def = RSA_get_default_method();
		pkcs11d_rsa_method = calloc(1, sizeof(*pkcs11d_rsa_method));
		memcpy(pkcs11d_rsa_method, def, sizeof(*pkcs11d_rsa_method));
		pkcs11d_rsa_method->name = "pkcs11d";
		pkcs11d_rsa_method->rsa_priv_enc = pkcs11d_rsa_private_encrypt;
		pkcs11d_rsa_method->rsa_priv_dec = pkcs11d_rsa_private_decrypt;
	}
	return pkcs11d_rsa_method;
}

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECDSA
static ECDSA_METHOD *engine_ecdsa_method(void)
{
	return NULL;
}
#endif

#ifndef OPENSSL_NO_ECDH
static ECDH_METHOD *engine_ecdh_method(void)
{
	return NULL;
}
#endif
#endif

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

            i2d_RSAPublicKey_bio(s, EVP_PKEY_get1_RSA(pkey));
            n = BIO_gets(h, (char*)md, EVP_MAX_MD_SIZE);
            for(k = 0, l = 0; k < n; k++) {
                l += sprintf(key_id + l, "%02X", md[k]);
            }
            fprintf(stderr, "key id=%s\n", key_id);
            struct pkcs11d_data *pd = (struct pkcs11d_data *) malloc(sizeof(struct pkcs11d_data));
            memcpy(pd->id, key_id, sizeof(key_id));
            RSA_set_method(EVP_PKEY_get1_RSA(pkey), engine_rsa_method());
            RSA_set_ex_data(EVP_PKEY_get1_RSA(pkey), pkcs11d_rsa_key_idx, pd);
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
#ifndef OPENSSL_NO_ECDSA
        !ENGINE_set_ECDSA(e, engine_ecdsa_method()) ||
#endif
#ifndef OPENSSL_NO_ECDH
        !ENGINE_set_ECDH(e, engine_ecdh_method()) ||
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
