#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
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

#define ENGINE_ID   "pkcs11d"
#define ENGINE_NAME "pkcs11d"

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

static RSA_METHOD *engine_rsa_method(void)
{
    return NULL;
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

EVP_PKEY *engine_load_private_key(ENGINE * e, const char *s_key_id,
                                  UI_METHOD * ui_method, void *callback_data)
{
    return NULL;
}

static int bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, ENGINE_ID) != 0)) {
		fprintf(stderr, "Wrong engine id\n");
		return 0;
	}
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
        !ENGINE_set_load_privkey_function(e, engine_load_private_key)) {
		fprintf(stderr, "Error setting engine functions\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
