#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>

#define ENGINE_ID   "pkcs11d"
#define ENGINE_NAME "pkcs11d"

static int engine_init(ENGINE * engine)
{
	(void)engine;
	return 1;
}

static int bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, ENGINE_ID) != 0)) {
		fprintf(stderr, "Wrong engine id\n");
		return 0;
	}
    if (!ENGINE_set_id(e, ENGINE_ID) ||
        !ENGINE_set_name(e, ENGINE_NAME) ||
        !ENGINE_set_init_function(e, engine_init)) {
		fprintf(stderr, "Error setting engine functions\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
