#ifndef CRYPTO_H
#define CRYPTO_H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void init_crypto();

#ifdef HAVE_OPENSSL
EVP_PKEY *load_pkcs11_key(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key);
void unload_pkcs11_key(EVP_PKEY *k);
#endif

#ifdef __cplusplus
};
#endif

#endif /* CRYPTO_H */
