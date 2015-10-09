#ifndef PKCS11_UTIL_H
#define PKCS11_UTIL_H

/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#ifdef __cplusplus
extern "C" {
#endif

int clean(int argc, char **argv);
int keygen(int argc, char **argv);
int list(int argc, char **argv);

#ifdef __cplusplus
};
#endif

#endif /* PKCS11_UTIL_H */
