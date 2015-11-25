#ifndef PKCS11_UTIL_H
#define PKCS11_UTIL_H

/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

int clean(int argc, char **argv);
int init_token(int argc, char **argv);
int keygen(int argc, char **argv);
int info(int argc, char **argv);
int mechanisms(int argc, char **argv);
int objects(int argc, char **argv);
int random_p11(int argc, char **argv);
int slots(int argc, char **argv);
int ssh(int argc, char **argv);

#ifdef HAVE_OPENSSL
int certify(int argc, char **argv);
int extract(int argc, char **argv);
int request(int argc, char **argv);
#ifdef HAVE_PTHREAD
int speed(int argc, char **argv);
#endif
#endif

#ifdef __cplusplus
};
#endif

#endif /* PKCS11_UTIL_H */
