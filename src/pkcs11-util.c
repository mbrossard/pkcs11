/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11-util.h"

void usage()
{
    printf("Usage: pkcs11-util <command>\nOptions:\n"
           " * help (-h or --help): help message\n"
           " * clean: delete objects\n"
           " * init: initialize token\n"
           " * keygen: create keys\n"
           " * list: list slots and objects\n"
#ifdef HAVE_OPENSSL
           " * request: create a certificate request\n"
#endif
#ifdef HAVE_PTHREAD
           " * speed: performance testing\n"
#endif
           " * ssh: list SSH keys\n"
#ifdef HAVE_OPENSSL
           " * wrap: wrap keys\n"
#endif
           "\n");
}

int main(int argc, char **argv)
{
    int r = 0;

    if(argc <= 1) {
        usage();
    } else if(!strcmp(argv[1], "help") ||
              !strcmp(argv[1], "--help") ||
              !strcmp(argv[1], "-h")) {
        usage();
    } else if(!strcmp(argv[1], "clean")) {
        r = clean(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "init")) {
        r = init_token(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "keygen")) {
        keygen(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "list")) {
        r = list(argc - 1, argv + 1);
#ifdef HAVE_OPENSSL
    } else if(!strcmp(argv[1], "request")) {
        r = request(argc - 1, argv + 1);
#endif
#ifdef HAVE_PTHREAD
    } else if(!strcmp(argv[1], "speed")) {
        r = speed(argc - 1, argv + 1);
#endif
    } else if(!strcmp(argv[1], "ssh")) {
        r = ssh(argc - 1, argv + 1);
#ifdef HAVE_OPENSSL
    } else if(!strcmp(argv[1], "wrap")) {
        r = wrap(argc - 1, argv + 1);
#endif
    } else {
        usage();
        r = -1;
    }

    exit(r);
}
