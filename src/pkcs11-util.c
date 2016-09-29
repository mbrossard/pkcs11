/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "pkcs11-util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage()
{
    printf("Usage: pkcs11-util <command>\nOptions:\n"
           " * help (-h or --help): help message\n"
           " * clean: delete objects\n"
#ifdef HAVE_OPENSSL
           " * extract: extract keys\n"
#endif
           " * info: show module information\n"
           " * init: initialize token\n"
           " * keygen: create keys\n"
           " * list: list slots and objects\n"
           " * [list-]mechanisms: list mechanisms\n"
           " * [list-]objects: list objects\n"
           " * [list-]slots: list slots\n"
           " * random: get random string\n"
#ifdef HAVE_OPENSSL
           " * request: create a certificate request\n"
#endif
#ifdef HAVE_PTHREAD
           " * speed: performance testing\n"
#endif
           " * ssh: list SSH keys\n"
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
    } else if(!strcmp(argv[1], "info")) {
        r = info(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "init")) {
        r = init_p11(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "keygen")) {
        keygen(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "list-objects") ||
            !strcmp(argv[1], "objects")) {
        r = objects(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "list-slots") ||
            !strcmp(argv[1], "slots")) {
        r = slots(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "list-mechanisms") ||
            !strcmp(argv[1], "mechanisms") ||
            !strcmp(argv[1], "mechs")) {
        r = mechanisms(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "random")) {
        r = random_p11(argc - 1, argv + 1);
#ifdef HAVE_OPENSSL
    } else if(!strcmp(argv[1], "certify")) {
        r = certify(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "extract")) {
        r = extract(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "import")) {
        r = import(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "request")) {
        r = request(argc - 1, argv + 1);
#ifdef HAVE_PTHREAD
    } else if(!strcmp(argv[1], "speed")) {
        r = speed(argc - 1, argv + 1);
#endif
#endif
    } else if(!strcmp(argv[1], "ssh")) {
        r = ssh(argc - 1, argv + 1);
    } else {
        usage();
        r = -1;
    }

    exit(r);
}
