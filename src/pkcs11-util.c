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
           " * keygen: create keys\n"
           "\n");
}

int main(int argc, char **argv)
{
    int r = 0;

    if(argc <= 0) {
        usage();
    } else if(!strcmp(argv[1], "help") ||
              !strcmp(argv[1], "--help") ||
              !strcmp(argv[1], "-h")) {
        usage();
    } else if(!strcmp(argv[1], "clean")) {
        r = clean(argc - 1, argv + 1);
    } else if(!strcmp(argv[1], "keygen")) {
        keygen(argc - 1, argv + 1);
    } else {
        usage();
        r = -1;
    }

    exit(r);
}
