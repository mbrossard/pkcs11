/*
 * Copyright (C) 2011 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <memory.h>

#ifndef WIN32
#ifdef __APPLE__
#include <Carbon/Carbon.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>

#define __USE_BSD 1

#include <stdlib.h>
#include <dirent.h>
#else
#include <windows.h>
#endif

#include <stdio.h>

#include "pkcs11_util.h"

#ifndef WIN32
#define DEFAULT_PKCSLIB "/usr/lib/pkcs11/opensc-pkcs11.so"
#else
#define DEFAULT_PKCSLIB "opensc-pkcs11.dll"
#endif

CK_FUNCTION_LIST  *pkcs11_get_function_list( const char *param )
{
    CK_FUNCTION_LIST  *funcs;
    CK_RV              rc;
    CK_RV            (*pfoo)();
    void              *d;
    const char        *e;
    char              *z = DEFAULT_PKCSLIB;

    if( param ) {
        e = param;
    } else {
        e = getenv("PKCS11_LIBRARY");
        if ( e == NULL) {
            e = z;
        }
    }
#ifdef WIN32
    d = LoadLibrary(e);
    
    if ( d == NULL ) {
        printf("LoadLibrary Failed\n");
        return NULL;
    }
    pfoo = (CK_RV (*)())GetProcAddress(d, "C_GetFunctionList");
#else
    d = dlopen(e, RTLD_LAZY | RTLD_LOCAL);
    if ( d == NULL ) {
        d = dlopen(e, RTLD_LAZY);
        if (d == NULL ) {
            return NULL;
        }
    }
    pfoo = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
#endif
    if (pfoo == NULL ) {
        printf("Symbol lookup failed\n");
        return NULL;
    }
#ifndef WIN32
    rc = pfoo(&funcs);
#else
    funcs = (CK_FUNCTION_LIST_PTR) malloc(sizeof(CK_FUNCTION_LIST));
    if(funcs) {
#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO(name)                       \
        funcs->name = (CK_RV (*)())GetProcAddress(d, #name);
#include "pkcs11f.h"
        rc = CKR_OK;
    }
#endif
    if (rc != CKR_OK) {
        printf("Call to C_GetFunctionList failed\n");
        funcs = NULL;
    }
    printf("C_GetFunctionList returned %lx\n", (long unsigned int)funcs);
    
    return funcs;
}

int search_file(char *buffer, int size, char *key)
#ifndef WIN32
{
    DIR *dir = opendir(buffer);
    struct dirent *ent;
    int found = 0;

    while((found == 0) && (ent = readdir(dir))) {
        if((ent->d_type & DT_DIR)) {
            int len = strlen(buffer);
            if((ent->d_name[0] != '.') && (len < size - 8)) {
                buffer[len] = '/';
                strncpy(buffer + len + 1, ent->d_name, size - len - 1);
                found = search_file(buffer, size, key);
                if(found == 0) {
                    buffer[len] = '\0';
                }
            }
        }
        if((ent->d_type & DT_REG)) {
            if(strcmp(key, ent->d_name) == 0) {
                found = 1;
            }
        }
    }
    closedir(dir);
    return found;
}
#else
{
    return 0;
}
#endif

CK_RV pkcs11_initialize(CK_FUNCTION_LIST_PTR funcs)
{
    CK_RV rc = CKR_HOST_MEMORY;
    if(funcs) {
        rc = funcs->C_Initialize( NULL );
#ifndef WIN32
        if (rc == CKR_ARGUMENTS_BAD) {
            char buffer[256];
            char *z;
            CK_C_INITIALIZE_ARGS *iap = NULL;
            struct {
                CK_CREATEMUTEX CreateMutex;
                CK_DESTROYMUTEX DestroyMutex;
                CK_LOCKMUTEX LockMutex;
                CK_UNLOCKMUTEX UnlockMutex;
                CK_FLAGS flags;
                CK_CHAR_PTR LibraryParameters;
                CK_VOID_PTR pReserved;
            } ia;
            
            (void)memset(&ia, 0, sizeof(ia));
            if ((z = getenv("MOZILLA_INIT"))) {
                snprintf(buffer, 256, "%s", z);
            } else {
                char *l = "configdir='%s' certPrefix='' keyPrefix='' secmod='secmod.db'";
                char path[256];
                snprintf(path, 256, "%s/.mozilla", getenv("HOME"));
                search_file(path, 256, "secmod.db");
                snprintf(buffer, 256, l, path);
            }

            iap = (CK_C_INITIALIZE_ARGS *)&ia;
            ia.flags = CKF_OS_LOCKING_OK;
            ia.LibraryParameters = (CK_CHAR_PTR)buffer;
            ia.pReserved = NULL_PTR;
            rc = funcs->C_Initialize( (CK_VOID_PTR)iap );
        }
#endif
    }
    return rc;
}
