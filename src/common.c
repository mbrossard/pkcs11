/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <memory.h>

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
#ifdef __APPLE__
#include <Carbon/Carbon.h>
#endif

#include <sys/types.h>
#include <dlfcn.h>

#define __USE_BSD 1

#include <stdlib.h>
#include <dirent.h>

#include <sys/stat.h>
#else
#include <windows.h>
#endif

#include "common.h"
#include "pkcs11_display.h"

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
#define DEFAULT_PKCSLIB "/usr/lib/pkcs11/opensc-pkcs11.so"
#else
#define DEFAULT_PKCSLIB "opensc-pkcs11.dll"
#endif

{
    CK_FUNCTION_LIST  *funcs;
    CK_RV              rc;
    CK_RV            (*pfoo)();
    void              *d;
    const char        *e;
    char              *z = DEFAULT_PKCSLIB;

    if(param) {
        e = param;
    } else {
        e = getenv("PKCS11_LIBRARY");
        if (e == NULL) {
            e = z;
        }
    }
#if (defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
    d = LoadLibrary(e);
    
    if (d == NULL ) {
        fprintf(stdout, "LoadLibrary Failed\n");
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
    *(void **) (&pfoo) = dlsym(d, "C_GetFunctionList");
#endif
    if (pfoo == NULL ) {
        printf("Symbol lookup failed\n");
        return NULL;
    }
#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
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
#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
{
    DIR *dir = opendir(buffer);
    struct dirent *ent;
    int found = 0;

    if (!buffer)
	    return 0;

    dir = opendir(buffer);
    if (!dir)
	    return 0;

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
    return pkcs11_initialize_nss(funcs, NULL);
}

CK_RV pkcs11_initialize_nss(CK_FUNCTION_LIST_PTR funcs, const char *path)
{
    CK_RV rc = CKR_HOST_MEMORY;

    if(funcs) {
        rc = funcs->C_Initialize(NULL);
    }

    if(funcs && (rc == CKR_ARGUMENTS_BAD)) {
        static const char *nss_init_string = "configdir='%s' certPrefix='' keyPrefix='' secmod='secmod.db'";
        char buffer[256];
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
        char *z;

        iap = (CK_C_INITIALIZE_ARGS *)&ia;
        ia.flags = CKF_OS_LOCKING_OK;
        ia.LibraryParameters = (CK_CHAR_PTR)buffer;
        ia.pReserved = NULL_PTR;
 
        if(path) {
            snprintf(buffer, 256, nss_init_string, path);
        } else if((z = getenv("NSS_INIT"))) {
            snprintf(buffer, 256, "%s", z);
        } else if((z = getenv("NSS_DIR"))) {
            snprintf(buffer, 256, nss_init_string, z);
        } else {
            int found = 0;
#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
            char search[256];
            DIR *dir;
            snprintf(search, 256, "%s/.mozilla", getenv("HOME"));
            if ((dir = opendir(search)))   {
                if(search_file(search, 256, "secmod.db")) {
                    found = 1;
                }
                closedir(dir);
            }
            snprintf(buffer, 256, nss_init_string, search);

            if(!found) {
                return CKR_ARGUMENTS_BAD;
            }
#endif
        }
        rc = funcs->C_Initialize((CK_VOID_PTR)iap);
    }

    return rc;
}

void print_usage_and_die(const char *name, const struct option *opts, const char **help)
{
    int i = 0;
    printf("Usage: %s [OPTIONS]\nOptions:\n", name);

    while (opts[i].name) {
        char buf[40], tmp[5];
        const char *arg_str;

        /* Skip "hidden" opts */
        if (help[i] == NULL) {
            i++;
            continue;
        }

        if (opts[i].val > 0 && opts[i].val < 128)
            sprintf(tmp, ", -%c", opts[i].val);
        else
            tmp[0] = 0;
        switch (opts[i].has_arg) {
            case 1:
                arg_str = " <arg>";
                break;
            case 2:
                arg_str = " [arg]";
                break;
            default:
                arg_str = "";
                break;
        }
        sprintf(buf, "--%s%s%s", opts[i].name, tmp, arg_str);
        if (strlen(buf) > 29) {
            printf("  %s\n", buf);
            buf[0] = '\0';
        }
        printf("  %-29s %s\n", buf, help[i]);
        i++;
    }
    exit(2);
}

CK_RV pkcs11_get_slots(CK_FUNCTION_LIST_PTR funcs, FILE *out,
                       CK_SLOT_ID_PTR *slots, CK_ULONG_PTR nslots)
{
    CK_SLOT_ID *s;
    CK_ULONG n;
    CK_RV rc;

    if(!slots || !nslots) {
        return CKR_ARGUMENTS_BAD;
    }

    rc = funcs->C_GetSlotList(0, NULL_PTR, &n);
    if (rc != CKR_OK) {
        if(out) {
            show_error(out, "C_GetSlotList", rc);
        }
        return rc;
    }
    s = malloc(sizeof(CK_SLOT_ID) * n);
    rc = funcs->C_GetSlotList(0, s, &n);
    if (rc != CKR_OK) {
        if(out) {
            show_error(out, "C_GetSlotList", rc);
        }
        return rc;
    }

    *slots = s;
    *nslots = n;

    return rc;
}

CK_RV pkcs11_find_object(CK_FUNCTION_LIST_PTR funcs, FILE *out,
                         CK_SESSION_HANDLE h_session,
                         CK_ATTRIBUTE_PTR search, CK_ULONG length,
                         CK_OBJECT_HANDLE_PTR objects,
                         CK_ULONG count, CK_ULONG_PTR found)
{
    CK_ULONG f;
    CK_RV rc;

    rc = funcs->C_FindObjectsInit(h_session, search, length);
    if (rc != CKR_OK) {
        if(out) {
            show_error(out, "C_FindObjectsInit", rc);
        }
        return rc;
    }

    rc = funcs->C_FindObjects(h_session, objects, count, &f);
    if (rc != CKR_OK) {
        if(out) {
            show_error(out, "C_FindObjects", rc);
        }
        return rc;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        if(out) {
            show_error(out, "C_FindObjectsFinal", rc);
        }
        return rc;
    }

    if(found) {
        *found = f;
    }

    return rc;
}

CK_RV pkcs11_login_session(CK_FUNCTION_LIST_PTR funcs, FILE *out,  CK_SLOT_ID slot,
                           CK_SESSION_HANDLE_PTR session, CK_BBOOL readwrite,
                           CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen)
{
    CK_SESSION_HANDLE h_session;
    CK_FLAGS flags = CKF_SERIAL_SESSION | (readwrite ? CKF_RW_SESSION : 0);
    CK_RV rc;

    rc = funcs->C_OpenSession(slot, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        if(out) {
            show_error(stdout, "C_OpenSession", rc);
        }
        return rc;
    }

    if(pin) {
        rc = funcs->C_Login(h_session, user, pin, pinLen);
        if (rc != CKR_OK) {
            if(out) {
                show_error(out, "C_Login", rc);
            }
            goto end;
        }
    } else if(readwrite || pinLen > 0) {
        CK_TOKEN_INFO  info;

        rc = funcs->C_GetTokenInfo(slot, &info);
        if (rc != CKR_OK) {
            if(out) {
                show_error(out, "C_GetTokenInfo", rc);
            }
            goto end;
        }
        
        if(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
            rc = funcs->C_Login(h_session, user, NULL, 0);
            if (rc != CKR_OK) {
                if(out) {
                    show_error(out, "C_Login", rc);
                }
                goto end;
            }
        }
    }

 end:
    if (rc != CKR_OK) {
        /* We want to keep the original error code */
        CK_RV r = funcs->C_CloseSession(h_session);
        if ((r != CKR_OK) && out) {
            show_error(out, "C_CloseSession", r);
        }
    } else if(session) {
        *session = h_session;
    }
    return rc;
}

void fillAttribute(CK_ATTRIBUTE *attr, CK_ATTRIBUTE_TYPE type,
                   CK_VOID_PTR pvoid, CK_ULONG ulong)
{
	attr->type = type;
	attr->pValue =  pvoid;
	attr->ulValueLen = ulong;
}
