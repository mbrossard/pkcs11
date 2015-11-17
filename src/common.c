/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>
#include <memory.h>

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
#ifdef __APPLE__
#include <Carbon/Carbon.h>
#endif

#include <sys/types.h>
#include <dlfcn.h>
#include <stdlib.h>
#define DEFAULT_PKCSLIB "/usr/lib/pkcs11/opensc-pkcs11.so"
#else
#include <windows.h>
#define DEFAULT_PKCSLIB "opensc-pkcs11.dll"
#endif

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
CK_FUNCTION_LIST  *pkcs11_get_function_list(const char *param)
{
    CK_FUNCTION_LIST  *funcs;
    CK_RV            (*get_fun)();
    void              *d;
    const char        *e = param ? param : getenv("PKCS11_LIBRARY");
    e = e ? e : DEFAULT_PKCSLIB;

    d = dlopen(e, RTLD_LAZY);
    if (d == NULL ) {
        fprintf(stdout, "dlopen('%s') failed\n", e);
        return NULL;
    }
    *(void **) (&get_fun) = dlsym(d, "C_GetFunctionList");
    if (get_fun == NULL ) {
        fprintf(stdout, "Symbol lookup failed\n");
        return NULL;
    }
    CK_RV rc = get_fun(&funcs);
    if (rc != CKR_OK) {
        show_error(stdout, "C_GetFunctionList", rc);
        funcs = NULL;
    } else if(funcs == NULL) {
        fprintf(stdout, "C_GetFunctionList returned empty value\n");
    }
    return funcs;
}
#else
CK_FUNCTION_LIST  *pkcs11_get_function_list(const char *param)
{
    CK_FUNCTION_LIST  *funcs;
    void              *d;
    const char        *e = param ? param : getenv("PKCS11_LIBRARY");
    e = e ? e : DEFAULT_PKCSLIB;

    d = LoadLibrary(e);    
    if (d == NULL) {
        fprintf(stdout, "LoadLibrary Failed\n");
        return NULL;
    }

#ifndef USE_GET_FUNCTION_LIST
    /* Look-up all symbols from dll */
    funcs = (CK_FUNCTION_LIST_PTR) malloc(sizeof(CK_FUNCTION_LIST));
    if(funcs) {
#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO(name)                       \
        if((funcs->name = (CK_RV (*)())GetProcAddress(d, #name)) == NULL) { \
            fprintf(stdout, "Error looking up %s\n", #name); \
            free(funcs); \
            return NULL; \
        }
#include "pkcs11f.h"
    }
#else
    /* Look-up C_GetFunctionList and use it to get all functions */
    CK_RV            (*get_fun)();
    get_fun = (CK_RV (*)())GetProcAddress(d, "C_GetFunctionList");
    if (get_fun == NULL ) {
        fprintf(stdout, "Symbol lookup failed\n");
        return NULL;
    }
    CK_RV rc = get_fun(&funcs);
    if (rc != CKR_OK) {
        show_error(stdout, "C_GetFunctionList", rc);
        funcs = NULL;
    } else if(funcs == NULL) {
        fprintf(stdout, "C_GetFunctionList returned empty value\n");
    }
#endif
    return funcs;
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
        }
        rc = funcs->C_Initialize((CK_VOID_PTR)iap);
    }

    return rc;
}

void print_usage_and_die(const char *name, const struct option *opts, const char **help)
{
    int i = 0;
    fprintf(stdout, "Usage: %s [OPTIONS]\nOptions:\n", name);

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
            fprintf(stdout, "  %s\n", buf);
            buf[0] = '\0';
        }
        fprintf(stdout, "  %-29s %s\n", buf, help[i]);
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

CK_RV pkcs11_load_init(const char *module, const char *path,
                       FILE *err, CK_FUNCTION_LIST_PTR *funcs)
{
    CK_RV rc = CKR_GENERAL_ERROR;
    CK_FUNCTION_LIST_PTR f;

    if(funcs == NULL) {
        return rc;
    }

    f = pkcs11_get_function_list(module);
    if (!f) {
        fprintf(err, "Could not get function list.\n");
        return rc;
    }

    if(path) {
        fprintf(err, "Using %s directory\n", path);
    }

    rc = pkcs11_initialize_nss(f, path);
    if (rc != CKR_OK) {
        show_error(err, "C_Initialize", rc);
        return rc;
    }

    *funcs = f;
    return rc;
}

CK_RV pkcs11_close(FILE *err, CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE h_session)
{
    CK_RV rc = funcs->C_Logout(h_session);
    if (rc != CKR_OK) {
        show_error(err, "C_Logout", rc);
        return rc;
    }
    
    rc = funcs->C_CloseSession(h_session);
    if (rc != CKR_OK) {
        show_error(err, "C_CloseSession", rc);
        return rc;
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(err, "C_Finalize", rc);
        return rc;
    }

    return rc;
}
