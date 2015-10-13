#ifndef COMMON_H
#define COMMON_H

/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
   /* Unix case */
#define CK_DEFINE_FUNCTION(returnType, name) \
   returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#else
   /* Win32 case */
#define CK_DEFINE_FUNCTION(returnType, name) \
   returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllexport) name

#ifdef __MINGW32__
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#else
#define CK_DECLARE_FUNCTION_POINTER(returnType, name)    \
   returnType __declspec(dllimport) (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#endif

#define CK_PTR *
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <pkcs11.h>
#include <getopt.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

CK_FUNCTION_LIST *pkcs11_get_function_list(const char *param);
CK_RV pkcs11_initialize(CK_FUNCTION_LIST_PTR funcs);
CK_RV pkcs11_initialize_nss(CK_FUNCTION_LIST_PTR funcs, const char *path);
void print_usage_and_die(const char *name, const struct option *opts, const char **help);

CK_RV pkcs11_get_slots(CK_FUNCTION_LIST_PTR funcs, FILE *out,
                       CK_SLOT_ID_PTR *slots, CK_ULONG_PTR nslots);
void fillAttribute(CK_ATTRIBUTE *attr, CK_ATTRIBUTE_TYPE type,
                   CK_VOID_PTR pvoid, CK_ULONG ulong);

#ifdef __cplusplus
};
#endif

#endif /* COMMON_H */
