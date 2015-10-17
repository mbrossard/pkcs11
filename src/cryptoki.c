/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *                                
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#ifdef HAVE_VISIBILITY
#define DLL_EXPORTED __attribute__((__visibility__("default")))
#else
#define DLL_EXPORTED
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
/* Unix case */
#define CK_DEFINE_FUNCTION(returnType, name)    \
    returnType name

#define CK_DECLARE_FUNCTION(returnType, name)   \
    returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name)   \
    returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name)  \
    returnType (* name)

#else
/* Win32 case */
#define CK_DEFINE_FUNCTION(returnType, name)    \
    returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION(returnType, name)   \
    returnType __declspec(dllexport) name

#ifdef __MINGW32__
#define CK_DECLARE_FUNCTION_POINTER(returnType, name)   \
    returnType (* name)
#else
#define CK_DECLARE_FUNCTION_POINTER(returnType, name)   \
    returnType __declspec(dllimport) (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name)  \
    returnType (* name)

/* Work-around for MingW32 #2014 */
#define off_t _off_t
#define off64_t _off64_t
#endif

#define CK_PTR *
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#define PKCS11_MAJOR_VERSION 2
#define PKCS11_MINOR_VERSION 20

#include <pkcs11.h>

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
#ifdef __APPLE__
#include <Carbon/Carbon.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#else
#include <windows.h>
#endif

#include "iniparser.h"

#ifdef DEFAULT_PKCS11_MODULE
#define DEFAULT_PKCSLIB DEFAULT_PKCS11_MODULE
#else
#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
#ifdef __APPLE__
#define DEFAULT_PKCSLIB "libsoftokn3.dylib"
#else
#define DEFAULT_PKCSLIB "libsoftokn3.so"
#endif
#else
#define DEFAULT_PKCSLIB "libsoftokn3.dll"
#endif
#endif

static char* data_path = NULL;
static CK_FUNCTION_LIST_PTR pkcs11 = NULL;
static CK_FUNCTION_LIST_PTR nss = NULL;
static CK_BBOOL pkcs11_initialized = CK_FALSE;

static CK_RV init_module(void)
{
    CK_RV       (*pf)() = NULL;
    dictionary   *dic   = NULL;
    void         *d     = NULL;
    const char   *z     = NULL;
	int rv              = CKR_OK;

    dic = iniparser_load("token.ini");

    if(!dic) {
        char path[FILENAME_MAX];
        snprintf(path, sizeof(path), "%s/.pkcs11/token.ini", getenv("HOME"));
        dic = iniparser_load(path);
    }

    if(!dic) {
        dic = iniparser_load("/etc/pkcs11-token.ini");
    }

    if(dic) {
        z = strdup(iniparser_getstring(dic, "token:module", NULL));
        data_path = strdup(iniparser_getstring(dic, "token:data", NULL));
        iniparser_freedict(dic);
    }

    if(z == NULL) {
        z = DEFAULT_PKCSLIB;
    }

	/* Allocates the PKCS#11 function list structures */
	if(!(pkcs11 = malloc(sizeof(CK_FUNCTION_LIST))) ||
       !(nss = malloc(sizeof(CK_FUNCTION_LIST)))) {
		return CKR_HOST_MEMORY;
	}

#if !(defined _WIN32 || defined __CYGWIN__ || defined __MINGW32__)
    if (((d = dlopen(z, RTLD_LAZY)) == NULL) ||
        ((*(void **) (&pf) = dlsym(d, "C_GetFunctionList")) == NULL)) {
        return CKR_HOST_MEMORY;
    }
#else
    if (((d = LoadLibrary(z)) == NULL) || 
        ((pf = (CK_RV (*)())GetProcAddress(d, "C_GetFunctionList")) == NULL)) {
        return CKR_HOST_MEMORY;
    }
#endif
    if((rv = pf(&nss)) != CKR_OK) {
        return rv;
    }

    pkcs11->version.major = PKCS11_MAJOR_VERSION;
    pkcs11->version.major = PKCS11_MINOR_VERSION;
    pkcs11->C_Initialize = C_Initialize;
    pkcs11->C_Finalize = C_Finalize;
    pkcs11->C_GetInfo = C_GetInfo;
    pkcs11->C_GetFunctionList = C_GetFunctionList;
    pkcs11->C_GetSlotList = C_GetSlotList;
    pkcs11->C_GetSlotInfo = C_GetSlotInfo;
    pkcs11->C_GetTokenInfo = C_GetTokenInfo;
    pkcs11->C_GetMechanismList = C_GetMechanismList;
    pkcs11->C_GetMechanismInfo = C_GetMechanismInfo;
    pkcs11->C_InitToken = C_InitToken;
    pkcs11->C_InitPIN = C_InitPIN;
    pkcs11->C_SetPIN = C_SetPIN;
    pkcs11->C_OpenSession = C_OpenSession;
    pkcs11->C_CloseSession = C_CloseSession;
    pkcs11->C_CloseAllSessions = C_CloseAllSessions;
    pkcs11->C_GetSessionInfo = C_GetSessionInfo;
    pkcs11->C_GetOperationState = C_GetOperationState;
    pkcs11->C_SetOperationState = C_SetOperationState;
    pkcs11->C_Login = C_Login;
    pkcs11->C_Logout = C_Logout;
    pkcs11->C_CreateObject = C_CreateObject;
    pkcs11->C_CopyObject = C_CopyObject;
    pkcs11->C_DestroyObject = C_DestroyObject;
    pkcs11->C_GetObjectSize = C_GetObjectSize;
    pkcs11->C_GetAttributeValue = C_GetAttributeValue;
    pkcs11->C_SetAttributeValue = C_SetAttributeValue;
    pkcs11->C_FindObjectsInit = C_FindObjectsInit;
    pkcs11->C_FindObjects = C_FindObjects;
    pkcs11->C_FindObjectsFinal = C_FindObjectsFinal;
    pkcs11->C_EncryptInit = C_EncryptInit;
    pkcs11->C_Encrypt = C_Encrypt;
    pkcs11->C_EncryptUpdate = C_EncryptUpdate;
    pkcs11->C_EncryptFinal = C_EncryptFinal;
    pkcs11->C_DecryptInit = C_DecryptInit;
    pkcs11->C_Decrypt = C_Decrypt;
    pkcs11->C_DecryptUpdate = C_DecryptUpdate;
    pkcs11->C_DecryptFinal = C_DecryptFinal;
    pkcs11->C_DigestInit = C_DigestInit;
    pkcs11->C_Digest = C_Digest;
    pkcs11->C_DigestUpdate = C_DigestUpdate;
    pkcs11->C_DigestKey = C_DigestKey;
    pkcs11->C_DigestFinal = C_DigestFinal;
    pkcs11->C_SignInit = C_SignInit;
    pkcs11->C_Sign = C_Sign;
    pkcs11->C_SignUpdate = C_SignUpdate;
    pkcs11->C_SignFinal = C_SignFinal;
    pkcs11->C_SignRecoverInit = C_SignRecoverInit;
    pkcs11->C_SignRecover = C_SignRecover;
    pkcs11->C_VerifyInit = C_VerifyInit;
    pkcs11->C_Verify = C_Verify;
    pkcs11->C_VerifyUpdate = C_VerifyUpdate;
    pkcs11->C_VerifyFinal = C_VerifyFinal;
    pkcs11->C_VerifyRecoverInit = C_VerifyRecoverInit;
    pkcs11->C_VerifyRecover = C_VerifyRecover;
    pkcs11->C_DigestEncryptUpdate = C_DigestEncryptUpdate;
    pkcs11->C_DecryptDigestUpdate = C_DecryptDigestUpdate;
    pkcs11->C_SignEncryptUpdate = C_SignEncryptUpdate;
    pkcs11->C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
    pkcs11->C_GenerateKey = C_GenerateKey;
    pkcs11->C_GenerateKeyPair = C_GenerateKeyPair;
    pkcs11->C_WrapKey = C_WrapKey;
    pkcs11->C_UnwrapKey = C_UnwrapKey;
    pkcs11->C_DeriveKey = C_DeriveKey;
    pkcs11->C_SeedRandom = C_SeedRandom;
    pkcs11->C_GenerateRandom = C_GenerateRandom;
    pkcs11->C_GetFunctionStatus = C_GetFunctionStatus;
    pkcs11->C_CancelFunction = C_CancelFunction;
    pkcs11->C_WaitForSlotEvent = C_WaitForSlotEvent;

	return rv;
}

CK_RV DLL_EXPORTED C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    CK_RV rv = CKR_OK;
	if (pkcs11 == NULL_PTR) {
		rv = init_module();
	}

    if (rv == CKR_OK) {
        *ppFunctionList = pkcs11;
    }

	return rv;
}

CK_RV DLL_EXPORTED C_Initialize(CK_VOID_PTR pInitArgs)
{
    CK_RV rv = CKR_OK;

    if(pkcs11_initialized == CK_TRUE) {
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    if (pkcs11 == NULL) {
        rv = init_module();
	}
        
    if (rv == CKR_OK) {
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

        iap = (CK_C_INITIALIZE_ARGS *)&ia;
        ia.flags = CKF_OS_LOCKING_OK;
        ia.LibraryParameters = (CK_CHAR_PTR)buffer;
        ia.pReserved = NULL_PTR;
 
        if(data_path) {
            snprintf(buffer, 256, nss_init_string, data_path);
        } else {
            snprintf(buffer, 256, nss_init_string, ".");
        }
        rv = nss->C_Initialize( (CK_VOID_PTR)iap );
        pkcs11_initialized = CK_TRUE;
    }
	return rv;
}

CK_RV DLL_EXPORTED C_Finalize(CK_VOID_PTR pReserved)
{
    if(pkcs11_initialized == CK_FALSE) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pkcs11_initialized = CK_FALSE;
    return nss->C_Finalize(pReserved);
}

CK_RV DLL_EXPORTED C_GetInfo(CK_INFO_PTR pInfo)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetInfo(pInfo);
    }
}

CK_RV DLL_EXPORTED C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetSlotList(tokenPresent, pSlotList, pulCount);
    }
}

CK_RV DLL_EXPORTED C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetSlotInfo(slotID, pInfo);
    }
}

CK_RV DLL_EXPORTED C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetTokenInfo(slotID, pInfo);
    }
}

CK_RV DLL_EXPORTED C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
                                      CK_ULONG_PTR pulCount)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetMechanismList(slotID, pMechanismList, pulCount);
    }
}

CK_RV DLL_EXPORTED C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                                      CK_MECHANISM_INFO_PTR pInfo)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetMechanismInfo(slotID, type, pInfo);
    }
}

CK_RV DLL_EXPORTED C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
                               CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_InitToken(slotID, pPin, ulPinLen, pLabel);
    }
}

CK_RV DLL_EXPORTED C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                             CK_ULONG ulPinLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_InitPIN(hSession, pPin, ulPinLen);
    }
}

CK_RV DLL_EXPORTED C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
                            CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
                            CK_ULONG ulNewLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
    }
}

CK_RV DLL_EXPORTED C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                                 CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                 CK_SESSION_HANDLE_PTR phSession)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_OpenSession(slotID, flags, pApplication, Notify, phSession);
    }
}

CK_RV DLL_EXPORTED C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_CloseSession(hSession);
    }
}

CK_RV DLL_EXPORTED C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_CloseAllSessions(slotID);
    }
}

CK_RV DLL_EXPORTED C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                    CK_SESSION_INFO_PTR pInfo)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetSessionInfo(hSession, pInfo);
    }
}

CK_RV DLL_EXPORTED C_GetOperationState(CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pOperationState,
                                       CK_ULONG_PTR pulOperationStateLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetOperationState(hSession,
                                           pOperationState,
                                           pulOperationStateLen);
    }
}

CK_RV DLL_EXPORTED C_SetOperationState(CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pOperationState,
                                       CK_ULONG ulOperationStateLen,
                                       CK_OBJECT_HANDLE hEncryptionKey,
                                       CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SetOperationState(hSession,
                                           pOperationState,
                                           ulOperationStateLen,
                                           hEncryptionKey,
                                           hAuthenticationKey);
    }
}

CK_RV DLL_EXPORTED C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                           CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_Login(hSession, userType,
                               pPin, ulPinLen);
    }
}

CK_RV DLL_EXPORTED C_Logout(CK_SESSION_HANDLE hSession)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_Logout(hSession);
    }
}

CK_RV DLL_EXPORTED C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                                  CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_CreateObject(hSession, pTemplate,
                                      ulCount, phObject);
    }
}

CK_RV DLL_EXPORTED C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                CK_OBJECT_HANDLE_PTR phNewObject)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_CopyObject(hSession, hObject,
                                    pTemplate, ulCount,
                                    phNewObject);
    }
}

CK_RV DLL_EXPORTED C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DestroyObject(hSession, hObject);
    }
}

CK_RV DLL_EXPORTED C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                   CK_ULONG_PTR pulSize)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetObjectSize(hSession, hObject,
                                       pulSize);
    }
}

CK_RV DLL_EXPORTED C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                       CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetAttributeValue(hSession, hObject,
                                           pTemplate, ulCount);
    }
}

CK_RV DLL_EXPORTED C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                       CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SetAttributeValue(hSession, hObject,
                                           pTemplate, ulCount);
    }
}

CK_RV DLL_EXPORTED C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                                     CK_ULONG ulCount)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_FindObjectsInit(hSession, pTemplate,
                                         ulCount);
    }
}

CK_RV DLL_EXPORTED C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                                 CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_FindObjects(hSession, phObject,
                                     ulMaxObjectCount, pulObjectCount);
    }
}

CK_RV DLL_EXPORTED C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_FindObjectsFinal(hSession);
    }
}

CK_RV DLL_EXPORTED C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_EncryptInit(hSession, pMechanism,
                                     hKey);
    }
}

CK_RV DLL_EXPORTED C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                             CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_Encrypt(hSession, pData, ulDataLen,
                                 pEncryptedData, pulEncryptedDataLen);
    }
}

CK_RV DLL_EXPORTED C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                   CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                                   CK_ULONG_PTR pulEncryptedPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_EncryptUpdate(hSession, pPart,
                                       ulPartLen, pEncryptedPart,
                                       pulEncryptedPartLen);
    }
}

CK_RV DLL_EXPORTED C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                                  CK_ULONG_PTR pulLastEncryptedPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_EncryptFinal(hSession, pLastEncryptedPart,
                                      pulLastEncryptedPartLen);
    }
}

CK_RV DLL_EXPORTED C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DecryptInit(hSession, pMechanism,
                                     hKey);
    }
}

CK_RV DLL_EXPORTED C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                             CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                             CK_ULONG_PTR pulDataLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_Decrypt(hSession, pEncryptedData,
                                 ulEncryptedDataLen, pData,
                                 pulDataLen);
    }
}

CK_RV DLL_EXPORTED C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                                   CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                                   CK_ULONG_PTR pulPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DecryptUpdate(hSession, pEncryptedPart,
                                       ulEncryptedPartLen, pPart,
                                       pulPartLen);
    }
}

CK_RV DLL_EXPORTED C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                                  CK_ULONG_PTR pulLastPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DecryptFinal(hSession, pLastPart,
                                      pulLastPartLen);
    }
}

CK_RV DLL_EXPORTED C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DigestInit(hSession, pMechanism);
    }
}

CK_RV DLL_EXPORTED C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                            CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                            CK_ULONG_PTR pulDigestLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_Digest(hSession, pData,
                                ulDataLen, pDigest,
                                pulDigestLen);
    }
}

CK_RV DLL_EXPORTED C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                  CK_ULONG ulPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DigestUpdate(hSession, pPart,
                                      ulPartLen);
    }
}

CK_RV DLL_EXPORTED C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DigestKey(hSession, hKey);
    }
}

CK_RV DLL_EXPORTED C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                                 CK_ULONG_PTR pulDigestLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DigestFinal(hSession, pDigest,
                                     pulDigestLen);
    }
}

CK_RV DLL_EXPORTED C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                              CK_OBJECT_HANDLE hKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SignInit(hSession, pMechanism,
                                  hKey);
    }
}

CK_RV DLL_EXPORTED C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                          CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_Sign(hSession, pData, ulDataLen,
                              pSignature, pulSignatureLen);
    }
}

CK_RV DLL_EXPORTED C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                CK_ULONG ulPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SignUpdate(hSession, pPart,
                                    ulPartLen);
    }
}

CK_RV DLL_EXPORTED C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                               CK_ULONG_PTR pulSignatureLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SignFinal(hSession, pSignature,
                                   pulSignatureLen);
    }
}

CK_RV DLL_EXPORTED C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                     CK_OBJECT_HANDLE hKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SignRecoverInit(hSession, pMechanism, hKey);
    }
}

CK_RV DLL_EXPORTED C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                                 CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                                 CK_ULONG_PTR pulSignatureLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SignRecover(hSession, pData,
                                     ulDataLen, pSignature,
                                     pulSignatureLen);
    }
}

CK_RV DLL_EXPORTED C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                CK_OBJECT_HANDLE hKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_VerifyInit(hSession, pMechanism,
                                    hKey);
    }
}

CK_RV DLL_EXPORTED C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                            CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                            CK_ULONG ulSignatureLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_Verify(hSession, pData,
                                ulDataLen, pSignature,
                                ulSignatureLen);
    }
}

CK_RV DLL_EXPORTED C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                  CK_ULONG ulPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_VerifyUpdate(hSession, pPart,
                                      ulPartLen);
    }
}

CK_RV DLL_EXPORTED C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                                 CK_ULONG ulSignatureLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_VerifyFinal(hSession, pSignature,
                                     ulSignatureLen);
    }
}


CK_RV DLL_EXPORTED C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_VerifyRecoverInit(hSession,
                                           pMechanism,
                                           hKey);
    }
}

CK_RV DLL_EXPORTED C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                                   CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                                   CK_ULONG_PTR pulDataLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_VerifyRecover(hSession, pSignature,
                                       ulSignatureLen, pData,
                                       pulDataLen);
    }
}

CK_RV DLL_EXPORTED C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                         CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                                         CK_ULONG_PTR pulEncryptedPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DigestEncryptUpdate(hSession, pPart,
                                             ulPartLen, pEncryptedPart,
                                             pulEncryptedPartLen);
    }
}

CK_RV DLL_EXPORTED C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                                         CK_BYTE_PTR pEncryptedPart,
                                         CK_ULONG ulEncryptedPartLen,
                                         CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DecryptDigestUpdate(hSession,
                                             pEncryptedPart,
                                             ulEncryptedPartLen,
                                             pPart, pulPartLen);
    }
}

CK_RV DLL_EXPORTED C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                       CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                                       CK_ULONG_PTR pulEncryptedPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SignEncryptUpdate(hSession, pPart,
                                           ulPartLen, pEncryptedPart,
                                           pulEncryptedPartLen);
    }
}

CK_RV DLL_EXPORTED C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                                         CK_BYTE_PTR pEncryptedPart,
                                         CK_ULONG ulEncryptedPartLen,
                                         CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DecryptVerifyUpdate(hSession,
                                             pEncryptedPart,
                                             ulEncryptedPartLen,
                                             pPart, pulPartLen);
    }
}

CK_RV DLL_EXPORTED C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                 CK_OBJECT_HANDLE_PTR phKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
    }
}

CK_RV DLL_EXPORTED C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                     CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                     CK_ULONG ulPublicKeyAttributeCount,
                                     CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                     CK_ULONG ulPrivateKeyAttributeCount,
                                     CK_OBJECT_HANDLE_PTR phPublicKey,
                                     CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate,
                                         ulPublicKeyAttributeCount, pPrivateKeyTemplate,
                                         ulPrivateKeyAttributeCount, phPublicKey,
                                         phPrivateKey);
    }
}

CK_RV DLL_EXPORTED C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                             CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_WrapKey(hSession, pMechanism, hWrappingKey, hKey,
                                 pWrappedKey, pulWrappedKeyLen);
    }
}

CK_RV DLL_EXPORTED C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                               CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                               CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey,
                                   ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
    }
}

CK_RV DLL_EXPORTED C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                               CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_DeriveKey(hSession, pMechanism, hBaseKey,
                                   pTemplate, ulAttributeCount, phKey);
    }
}

CK_RV DLL_EXPORTED C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                                CK_ULONG ulSeedLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_SeedRandom(hSession, pSeed, ulSeedLen);
    }
}

CK_RV DLL_EXPORTED C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData,
                                    CK_ULONG ulRandomLen)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GenerateRandom(hSession, RandomData, ulRandomLen);
    }
}

CK_RV DLL_EXPORTED C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_GetFunctionStatus(hSession);
    }
}

CK_RV DLL_EXPORTED C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_CancelFunction(hSession);
    }
}

CK_RV DLL_EXPORTED C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                                      CK_VOID_PTR pRserved)
{
	if (pkcs11 == NULL_PTR) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        return nss->C_WaitForSlotEvent(flags, pSlot, pRserved);
    }
}
