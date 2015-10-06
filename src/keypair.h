#ifndef KEYPAIR_H
#define KEYPAIR_H

/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

CK_RV generateRsaKeyPair(CK_FUNCTION_LIST_PTR p11,
                         CK_SESSION_HANDLE session,
                         CK_ULONG size, CK_BYTE_PTR label);

CK_RV ecdsaNeedsEcParams(CK_FUNCTION_LIST *funcs,
                         CK_SLOT_ID slot_id, CK_BBOOL *full);

CK_RV generateEcdsaKeyPair(CK_FUNCTION_LIST_PTR p11,
                           CK_SESSION_HANDLE session,
                           char *name, CK_BBOOL full, CK_BYTE_PTR label);

CK_RV generateGostKeyPair(CK_FUNCTION_LIST_PTR p11,
                          CK_SESSION_HANDLE session,
                          char *name, CK_BYTE_PTR label);

#ifdef __cplusplus
};
#endif

#endif /* KEYPAIR_H */
