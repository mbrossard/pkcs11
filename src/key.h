#ifndef KEY_H
#define KEY_H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

CK_RV generateKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session,
                  CK_KEY_TYPE type, CK_ULONG mech, CK_ULONG size,
                  CK_BYTE_PTR label);

#ifdef __cplusplus
};
#endif

#endif /* KEY_H */
