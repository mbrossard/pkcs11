/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>

CK_RV generateKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session,
                  CK_KEY_TYPE type, CK_ULONG mech, CK_ULONG size,
                  CK_BYTE_PTR label)
{
	CK_RV rv = CKR_HOST_MEMORY;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = { mech, NULL_PTR, 0 };
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_OBJECT_CLASS	class = CKO_SECRET_KEY;
    CK_ATTRIBUTE keyTemplate[9] = {
        { CKA_CLASS ,          &class,    sizeof(class)    },
        { CKA_KEY_TYPE,        &type,     sizeof(type)     },
        { CKA_TOKEN,           &t,        sizeof(CK_BBOOL) },
        { CKA_ENCRYPT,         &t,        sizeof(CK_BBOOL) },
        { CKA_SIGN,            &f,        sizeof(CK_BBOOL) },
        { CKA_VERIFY,          &f,        sizeof(CK_BBOOL) },
        { CKA_WRAP,            &t,        sizeof(CK_BBOOL) },
        { CKA_UNWRAP,          &t,        sizeof(CK_BBOOL) },
        { CKA_VALUE_LEN,       &size,     sizeof(size)     },
    };
    CK_ATTRIBUTE att[1];

	if(!p11) {
        goto done;
    }

    if((rv = p11->C_GenerateKey(session, &mechanism, keyTemplate,
                                size ? 9 : 8, &hKey)) != CKR_OK) {
        show_error(stdout, "C_GenerateKey", rv);
        goto done;
    }

    if(label) {
        fillAttribute(att, CKA_LABEL, label, strlen((char *)label));
        if((rv = p11->C_SetAttributeValue(session, hKey , att, 1)) != CKR_OK) {
            show_error(stdout, "C_SetAttributeValue", rv);
        }
    }

 done:
	return rv;
}
