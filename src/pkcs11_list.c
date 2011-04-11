/*
 * Copyright (C) 2011 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <unistd.h>
#include <getopt.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

#include "pkcs11_util.h"
#include "pkcs11_display.h"

void fillAttribute(CK_ATTRIBUTE *attr, CK_ATTRIBUTE_TYPE type,
			  CK_VOID_PTR pvoid, CK_ULONG ulong)
{
	attr->type = type;
	attr->pValue =  pvoid;
	attr->ulValueLen = ulong;
}

CK_RV generateKeyPair(CK_FUNCTION_LIST_PTR p11, 
                      CK_SESSION_HANDLE session,
                      CK_ULONG modulusBits)
{
	CK_RV rv = CKR_HOST_MEMORY;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN , NULL_PTR , 0 };        
    CK_BYTE publicExponent[3] = { 0x01, 0x00, 0x01 };
    CK_BBOOL t = TRUE;
    CK_ATTRIBUTE attrs[2];
    CK_BYTE *tmp = NULL;
    CK_ATTRIBUTE kid[1];
    CK_OBJECT_CLASS	prv_class = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_ATTRIBUTE publicKeyTemplate[6] = {
        /* { CKA_CLASS , &pub_class , sizeof(pub_class) },  */
        /* { CKA_KEY_TYPE , &key_type , sizeof(key_type) }, */
        { CKA_TOKEN,           &t,              sizeof(CK_BBOOL) },
        { CKA_ENCRYPT,         &t,              sizeof(CK_BBOOL) },
        { CKA_VERIFY,          &t,              sizeof(CK_BBOOL) },
        { CKA_WRAP,            &t,              sizeof(CK_BBOOL) }, 
        { CKA_MODULUS_BITS,    &modulusBits,    sizeof(modulusBits) },
        { CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent) },
    };
    CK_ATTRIBUTE privateKeyTemplate[6] = {
        /* { CKA_CLASS , &pub_class , sizeof(pub_class) },  */
        /* { CKA_KEY_TYPE , &key_type , sizeof(key_type) }, */
        { CKA_TOKEN,           &t,              sizeof(CK_BBOOL) }, 
        { CKA_PRIVATE,         &t,              sizeof(CK_BBOOL) },              
        { CKA_SENSITIVE,       &t,              sizeof(CK_BBOOL) }, 
        { CKA_DECRYPT,         &t,              sizeof(CK_BBOOL) }, 
        { CKA_SIGN,            &t,              sizeof(CK_BBOOL) }, 
        { CKA_UNWRAP,          &t,              sizeof(CK_BBOOL) },
    };

	if(p11) {
        goto done;
    }
    
    ;
    
    if((rv = p11->C_GenerateKeyPair
        (session, &mechanism, publicKeyTemplate, 6,
         privateKeyTemplate, 6, &hPublicKey, &hPrivateKey)) != CKR_OK ) {
        goto done;
    }
    
    if((hPublicKey  == CK_INVALID_HANDLE) ||       
       (hPrivateKey == CK_INVALID_HANDLE)) {
        rv = CKR_HOST_MEMORY; /* */
        goto done;
    }

    fillAttribute(&attrs[0], CKA_PUBLIC_EXPONENT, NULL, 0);
    fillAttribute(&attrs[1], CKA_MODULUS,         NULL, 0);
        
    if ((rv = p11->C_GetAttributeValue
         (session, hPublicKey, attrs, 2)) != CKR_OK) {
        goto done;
    }

    if (((attrs[0].pValue = malloc(attrs[0].ulValueLen)) == NULL) ||
        ((attrs[1].pValue = malloc(attrs[1].ulValueLen)) == NULL)) {
        rv = CKR_HOST_MEMORY; 
        goto done;
    }

    if ((rv = p11->C_GetAttributeValue
         (session, hPublicKey, attrs, 2)) != CKR_OK) {
        goto done;
    }
            
    if ((tmp = (CK_BYTE *)malloc(SHA_DIGEST_LENGTH)) != NULL) {
        SHA1((unsigned char*)attrs[1].pValue, attrs[1].ulValueLen, tmp);
        kid[0].type = CKA_ID;
        kid[0].pValue = tmp;
        kid[0].ulValueLen = SHA_DIGEST_LENGTH;
				
        rv = p11->C_SetAttributeValue(session, hPublicKey , kid, 1);
        rv = p11->C_SetAttributeValue(session, hPrivateKey, kid, 1);
    }
 done:
	return rv;
}
    


int do_list_token_objects(CK_FUNCTION_LIST *funcs,
                          CK_SLOT_ID        SLOT_ID,
                          CK_BYTE          *user_pin,
                          CK_ULONG          user_pin_len)
{
    CK_RV             rc;
    CK_FLAGS          flags;
    CK_ULONG          i, j, k, l;
    CK_SESSION_HANDLE h_session;
    CK_OBJECT_HANDLE  obj;

    if(user_pin) {
        /* create a USER/SO R/W session */
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            rc = FALSE;
            goto done;
        }
	 
        rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
        if (rc != CKR_OK) {
            show_error(stdout, "C_Login", rc );
            rc = FALSE;
            goto done;
        }
    } else {
        /* create a Public R/W session */
        flags = CKF_SERIAL_SESSION;
        rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            rc = FALSE;
            goto done;
        }
    }

    rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc );
        rc = FALSE;
        goto done;
    }

    j = 0;

    do {
        rc = funcs->C_FindObjects( h_session, &obj, 1, &i );
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjects", rc );
            rc = FALSE;
            goto done;
        }
        if(i) {
            CK_ATTRIBUTE attribute;

            rc = funcs->C_GetObjectSize( h_session, obj, &k );
            if (rc != CKR_OK) {
                if(rc != CKR_FUNCTION_NOT_SUPPORTED) {
                    show_error(stdout, "C_GetObjectSize", rc );
                    rc = FALSE;
                    goto done;
                }
            } else {
                printf("----------------\nObject %ld has size %ld\n", j, k);
            }

            j++;

            for(k = 0, l = 0; k < ck_attribute_num; k++) {
                attribute.type = ck_attribute_specs[k].type;
                attribute.pValue = NULL;
                attribute.ulValueLen = 0;

                rc = funcs->C_GetAttributeValue( h_session, obj, &attribute, 1);
                if ((rc == CKR_OK) && ((CK_LONG)attribute.ulValueLen != -1)) {
                    attribute.pValue = (CK_VOID_PTR) malloc(attribute.ulValueLen);

                    rc = funcs->C_GetAttributeValue(h_session, obj, &attribute, 1);
                    if (rc == CKR_OK) {
                        printf("(%02ld) %s ", l++, ck_attribute_specs[k].name);

                        ck_attribute_specs[k].display
                            (stdout, attribute.type, attribute.pValue,
                             attribute.ulValueLen, ck_attribute_specs[k].arg);
                    }
                    free(attribute.pValue);
                } else if(rc == CKR_ATTRIBUTE_SENSITIVE) {
                    printf("(%02ld) %s is sensitive\n", l++,
                           ck_attribute_specs[k].name);
                } else if((rc != CKR_ATTRIBUTE_TYPE_INVALID) &&
                          (rc != CKR_TEMPLATE_INCONSISTENT)) {
                    show_error(stdout, "C_GetAttributeValue", rc );
                    rc = FALSE;
                    goto done;
                }
            }
        }
    } while (i);
    
    rc = funcs->C_FindObjectsFinal( h_session );
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc );
        rc = FALSE;
        goto done;
    }

    printf("Found: %ld objects\n", j);
    rc = TRUE;

 done:
    if(user_pin) {
        funcs->C_CloseAllSessions( SLOT_ID );
    }
    return rc;
}

int do_GetSlotInfo(CK_FUNCTION_LIST *funcs,
                   CK_SLOT_ID slot_id)
{
    CK_SLOT_INFO  info;
    CK_RV         rc;

    rc = funcs->C_GetSlotInfo( slot_id, &info );
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc );
        return FALSE;
    }

    printf("CK_SLOT_INFO for slot #%ld:  \n", slot_id);
    print_slot_info(stdout, &info);
    printf("\n\n");

    return TRUE;
}

int do_GetTokenInfo(CK_FUNCTION_LIST *funcs,
                    CK_SLOT_ID slot_id)
{
    CK_TOKEN_INFO  info;
    CK_RV          rc;

    rc = funcs->C_GetTokenInfo( slot_id, &info );
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc );
        return FALSE;
    }

    printf("CK_TOKEN_INFO for slot #%ld:  \n", slot_id);
    print_token_info(stdout, &info);
    printf("\n\n");

    return TRUE;
}

int do_GetTokenMech(CK_FUNCTION_LIST *funcs,
                    CK_SLOT_ID slot_id)
{
    CK_RV             rc;
    CK_MECHANISM_INFO minfo;
    CK_MECHANISM_TYPE_PTR pMechanismList;
    CK_ULONG          imech, ulMechCount;

    rc = funcs->C_GetMechanismList(slot_id, NULL, &ulMechCount);
  
    pMechanismList = (CK_MECHANISM_TYPE *) malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE));
    if (!pMechanismList) {
        fprintf(stderr, "Failed on line %d\n", __LINE__);
        return CKR_HOST_MEMORY;
    }
  
    rc = funcs->C_GetMechanismList(slot_id, pMechanismList, &ulMechCount);
    if (rc != CKR_OK) {
        fprintf(stderr, "Failed on line %d\n", __LINE__);
        return rc;
    }

    for (imech = 0; imech < ulMechCount; imech++) {
        rc = funcs->C_GetMechanismInfo(slot_id, pMechanismList[imech], &minfo);
        print_mech_info(stdout, pMechanismList[imech], &minfo);
    }

    free(pMechanismList);
    return rc;
}

char *app_name = "obj_list";

const struct option options[] = {
    { "show-info",          0, 0,           'I' },
    { "list-slots",         0, 0,           'L' },
    { "list-mechanisms",    0, 0,           'M' },
    { "list-objects",       0, 0,           'O' },
    { "help",               0, 0,           'h' },
    { "login",              0, 0,           'l' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "genkey",             0, 0,           'g' },
    { 0, 0, 0, 0 }
};

const char *option_help[] = {
    "Show global token information",
    "List slots available on the token",
    "List mechanisms supported by the token",
    "List objects contained in the token",
    "Print this help and exit",
    "Log into the token first (not needed when using --pin)",
    "Supply PIN on the command line (if used in scripts: careful!)",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Generate key",
};

void print_usage_and_die(void)
{
    int i = 0;
    printf("Usage: %s [OPTIONS]\nOptions:\n", app_name);
  
    while (options[i].name) {
        char buf[40], tmp[5];
        const char *arg_str;

        /* Skip "hidden" options */
        if (option_help[i] == NULL) {
            i++;
            continue;
        }

        if (options[i].val > 0 && options[i].val < 128)
            sprintf(tmp, ", -%c", options[i].val);
        else
            tmp[0] = 0;
        switch (options[i].has_arg) {
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
        sprintf(buf, "--%s%s%s", options[i].name, tmp, arg_str);
        if (strlen(buf) > 29) {
            printf("  %s\n", buf);
            buf[0] = '\0';
        }
        printf("  %-29s %s\n", buf, option_help[i]);
        i++;
    }
    exit(2);
}

#define NEED_SESSION_RO 0x01
#define NEED_SESSION_RW 0x02

int main( int argc, char **argv )
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_BYTE           opt_pin[20] = "";
    CK_INFO           info;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL;
    int long_optind = 0;
    int do_show_info = 0;
    int do_list_slots = 0;
    int do_list_mechs = 0;
    int do_list_objects = 0;
    int need_session = 0;
    int opt_login = 0;
    int action_count = 0;
    int genkey = 0;

    char c;

    if((argc == 2) && ((opt_pin_len = strlen(argv[1])) < 20)) {
        memcpy( opt_pin, argv[1] , opt_pin_len );
    } else {
        opt_pin_len = 0;
    }

#ifdef HAVE_OPENSSL
    if (OPENSSL_VERSION_NUMBER > 0x00907000L) {
        OpenSSL_add_all_algorithms(); 
    } else {
        OPENSSL_add_all_algorithms_noconf();
    }
#endif

    while (1) {
        c = getopt_long(argc, argv, "ILMOhlp:s:m:",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'I':
                do_show_info = 1;
                action_count++;
                break;
            case 'L':
                do_list_slots = 1;
                action_count++;
                break;
            case 'M':
                do_list_mechs = 1;
                action_count++;
                break;
            case 'O':
                need_session |= NEED_SESSION_RO;
                do_list_objects = 1;
                action_count++;
                break;
            case 'l':
                need_session |= NEED_SESSION_RW;
                opt_login = 1;
                break;
            case 'p':
                need_session |= NEED_SESSION_RW;
                opt_login = 1;
                opt_pin_len = strlen(optarg);
                opt_pin_len = (opt_pin_len < 20) ? opt_pin_len : 19;
                memcpy( opt_pin, optarg, opt_pin_len );
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'g':
                genkey = 1;
                break;
            case 'h':
            default:
                print_usage_and_die();
        }
    }

    funcs = pkcs11_get_function_list( opt_module );
    if (!funcs) {
        printf("Could not get function list.\n");
        return -1;
    }

    rc = pkcs11_initialize(funcs);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Initialize", rc );
        return rc;
    }

    if(do_show_info) {
        rc = funcs->C_GetInfo(&info);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GetInfo", rc );
            return rc;
        } else {
            print_ck_info(stdout,&info);
        }
    }

    if(opt_slot != -1) {
        pslots = &opt_slot;
        nslots = 1;
    } else {
        if(do_list_slots) {
            rc = funcs->C_GetSlotList(0, NULL_PTR, &nslots);
            if (rc != CKR_OK) {
                show_error(stdout, "C_GetSlotList", rc );
                return rc;
            }
            pslots = malloc(sizeof(CK_SLOT_ID) * nslots);
		  
            rc = funcs->C_GetSlotList(0, pslots, &nslots);
            if (rc != CKR_OK) {
                show_error(stdout, "C_GetSlotList", rc );
                return rc;
            }
        }
    }

    for (islot = 0; islot < nslots; islot++) {
        if (do_list_slots) {
            do_GetSlotInfo(funcs, pslots[islot]);
            do_GetTokenInfo(funcs, pslots[islot]);
        }
        if(do_list_mechs) {
            do_GetTokenMech(funcs, pslots[islot]);
        }

        if(do_list_objects) {
            if(opt_pin_len) {
                do_list_token_objects(funcs, pslots[islot],
                                      opt_pin, opt_pin_len);
            } else {
                do_list_token_objects(funcs, pslots[islot], NULL, 0);
            }
        }
        if(genkey) {
            CK_SESSION_HANDLE h_session;
            CK_FLAGS          flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
            rc = funcs->C_OpenSession( pslots[islot], flags, NULL, NULL, &h_session );
            if(opt_pin_len) {
                rc = funcs->C_Login( h_session, CKU_USER, opt_pin, opt_pin_len );
            }
            rc = generateKeyPair(funcs, h_session, 1024);
        }
    }

    rc = funcs->C_Finalize( NULL );
    return rc;
}
