/*
 * Copyright (C) 2011 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>

#include "pkcs11_util.h"
#include "pkcs11_display.h"

char *app_name = "pkcs11_speed";

const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "id",                 1, 0,           'i' },
    { "threads",            1, 0,           't' },
    { "operations",         1, 0,           'o' },
    { 0, 0, 0, 0 }
};

const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify label of the private key to use",
    "Specify number of threads to start",
    "Specify number of operations to perform"
};

CK_FUNCTION_LIST *funcs = NULL;
int operations = 1;
CK_OBJECT_HANDLE key;

typedef struct {
    CK_SESSION_HANDLE session;
    pthread_t thread;
} workload_t;

void *do_sign(void *arg)
{
    workload_t *w = (workload_t*)arg;

    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_RV rc;
    int i;

    for(i = 0; i < operations; i++) {
        rc = funcs->C_SignInit(w->session, &mech, key);
        if (rc != CKR_OK) {
            show_error(stdout, "C_SignInit", rc );
            pthread_exit(NULL);
        }

        CK_BYTE  sig[256];
        CK_ULONG len = 256;
        rc = funcs->C_Sign(w->session, (CK_UTF8CHAR *)"Hello, World!", 13, (CK_BYTE_PTR)sig, &len);
        if (rc != CKR_OK) {
            show_error(stdout, "C_Sign", rc );
            pthread_exit(NULL);
        }
    }
    pthread_exit(NULL);
}


int main( int argc, char **argv )
{
    CK_BYTE           opt_pin[32] = "";
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL;
    int long_optind = 0, threads = 1, i;
    workload_t     *work;
    struct timeval start, stop;
    pthread_attr_t pattr;
    char c;

    while (1) {
        c = getopt_long(argc, argv, "hp:s:g:m:t:o:",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'p':
                opt_pin_len = strlen(optarg);
                opt_pin_len = (opt_pin_len < sizeof(opt_pin)) ?
                    opt_pin_len : sizeof(opt_pin) - 1;
                memcpy( opt_pin, optarg, opt_pin_len );
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 't':
                threads = atoi(optarg);
                break;
            case 'o':
                operations = atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
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

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE search[] =
    {
        /* { CKA_LABEL, label, strlen ((char *) label)}, */
        { CKA_CLASS, &class, sizeof(class)}
    };
    CK_ULONG count;

    rc = funcs->C_OpenSession(opt_slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_OpenSession", rc );
        return rc;
    }

    if(*opt_pin != '\0') {
        rc = funcs->C_Login(h_session, CKU_USER, opt_pin, opt_pin_len );
        if (rc != CKR_OK) {
            show_error(stdout, "C_Login", rc );
            return rc;
        }
    }

    rc = funcs->C_FindObjectsInit(h_session, search, 1);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc );
        return rc;
    }

    rc = funcs->C_FindObjects(h_session, &key, 1, &count);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc );
        return rc;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc );
        return rc;
    }

    pthread_attr_init(&pattr);
    pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_JOINABLE);
    if((work = (workload_t *) malloc(threads * sizeof(workload_t))) == NULL) {
        show_error(stdout, "malloc", CKR_HOST_MEMORY);
        return CKR_HOST_MEMORY;
    }

    for (i = 0; i < threads; i++) {
        rc = funcs->C_OpenSession(opt_slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &(work[i].session));
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            return rc;
        }
    }

    gettimeofday(&start, NULL);

    for (i = 0; i < threads; i++) {
        rc = pthread_create( &(work[i].thread), &pattr, do_sign, (void *) &(work[i]));
    }

    for (i = 0; i < threads; i++) {
        void *status;
        pthread_join(work[i].thread, &status);
    }

    gettimeofday(&stop, NULL);
    
    double elapsed =(double)(stop.tv_sec - start.tv_sec) +
        (double)(stop.tv_usec = start.tv_usec) * 0.000001;
    double speed = threads * operations / elapsed;

    printf("Processed %d signatures in %.2fs = %.2f sig/s\n", threads * operations, elapsed, speed);

    for (i = 0; i < threads; i++) {
        rc = funcs->C_CloseSession(work[i].session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_CloseSession", rc );
            return rc;
        }
    }

    if(*opt_pin != '\0') {
        rc = funcs->C_Logout(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_Logout", rc );
            return rc;
        }
    }

    rc = funcs->C_CloseSession(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_CloseSession", rc );
        return rc;
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc );
        return rc;
    }

    rc = funcs->C_Finalize( NULL );
    return rc;
}
