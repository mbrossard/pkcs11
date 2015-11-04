/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "pkcs11-util.h"

#ifdef HAVE_PTHREAD
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>
#include <getopt.h>
#include <stdio.h>

#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

static char *app_name = "pkcs11-util speed";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "label",              1, 0,           'l' },
    { "threads",            1, 0,           't' },
    { "operations",         1, 0,           'o' },
    { "directory",          1, 0,           'd' },
    { "elliptic",           0, 0,           'e' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify label of the private key to use",
    "Specify number of threads to start",
    "Specify number of operations to perform",
    "Specify the directory for NSS database",
    "Test ECDSA performance",
};

static pthread_mutex_t join_mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int thread_ready = 0;

static CK_FUNCTION_LIST *funcs = NULL;
static int operations = 1;
static CK_OBJECT_HANDLE key;
static CK_BBOOL failure;
static CK_ULONG sig_mech = CKM_RSA_PKCS;

typedef struct {
    CK_SESSION_HANDLE session;
    pthread_t thread;
} workload_t;

void *do_sign(void *arg)
{
    workload_t *w = (workload_t*)arg;

    CK_MECHANISM mech = { sig_mech, NULL_PTR, 0 };
    CK_RV rc;
    int i;

    pthread_mutex_lock(&join_mut);
    thread_ready += 1;
    pthread_cond_wait(&cond, &join_mut);
    pthread_mutex_unlock(&join_mut);

    for(i = 0; i < operations; i++) {
        rc = funcs->C_SignInit(w->session, &mech, key);
        if (rc != CKR_OK) {
            failure = CK_TRUE;
            show_error(stdout, "C_SignInit", rc);
            pthread_exit(NULL);
        }

        CK_BYTE  sig[256];
        CK_ULONG len = 256;
        rc = funcs->C_Sign(w->session, (CK_UTF8CHAR *)"Hello, World!", 13, (CK_BYTE_PTR)sig, &len);
        if (rc != CKR_OK) {
            failure = CK_TRUE;
            show_error(stdout, "C_Sign", rc);
            pthread_exit(NULL);
        }
    }
    pthread_exit(NULL);
}

int speed( int argc, char **argv )
{
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    char             *opt_label = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0, threads = 1, i;
    workload_t     *work;
    struct timeval start, stop;
    pthread_attr_t pattr;
    char c;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE kt = CKK_RSA;
    CK_ATTRIBUTE search[3];
    CK_ULONG count = 2;

    while (1) {
        c = getopt_long(argc, argv, "hd:ep:s:g:l:m:t:o:",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
            case 'p':
                opt_pin = (CK_UTF8CHAR_PTR) strdup(optarg);
                if(opt_pin) {
                    opt_pin_len = strlen(optarg);
                }
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
            case 'l':
                opt_label = optarg;
                break;
            case 'e':
                kt = CKK_EC;
                sig_mech = CKM_ECDSA;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    funcs = pkcs11_get_function_list(opt_module);
    if (!funcs) {
        fprintf(stdout, "Could not get function list.\n");
        return -1;
    }

    rc = pkcs11_initialize_nss(funcs, opt_dir);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Initialize", rc);
        return rc;
    }

    rc = pkcs11_login_session(funcs, stdout, opt_slot, &h_session,
                              CK_FALSE, CKU_USER, opt_pin, opt_pin_len);
    if (rc != CKR_OK) {
        return rc;
    }

    fillAttribute(&(search[0]), CKA_CLASS, &class, sizeof(class));
    fillAttribute(&(search[1]), CKA_KEY_TYPE, &kt, sizeof(kt));
    if(opt_label) {
        fillAttribute(&(search[2]), CKA_LABEL, opt_label, strlen(opt_label));
        count = 2;
    }

    rc = pkcs11_find_object(funcs, stdout, h_session, search,
                            count, &key, 1, &count);
    if (rc != CKR_OK) {
        return rc;
    }

    if(count == 0) {
        fprintf(stdout, "No object found\n");
        exit(-1);
    }

    print_object_info(funcs, stdout, 0, h_session, key);

    failure = CK_FALSE;

    pthread_attr_init(&pattr);
    pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_JOINABLE);
    if((work = (workload_t *) malloc(threads * sizeof(workload_t))) == NULL) {
        show_error(stdout, "malloc", CKR_HOST_MEMORY);
        return CKR_HOST_MEMORY;
    }

    for (i = 0; i < threads; i++) {
        rc = funcs->C_OpenSession(opt_slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &(work[i].session));
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc);
            return rc;
        }
    }

    for (i = 0; i < threads; i++) {
        rc = pthread_create( &(work[i].thread), &pattr, do_sign, (void *) &(work[i]));
    }

    /* Wait until all threads are ready */
    i = 0;
    do {
        usleep(100);
        pthread_mutex_lock(&join_mut);
        i = thread_ready;
        pthread_mutex_unlock(&join_mut);
    } while (i != threads);

    fprintf(stdout, "\n\nStarting test (%d threads, %d operations)\n", threads, operations);

    gettimeofday(&start, NULL);
    /* Unleash all threads */
    pthread_cond_broadcast(&cond);

    for (i = 0; i < threads; i++) {
        void *status;
        pthread_join(work[i].thread, &status);
    }

    gettimeofday(&stop, NULL);
    
    double elapsed =(double)(stop.tv_sec - start.tv_sec) +
        (double)(stop.tv_usec = start.tv_usec) * 0.000001;
    double speed = threads * operations / elapsed;

    fprintf(stdout, "Processed %d signatures in %.2fs = %.2f sig/s\n", threads * operations, elapsed, speed);

    if(failure) {
        fprintf(stdout, "Failure recorded at some point, the result might not be trustworthy\n");
    }

    for (i = 0; i < threads; i++) {
        rc = funcs->C_CloseSession(work[i].session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_CloseSession", rc);
            return rc;
        }
    }

    if(opt_pin) {
        rc = funcs->C_Logout(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_Logout", rc);
            return rc;
        }
    }

    rc = funcs->C_CloseSession(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_CloseSession", rc);
        return rc;
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
        return rc;
    }

    return rc;
}

#endif
