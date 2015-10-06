#include "config.h"
#include "crypto.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

void init_crypto()
{
#ifdef HAVE_OPENSSL
    OPENSSL_add_all_algorithms_noconf();
#endif
}
