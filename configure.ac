define([PKCS11_VERSION_MAJOR], [0])
define([PKCS11_VERSION_MINOR], [1])
define([PKCS11_VERSION_PATCH], [0])
define([VERSION_SUFFIX], [])

define([LIB_VERSION_CURRENT], [1])
define([LIB_VERSION_AGE], [1])
define([LIB_VERSION_REVISION], [0])

AC_PREREQ(2.64)
AC_INIT([pkcs11-util],[PKCS11_VERSION_MAJOR.PKCS11_VERSION_MINOR.PKCS11_VERSION_PATCH[]VERSION_SUFFIX])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects)
AC_USE_SYSTEM_EXTENSIONS

VERSION_INFO="LIB_VERSION_CURRENT:LIB_VERSION_REVISION:LIB_VERSION_AGE"
AC_SUBST([VERSION_INFO])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT
AC_LIBTOOL_WIN32_DLL

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_EGREP

gl_VISIBILITY

AC_MSG_CHECKING([if libraries can be versioned])
GLD=`$LD --help < /dev/null 2>/dev/null | grep version-script`
if test "$GLD"; then
    have_ld_version_script=yes
    AC_MSG_RESULT(yes)
else
    have_ld_version_script=no
    AC_MSG_RESULT(no)
    AC_MSG_WARN(*** You have not enabled versioned symbols.)
fi
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

AX_APPEND_LINK_FLAGS([ -Wl,--as-needed -Wl,--gc-sections ],[LDFLAGS])
AX_APPEND_COMPILE_FLAGS([ -Wall -pedantic --std=c11 ])

AC_C_BIGENDIAN

AC_CHECK_HEADERS([getopt.h])
AC_CHECK_FUNCS([getopt_long])
AC_CHECK_LIB(dl, dlsym)
# AC_CHECK_FUNCS([strndup],, AC_DEFINE([_GNU_SOURCE], [], [Linux requires _GNU_SOURCE for strndup]))

AC_ARG_WITH(
        [pkcs11-module],
        [AS_HELP_STRING([--with-pkcs11-module], [Default PKCS#11 module])],
        [pkcs11_module="${withval}"]
)

if test x"$pkcs11_module" == x""; then
   AC_PATH_PROG([PKG_CONFIG], [pkg-config])
   if test x"$PKG_CONFIG" != x""; then
       NSS_LIBDIR=`$PKG_CONFIG nss --variable=libdir 2>/dev/null`
       if test x"NSS_LIBDIR" != x""; then
           if test `uname` == "Darwin" ; then
              NSS_LIBNAME="libsoftokn3.dylib" ;
           else
              NSS_LIBNAME="libsoftokn3.so" ;
              if test ! -f "$NSS_LIBDIR/$NSS_LIBNAME" -a -f "$NSS_LIBDIR/nss/$NSS_LIBNAME" ; then
                  NSS_LIBNAME="nss/$NSS_LIBNAME" ;
              fi
           fi
           pkcs11_module="$NSS_LIBDIR/$NSS_LIBNAME"
       fi
       if test ! -f "$pkcs11_module" ; then
           if test `uname` == "Darwin" ; then
              pkcs11_module=`ls -1 /usr/local/Cellar/nss/*/lib/libsoftokn3.dylib | sort | tail -1` ;
           else
              pkcs11_module=`ls -1 /usr/lib/*/nss/libsoftokn3.so | sort | tail -1` ;
           fi
       fi
   fi
fi

if test x"$pkcs11_module" != x"" -a -f "$pkcs11_module"; then
   pkcs11_path=`echo $pkcs11_module | sed 's|\\\\|\\\\\\\\|g'`
   AC_DEFINE_UNQUOTED([DEFAULT_PKCS11_MODULE], "${pkcs11_path}", [Default PKCS#11 module])
   DEFAULT_PKCS11_MODULE="${pkcs11_module}"
fi
AC_SUBST([DEFAULT_PKCS11_MODULE])

AX_CHECK_OPENSSL
if test x"$OPENSSL_LIBS" != x""; then
   AC_DEFINE_UNQUOTED([HAVE_OPENSSL], [1], [Compiled with OpenSSL])
   AC_MSG_CHECKING([whether OpenSSL version support ECDSA custom methods])
   CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
   AC_RUN_IFELSE(AC_LANG_SOURCE([[AC_LANG_DEFINES_PROVIDED
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#if ((defined(LIBRESSL_VERSION_NUMBER) && \
	(LIBRESSL_VERSION_NUMBER >= 0x20010002L))) || \
	(defined(ECDSA_F_ECDSA_METHOD_NEW))
int main() { return 0; } 
#else
int main() { return -1; } 
#endif
   ]]),[
     HAVE_OPENSSL_ECC=1
     AC_MSG_RESULT([yes])
   ], [
     HAVE_OPENSSL_ECC=0
     AC_MSG_RESULT([no])
  ])
fi
AC_SUBST([HAVE_OPENSSL])
AC_SUBST([HAVE_OPENSSL_ECC])

AX_PTHREAD
AC_SUBST([HAVE_PTHREAD])
CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
LIBS="$LIBS $PTHREAD_LIBS"

AC_CONFIG_FILES([Makefile])

AC_CACHE_SAVE

AC_OUTPUT

AC_MSG_RESULT([
        $PACKAGE $VERSION
        =====

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}

        pkcs11_module:          ${pkcs11_module}
        openssl binary:         ${OPENSSL_BIN}
])
