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

VERSION_INFO="LIB_VERSION_CURRENT:LIB_VERSION_REVISION:LIB_VERSION_AGE"
AC_SUBST(VERSION_INFO)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT

AC_PROG_CC
AC_PROG_CC_C99
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

AC_C_BIGENDIAN

AC_CHECK_HEADERS([getopt.h])
AC_CHECK_FUNCS([getopt_long])

AX_CHECK_OPENSSL

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
        cflags:                 ${CFLAGS} ${OPENSSL_INCLUDES}
        ldflags:                ${LDFLAGS} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}
])
