ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

MAINTAINERCLEANFILES = \
    $(srcdir)/Makefile.in \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/compile \
    $(srcdir)/configure \
    $(srcdir)/config.guess \
	$(srcdir)/config.log \
	$(srcdir)/config.status \
	$(srcdir)/config.sub \
    $(srcdir)/depcomp \
    $(srcdir)/install-sh \
	$(srcdir)/ltmain.sh \
	$(srcdir)/missing \
    $(srcdir)/src/config.h.in

EXTRA_DIST = \
		$(srcdir)/LICENSE \
		$(srcdir)/README.md \
		$(srcdir)/m4/*.m4

AM_CFLAGS = @OPENSSL_INCLUDES@ \
	 ${my_CFLAGS} \
	-I$(srcdir)/include \
	-I$(srcdir)/src \
	-fvisibility=hidden \
	-ffunction-sections \
	-fdata-sections

bin_PROGRAMS = pkcs11_list pkcs11_speed pkcs11_clean

pkcs11_list_SOURCES = \
	src/pkcs11_display.c \
	src/pkcs11_util.c \
	src/pkcs11_list.c

pkcs11_list_LDFLAGS = @OPENSSL_LDFLAGS@
pkcs11_list_LDADD = @OPENSSL_LIBS@

pkcs11_clean_SOURCES = \
	src/pkcs11_display.c \
	src/pkcs11_util.c \
	src/pkcs11_clean.c

pkcs11_speed_SOURCES = \
	src/pkcs11_display.c \
	src/pkcs11_util.c \
	src/pkcs11_speed.c

pkcs11_speed_LDADD = -lpthread

lib_LTLIBRARIES = pkcs11-token.la

pkcs11_token_la_SOURCES = \
	src/cryptoki.c \
	src/iniparser.c \
	src/dictionary.c

pkcs11_token_la_LDFLAGS = \
	-version-info @VERSION_INFO@ \
	-avoid-version -module

pkcs11_token_la_CFLAGS = $(AM_CFLAGS) $(CFLAGS_VISIBILITY)
