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

bin_PROGRAMS = pkcs11-util

pkcs11_util_SOURCES = \
	src/base64.c \
	src/clean.c \
	src/common.c \
	src/crypto.c \
	src/init.c \
	src/keypair.c \
	src/keygen.c \
	src/list.c \
	src/pkcs11_display.c \
	src/pkcs11-util.c \
	src/request.c \
	src/speed.c \
	src/ssh.c \
	src/wrap.c

pkcs11_util_LDFLAGS = @OPENSSL_LDFLAGS@
pkcs11_util_LDADD = @OPENSSL_LIBS@

lib_LTLIBRARIES = pkcs11-token.la

pkcs11_token_la_SOURCES = \
	src/cryptoki.c \
	src/iniparser.c \
	src/dictionary.c

pkcs11_token_la_LDFLAGS = \
	-version-info @VERSION_INFO@ \
	-avoid-version -module -no-undefined

pkcs11_token_la_CFLAGS = $(AM_CFLAGS) $(CFLAGS_VISIBILITY)

PIN=Vl0RJlAKiUMf
MODULE_PIN_SLOT = -m @DEFAULT_PKCS11_MODULE@ -d . --pin $(PIN) --slot 2

test:
	@rm -f cert8.db key3.db
	./pkcs11-util init    $(MODULE_PIN_SLOT)
	./pkcs11-util list    $(MODULE_PIN_SLOT) -M
	./pkcs11-util keygen  $(MODULE_PIN_SLOT) -l rsa2048 -k 2048
	./pkcs11-util keygen  $(MODULE_PIN_SLOT) -l ec256   -k prime256v1
	./pkcs11-util request $(MODULE_PIN_SLOT) -l rsa2048 | @OPENSSL_BIN@ req -verify
	if [ "@HAVE_OPENSSL_ECC@" = 1 ] ; then \
	  ./pkcs11-util request $(MODULE_PIN_SLOT) -l ec256   | @OPENSSL_BIN@ req -verify ; \
	fi
	./pkcs11-util certify $(MODULE_PIN_SLOT) -l rsa2048 | @OPENSSL_BIN@ verify
	if [ "@HAVE_OPENSSL_ECC@" = 1 ] ; then \
	  ./pkcs11-util certify $(MODULE_PIN_SLOT) -l ec256   | @OPENSSL_BIN@ verify ; \
	fi
	./pkcs11-util list    $(MODULE_PIN_SLOT) -O
	./pkcs11-util ssh     $(MODULE_PIN_SLOT)
	./pkcs11-util clean   $(MODULE_PIN_SLOT) -r
