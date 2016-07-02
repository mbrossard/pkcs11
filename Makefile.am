ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/compile \
	$(srcdir)/config.guess \
	$(srcdir)/config.log \
	$(srcdir)/config.status \
	$(srcdir)/config.sub \
	$(srcdir)/configure \
	$(srcdir)/depcomp \
	$(srcdir)/install-sh \
	$(srcdir)/ltmain.sh \
	$(srcdir)/missing \
	$(srcdir)/src/config.h.in \
	$(srcdir)/src/libpkcs11d.exports

EXTRA_DIST = \
	$(srcdir)/include/*.h \
	$(srcdir)/README.md \
	$(srcdir)/src/*.h \
	$(srcdir)/m4/*.m4

AM_CFLAGS = @OPENSSL_INCLUDES@ \
	 ${my_CFLAGS} \
	-I$(srcdir)/include \
	-I$(srcdir)/src \
	-fvisibility=hidden \
	-ffunction-sections \
	-fdata-sections

if HAVE_OPENSSL
bin_PROGRAMS = pkcs11-util pkcs11d
else
bin_PROGRAMS = pkcs11-util
endif

pkcs11_util_SOURCES = \
	src/base64.c \
	src/certify.c \
	src/clean.c \
	src/common.c \
	src/crypto.c \
	src/extract.c \
	src/info.c \
	src/init.c \
	src/key.c \
	src/keygen.c \
	src/keypair.c \
	src/mechanisms.c \
	src/objects.c \
	src/pkcs11-util.c \
	src/pkcs11_display.c \
	src/random.c \
	src/request.c \
	src/slots.c \
	src/speed.c \
	src/ssh.c

pkcs11_util_LDFLAGS = @OPENSSL_LDFLAGS@
pkcs11_util_LDADD = @OPENSSL_LIBS@

pkcs11d_SOURCES = \
	src/common.c \
	src/crypto.c \
	src/dictionary.c \
	src/iniparser.c \
	src/network.c \
	src/pkcs11d.c \
	src/pkcs11_display.c

pkcs11d_LDFLAGS = @OPENSSL_LDFLAGS@
pkcs11d_LDADD = @OPENSSL_LIBS@

if HAVE_OPENSSL
lib_LTLIBRARIES = pkcs11-token.la libpkcs11d.la
else
lib_LTLIBRARIES = pkcs11-token.la
endif

pkcs11_token_la_SOURCES = \
	src/cryptoki.c \
	src/iniparser.c \
	src/dictionary.c

pkcs11_token_la_LDFLAGS = \
	-version-info @VERSION_INFO@ \
	-avoid-version -module -no-undefined

pkcs11_token_la_CFLAGS = $(AM_CFLAGS) $(CFLAGS_VISIBILITY)

libpkcs11d_la_SOURCES = \
	src/libpkcs11d.c

libpkcs11d_la_CFLAGS = $(AM_CFLAGS) \
	-fvisibility=default

libpkcs11d_la_LDFLAGS = \
	-avoid-version -module --shared -export-dynamic \
	-export-symbols "$(srcdir)/src/libpkcs11d.exports" \
	@OPENSSL_LDFLAGS@

libpkcs11d_la_LIBADD = @OPENSSL_LIBS@

PIN=Vl0RJlAKiUMf
MODULE = -m "@DEFAULT_PKCS11_MODULE@" -d .
SLOT = --slot 2
MODULE_PIN_SLOT = $(MODULE) --pin $(PIN) $(SLOT)

test: pkcs11-util pkcs11-token.la
	@rm -f cert8.db key3.db
	./pkcs11-util init    $(MODULE_PIN_SLOT)
	./pkcs11-util keygen  $(MODULE_PIN_SLOT) -l rsa2048 -k 2048
	./pkcs11-util keygen  $(MODULE_PIN_SLOT) -l ec256   -k prime256v1
	./pkcs11-util keygen  $(MODULE_PIN_SLOT) -l 3des    -k des3
	./pkcs11-util keygen  $(MODULE_PIN_SLOT) -l aes     -k aes
	./pkcs11-util request $(MODULE_PIN_SLOT) -l rsa2048 | @OPENSSL_BIN@ req -verify
	./pkcs11-util certify $(MODULE_PIN_SLOT) -l rsa2048 | @OPENSSL_BIN@ x509
	if [ "@HAVE_OPENSSL_ECC@" = 1 ] ; then \
	  if ! @OPENSSL_BIN@ pkeyutl &>/dev/null ; then \
	    ./pkcs11-util request $(MODULE_PIN_SLOT) -l ec256 | @OPENSSL_BIN@ req -verify ; \
	    ./pkcs11-util certify $(MODULE_PIN_SLOT) -l ec256 | @OPENSSL_BIN@ x509 ; \
		fi ; \
	fi
	./pkcs11-util info            $(MODULE)
	./pkcs11-util list-mechanisms $(MODULE)
	./pkcs11-util list-slots      $(MODULE)
	./pkcs11-util list-objects    $(MODULE_PIN_SLOT)
	./pkcs11-util ssh             $(MODULE_PIN_SLOT)
	./pkcs11-util extract         $(MODULE_PIN_SLOT)
	./pkcs11-util random          $(MODULE) $(SLOT) -l 512 | @OPENSSL_BIN@ base64
	./pkcs11-util speed           $(MODULE_PIN_SLOT) -l rsa2048 -t 2 -o 200
	./pkcs11-util speed           $(MODULE_PIN_SLOT) -l ec256 -e -t 2 -o 500

test-clean:
	./pkcs11-util clean           $(MODULE_PIN_SLOT) -r
