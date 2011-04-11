HAVE_OPENSSL = 1

INCS    = -I. -Isrc -Iinclude
OPTLVL  = -O2 -Wall -fPIC -DPIC -ansi -pedantic
DEB     = -g
CFLAGS	= $(OPTLVL) $(INCS) $(DEB)
LDFLAGS = -ldl

ifdef  HAVE_OPENSSL
CFLAGS  += -DHAVE_OPENSSL
LDFLAGS += -lcrypto
endif

OS = $(shell uname -s)

ifeq ($(OS),Darwin)
LDFLAGS +=-arch i386 
CFLAGS  +=-arch i386 
endif

TARGETS = src/pkcs11_list

all: $(TARGETS)

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

src/pkcs11_list: src/pkcs11_list.o src/pkcs11_util.o src/pkcs11_display.o
	$(CC) -o $@  $^ $(LDFLAGS) 

clean:
	rm -f $(TARGETS) src/*.o *~ */*~
