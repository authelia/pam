# Makefile for pam_authelia.so - Authelia PAM module (C shim).
#
# Build flags match Authelia's GoReleaser hardening configuration.

CC      ?= gcc
VERSION ?= 0.0.0-dev
CFLAGS   = -O2 -pipe -fstack-protector-strong -fPIC -Wall -Wextra -Werror -pedantic -std=c11
CPPFLAGS = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -DPAM_AUTHELIA_VERSION='"$(VERSION)"'
LIBS     = -lpam

# Platform detection.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SO_EXT   = .dylib
    LDFLAGS  = -shared -dynamiclib
    PAM_DIR ?= /usr/local/lib/pam
else
    # Linux-specific hardening flags.
    CFLAGS  += -fno-plt
    LDFLAGS  = -shared -Wl,-O1,-sort-common,-as-needed,-z,relro,-z,now
    SO_EXT   = .so
    PAM_DIR ?= /lib/security
endif

SRC    = src/pam_authelia.c
OBJ    = $(SRC:.c=.o)
TARGET = pam_authelia$(SO_EXT)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c src/pam_authelia.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(EXTRA_CPPFLAGS) -c -o $@ $<

install: $(TARGET)
	install -d $(DESTDIR)$(PAM_DIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(PAM_DIR)/

clean:
	rm -f $(OBJ) $(TARGET)
