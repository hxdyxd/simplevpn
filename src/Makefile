# Makefile of simplevpn
# Copyright (C) 2019-2024  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config
DIR_OBJS ?= $(shell pwd)

TARGET += simplevpn

OBJS +=  log.o
OBJS +=  daemon.o
OBJS +=  simplevpn.o
OBJS +=  udp_alloc.o
OBJS +=  switch.o
OBJS +=  cache_table.o

C_INCLUDES += -I $(shell pwd)/

CFLAGS += -O3 -Wall -g -std=gnu99 $(C_DEFS)

ifeq ($(USE_CRYPTO), 1)
OBJS +=  crypto.o
CFLAGS += -DUSE_CRYPTO
CFLAGS += $(shell $(PKG_CONFIG) --cflags libsodium)
ifneq ($(STATIC), 1)
LDFLAGS += $(shell $(PKG_CONFIG) --libs libsodium)
endif
endif


LDFLAGS += -lpthread

quiet_CC  =      @echo "  CC      $@"; $(CC)
quiet_LD  =      @echo "  LD      $@"; $(LD)
quiet_INSTALL  = @echo "  INSTALL $?"; $(INSTALL)
quiet_MAKE     = @echo "  MAKE    $@"; $(MAKE)

V = 0
ifeq ($(V), 0)
	quiet = quiet_
else
	quiet =
endif

STATIC = 0
ifeq ($(STATIC), 1)
	LDFLAGS += -static
endif
CFLAGS += $(C_INCLUDES)

OBJS := $(addprefix $(DIR_OBJS)/,$(OBJS))
TARGET := $(addprefix $(DIR_OBJS)/,$(TARGET))

all: $(TARGET)
	@echo "build success!"

.PHONY: $(TARGET)
$(TARGET): $(OBJS)
	$($(quiet)LD) -o $@ $^ $(LDFLAGS)

$(DIR_OBJS)/%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	-$(RM) -f $(TARGET) $(OBJS)

install: $(TARGET)
	$($(quiet)INSTALL) -D $< /usr/local/bin/$<

uninstall:
	-$(RM) -f /usr/local/bin/$(TARGET)
