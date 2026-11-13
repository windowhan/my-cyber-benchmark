CC      ?= cc
OSSL    := $(firstword $(wildcard /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3))
CFLAGS  ?= -O2 -g -Wall -Isrc -Isrc/mod -Isrc/proto -Isrc/os
ifneq ($(OSSL),)
CFLAGS  += -DSNX_TLS -I$(OSSL)/include
LDFLAGS ?= -lz -L$(OSSL)/lib -lssl -lcrypto
else
LDFLAGS ?= -lz
endif

SRCS = \
	src/snx_util.c \
	src/snx_conf.c \
	src/snx_ev.c \
	src/snx_main.c \
	src/snx_http.c \
	src/snx_http_core.c \
	src/snx_http_body.c \
	src/snx_script.c \
	src/snx_filter.c \
	src/snx_resolver.c \
	src/snx_mail.c \
	src/snx_stream.c \
	src/snx_tls.c \
	src/mod/snx_mod_rewrite.c \
	src/mod/snx_mod_map.c \
	src/mod/snx_mod_charset.c \
	src/mod/snx_mod_ssi.c \
	src/mod/snx_mod_slice.c \
	src/mod/snx_mod_dav.c \
	src/mod/snx_mod_mp4.c \
	src/mod/snx_mod_proxy.c \
	src/mod/snx_mod_scgi.c \
	src/mod/snx_mod_aio.c \
	src/mod/snx_mod_index.c \
	src/mod/snx_mod_access.c \
	src/mod/snx_mod_limits.c \
	src/mod/snx_mod_sub.c \
	src/mod/snx_mod_gzip.c \
	src/mod/snx_mod_upstream.c \
	src/mod/snx_mod_cache.c \
	src/mod/snx_mod_log.c \
	src/mod/snx_mod_jwt.c \
	src/mod/snx_mod_gunzip.c \
	src/mod/snx_mod_image.c \
	src/proto/snx_h2.c \
	src/proto/snx_hpack.c \
	src/proto/snx_spdy.c \
	src/proto/snx_h3.c \
	src/os/snx_win32.c

OBJS = $(SRCS:.c=.o)

snx: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

ASAN_CFLAGS = -O0 -g -Wall -fsanitize=address,undefined -fno-omit-frame-pointer -Isrc -Isrc/mod -Isrc/proto -Isrc/os
ifneq ($(OSSL),)
ASAN_CFLAGS += -DSNX_TLS -I$(OSSL)/include
endif
ASAN_OBJS  = $(SRCS:.c=.asan.o)

snx_asan: $(ASAN_OBJS)
	$(CC) $(ASAN_CFLAGS) -o $@ $(ASAN_OBJS) $(LDFLAGS)

%.asan.o: %.c src/snx.h
	$(CC) $(ASAN_CFLAGS) -c -o $@ $<

asan: snx_asan

%.o: %.c src/snx.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(ASAN_OBJS) snx snx_asan

.PHONY: clean asan
