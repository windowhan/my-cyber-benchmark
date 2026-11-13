# unit PoC harnesses — built against the ASan-instrumented sources
# .asan.o objects are built with Homebrew llvm (fuzzer runtime), so
# the harnesses must link with the same ASan ABI
CC      := $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang) $(shell which clang))
CFLAGS   = -O0 -g -Wall -fsanitize=address,undefined \
           -fno-omit-frame-pointer -I../../src -I../../src/mod \
           -I../../src/proto -I../../src/os
OSSL     := $(firstword $(wildcard /opt/homebrew/opt/openssl@3/include /usr/local/opt/openssl@3/include))
OSSL_LIB := $(patsubst %/include,%/lib,$(OSSL))
LDFLAGS   = -lz $(if $(OSSL),-L$(OSSL_LIB) -lssl -lcrypto)

ROOT     = ../..
# every ASan object except snx_main (has main())
LIBOBJS  = $(filter-out $(ROOT)/src/snx_main.asan.o,$(wildcard $(ROOT)/src/*.asan.o) $(wildcard $(ROOT)/src/mod/*.asan.o) $(wildcard $(ROOT)/src/proto/*.asan.o) $(wildcard $(ROOT)/src/os/*.asan.o))

all: h_resolver h_proto h_tlsmail h_mem

h_resolver: h_resolver.c $(LIBOBJS)
	$(CC) $(CFLAGS) -DSNX_POC -o $@ h_resolver.c stubs.c \
	  $(filter-out $(ROOT)/src/snx_resolver.asan.o,$(LIBOBJS)) $(LDFLAGS)

h_proto: h_proto.c $(LIBOBJS)
	$(CC) $(CFLAGS) -o $@ h_proto.c stubs.c \
	  $(filter-out $(ROOT)/src/proto/snx_h2.asan.o $(ROOT)/src/proto/snx_spdy.asan.o $(ROOT)/src/proto/snx_h3.asan.o,$(LIBOBJS)) $(LDFLAGS)

h_tlsmail: h_tlsmail.c $(LIBOBJS)
	$(CC) $(CFLAGS) -DSNX_TLS $(if $(OSSL),-I$(OSSL)) -o $@ h_tlsmail.c stubs.c \
	  $(filter-out $(ROOT)/src/snx_tls.asan.o $(ROOT)/src/snx_mail.asan.o $(ROOT)/src/snx_stream.asan.o,$(LIBOBJS)) $(LDFLAGS)

h_mem: h_mem.c $(LIBOBJS)
	$(CC) $(CFLAGS) -o $@ h_mem.c stubs.c \
	  $(filter-out $(ROOT)/src/snx_http_body.asan.o,$(LIBOBJS)) $(LDFLAGS)

clean:
	rm -f h_resolver h_proto h_tlsmail h_mem

.PHONY: all clean
