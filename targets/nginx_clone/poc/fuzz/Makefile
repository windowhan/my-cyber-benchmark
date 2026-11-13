# fuzz harness — libFuzzer + ASan/UBSan over the snx parsers
# Apple CLT clang ships no fuzzer runtime; prefer Homebrew llvm
CC      := $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang) $(shell which clang))
CFLAGS   = -O1 -g -fsanitize=fuzzer,address,undefined \
           -fno-omit-frame-pointer -I../../src -I../../src/mod \
           -I../../src/proto -I../../src/os
LDFLAGS  = -lz

ROOT     = ../..
LIBOBJS  = $(filter-out $(ROOT)/src/snx_main.asan.o,$(wildcard $(ROOT)/src/*.asan.o) $(wildcard $(ROOT)/src/mod/*.asan.o) $(wildcard $(ROOT)/src/proto/*.asan.o) $(wildcard $(ROOT)/src/os/*.asan.o))

OSSL     := $(firstword $(wildcard /opt/homebrew/opt/openssl@3/include /usr/local/opt/openssl@3/include))
OSSL_LIB := $(patsubst %/include,%/lib,$(OSSL))

all: fuzz_snx

fuzz_snx: fuzz_snx.c $(LIBOBJS)
	$(CC) $(CFLAGS) -o $@ fuzz_snx.c $(LIBOBJS) $(LDFLAGS) $(if $(OSSL),-L$(OSSL_LIB) -lssl -lcrypto)

corpus:
	mkdir -p corpus
	printf 'GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n' > corpus/seed1
	printf 'PRI * HTTP/2.0\r\n' > corpus/seed2
	printf 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.x' > corpus/seed3
	printf '\x82\x87\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65' > corpus/seed4

run: fuzz_snx corpus
	./fuzz_snx corpus -max_total_time=30 -print_final_stats=1

clean:
	rm -f fuzz_snx
	rm -rf fuzz_snx.dSYM

.PHONY: all corpus run clean
