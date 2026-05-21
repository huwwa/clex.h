CC ?= cc
CFLAGS = -Wall -Wextra -Wno-unused -Wno-sign-compare
LDFLAGS = -lffi

default: lexer ffi

lexer: examples/lexer.c clex.h
	$(CC) $(CFLAGS) -o $@ $< $(CLEXFLAGS)

ffi: examples/ffi.c clex.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(CLEXFLAGS)

clean:
	rm -rf lexer ffi

.PHONY: default all clean
