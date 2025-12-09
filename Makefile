CC ?= cc
CFLAGS = -Wall -Wextra -Wno-unused -Wno-sign-compare -ggdb
LDFLAGS = -lreadline -lffi
CLEXFLAGS = -lm

default: lexer_repl
all: lexer_repl ffi_repl

lexer_repl: examples/lexer_repl.c clex.h
	$(CC) $(CFLAGS) -o $@ $< $(CLEXFLAGS)

#This example requires BOTH libffi and gnu-readline. Do not build it unless
#these libraries are installed on your system.
ffi_repl: examples/ffi_repl.c clex.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(CLEXFLAGS)

clean:
	rm -rf *_repl .*_history tags

.PHONY: default all clean
