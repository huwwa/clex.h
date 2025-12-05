CFLAGS = -Wall -Wextra -ggdb

default: test

test: clex.c clex.h
	cc $(CFLAGS) -o $@ $< && ./test input.c
