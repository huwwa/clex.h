CFLAGS = -Wall -Wextra -ggdb

default: clex

clex: clex.c clex.h
	cc $(CFLAGS) -o $@ $<
