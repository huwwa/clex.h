CFLAGS = -Wall -Wextra -ggdb
TESTDIR = tests
CC ?= cc

default: test

test: $(TESTDIR)/test_tokens.c clex.h
	$(CC) $(CFLAGS) -o $@ $< && ./test $(TESTDIR)/input
