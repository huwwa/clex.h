CFLAGS = -Wall -Wextra -ggdb
TESTDIR = tests

default: test

test: $(TESTDIR)/test_tokens.c clex.h
	cc $(CFLAGS) -o $@ $< && ./test $(TESTDIR)/input
