#define CLEX_IMPLEMENTATION
#include "../clex.h"

int main(int argc, char **argv)
{
    const char *filename;

    filename = (argc < 2) ? "-" : argv[1];
    if (clex_init(filename) < 1)
        clex_error("could not open '%s':", filename);

    do {
        next();

        const char *t = get_tok_str(tok, &tokc);
        switch (tok) {
#define DEF(id, str) \
{\
    case id:\
        if (strcmp(get_tok_str(tok, &tokc), str) != 0)\
            clex_error("0x%x: expected: %s, got: %s\n", id, str, t);\
    break;\
}

#include "toks.h"
#undef DEF
        }
        printf("token = %d %s\n", tok, t);
    } while (tok != TOK_EOF);

    clex_deinit();
    return 0;
}
