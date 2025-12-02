#define CLEX_IMPLEMENTATION
#include "clex.h"

int main(int argc, char **argv)
{
    const char *filename;

    filename = (argc < 2) ? "-" : argv[1];
    if (clex_init(filename) < 1) {
        fprintf(stderr, "could not open '%s': %s\n", filename, strerror(errno));
        exit(1);
    }

    do {
        next();
        printf("token = %d %s\n", tok, get_tok_str(tok, &tokc));
    } while (tok != TOK_EOF);

    clex_deinit();
    return 0;
}
