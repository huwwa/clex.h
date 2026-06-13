#define CLEX_IMPLEMENTATION
#include "../clex.h"

PUB_FUNC const char *get_tok_name(int v, char *buf, int len)
{
    switch (v) {
#define DEF(id, str) case id: snprintf(buf, len, "tok == " #id); break;
#include "tokens.h"
#undef DEF
        default:
            v &= ~(SYM_FIELD | SYM_STRUCT);
            if (v < TOK_IDENT) {
                if (v >= 127 || (v < 32 && !is_space(v) && v != '\n'))
                    snprintf(buf, len, "<\\x%02x>", v);
                snprintf(buf, len, "tok == '%c'", v);
            } else if (v < tok_ident) {
                snprintf(buf, len, "tok > TOK_UIDENT");
            } else {
                /* should never happen */
                snprintf(buf, len, "unknown");
            }
    }
    return buf;
}

int main(void)
{
    int n;
    char line[1024];
    char buf[64];

    clex_new();
    while (1) {
        printf("> ");
        fflush(stdout);
        if ((n = read(0, line, sizeof(line))) < 1)
            break;
        if (n == 1 && *line == '\n')
            continue;
        /* should utilize a statically allocated bufer instead */
        clex_open_bf_mem(line, n);
        do {
            next();
            printf("cond['%s'] -> (%s)\n", get_tok_str(tok, &tokc),
                   get_tok_name(tok, buf, sizeof(buf)));
        } while (tok != TOK_EOF);
        clex_close();
    }

    clex_delete();
    return 0;
}
