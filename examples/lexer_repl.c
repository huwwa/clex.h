#define CLEX_IMPLEMENTATION
#include "../clex.h"

PUB_FUNC const char *get_tok_name(int v, char *buff, int len)
{
    switch (v) {
#define DEF(id, str) case id: snprintf(buff, len, "tok == " #id); break;
#include "tokens.h"
#undef DEF
        default:
            v &= ~(SYM_FIELD | SYM_STRUCT);
            if (v < TOK_IDENT) {
                if (v >= 127 || (v < 32 && !is_space(v) && v != '\n'))
                    snprintf(buff, len, "<\\x%02x>", v);
                snprintf(buff, len, "tok == '%c'", v);
            } else if (v < tok_ident) {
                snprintf(buff, len, "tok > TOK_UIDENT");
            } else {
                /* should never happen */
                snprintf(buff, len, "unknown");
            }
    }
    return buff;
}

int main(void)
{
    int n;
    char line[BUFSIZ];
    char buff[64];

    clex_new();
    while (1) {
        printf("> ");
        fflush(stdout);
        n = read(0, line, sizeof(line));
        if (n < 0 || !n)
            break;
        if (n == 1)
            continue;

        clex_open_bf_mem(line, n);
        while (1) {
            next();
            if (tok == TOK_EOF)
                break;
            printf("cond(%s) -> %s\n",
                    get_tok_name(tok, buff, sizeof(buff)),
                    get_tok_str(tok, &tokc));
        }
    }
    clex_delete();
    return 0;
}
