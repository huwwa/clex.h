#define CLEX_IMPLEMENTATION
#include "../clex.h"
#include <ffi.h>

#define MAX_ARGS 32

typedef struct {
    ffi_type *types[MAX_ARGS];
    void *values[MAX_ARGS];
    int nb;
} Args;

#define CASE(tok, ctype, ffi_type, val)                 \
{                                                       \
    case tok:                                           \
        args.types[args.nb] = &ffi_type;                \
        args.values[args.nb] = malloc(sizeof(ctype));   \
        *(ctype *)args.values[args.nb] = val;           \
        args.nb += 1;                                   \
        break;                                          \
}

void repl(void *dll)
{
    int n;
    char buf[1024], *sym;

    while (1) {
        void *fn;
        Args args   = {0};
        ffi_cif cif = {0};
        ffi_type *rtype;
        ffi_status status;

        printf("> ");
        fflush(stdout);
        if ((n = read(0, buf, sizeof(buf))) < 1)
            break;
        if (n == 1 && *buf == '\n')
            continue;
        /* should utilize a statically allocated buffer instead */
        clex_open_bf_mem(buf, n);

        next();
        if (tok < TOK_UIDENT) {
            fprintf(stderr, "function name expected\n");
            continue;
        }

        sym = table_ident[tok - TOK_IDENT]->str;
        fn = dlsym(dll, sym);
        if (!fn) {
            fprintf(stderr, "%s\n", dlerror());
            continue;
        }

        do {
            next();
            if (args.nb == MAX_ARGS) {
                fprintf(stderr, "too many arguments: %d max.", MAX_ARGS);
                goto end;
            }
            switch (tok) {
                CASE(TOK_CCHAR, char, ffi_type_schar, tokc.i);
                CASE(TOK_CINT, int, ffi_type_sint32, tokc.i);
                CASE(TOK_STR, char*, ffi_type_pointer, strdup(tokc.str.data));
                CASE(TOK_CDOUBLE, double, ffi_type_double, tokc.d);
            default:
                if (tok == TOK_EOF)
                    break;
                printf("invalid argument '%s'\n"
                       "expected syntax: func [arg...]\n" , get_tok_str(tok, &tokc));
                goto end;
            }
        } while (tok != TOK_EOF);

        if (args.nb != 0) {
            status = ffi_prep_cif(&cif, FFI_DEFAULT_ABI,
                                  args.nb, &ffi_type_void, args.types);
            if (status == FFI_OK) {
                ffi_call(&cif, FFI_FN(fn), NULL, args.values);
            } else {
                printf("could not prepare cif\n");
            }
        end:
            for (int i = 0; i < args.nb; ++i) {
                if (args.types[i] == &ffi_type_pointer)
                    free(*(void **)args.values[i]);
                free(args.values[i]);
            }
        }
    }
}

int main(int argc, char **argv)
{
    void *handle;

    if (argc < 2)
        clex_error("Usage: %s [dll.so]", *argv);

    handle = dlopen(argv[1], RTLD_LAZY);
    if (!handle)
        clex_error("%s", dlerror());

    clex_new();
    repl(handle);
    clex_delete();
    dlclose(handle);
    return 0;
}
