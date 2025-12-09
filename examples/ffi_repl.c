/* This program uses libffi to call C functions dynamically, and gnu-readline to
 * handle interactive input. Function argument can be int, double, char, or
 * string. The return value of the function is ignored.  */

#define CLEX_IMPLEMENTATION
#include "../clex.h"
#include <ffi.h>

#include <readline/readline.h>
#include <readline/history.h>

typedef struct {
    ffi_type **types;
    void **values;
    int nb_types;
    int nb_values;
} ARGState;

void dynarray_add(void *ptab, int *nb_ptr, void *data)
{
    int nb, nb_alloc;
    void **pp;

    nb = *nb_ptr;
    pp = *(void ***)ptab;
    /* every power of two we double array size */
    if ((nb & (nb - 1)) == 0) {
        if (!nb)
            nb_alloc = 1;
        else
            nb_alloc = nb * 2;
        pp = realloc(pp, nb_alloc * sizeof(void *));
        *(void***)ptab = pp;
    }
    pp[nb++] = data;
    *nb_ptr = nb;
}

void dynarray_reset(void *pp, int *n)
{
    void **p;
    for (p = *(void***)pp; *n; ++p, --*n)
        if (*p)
            free(*p);
    free(*(void**)pp);
    *(void**)pp = NULL;
}

void repl(void *dll)
{
    char *buf, *sym;
    int len;
    void *fn;
    ffi_type *rtype;

    ffi_cif cif = {0};
    ARGState s1 = {0};
    clex_new();
    using_history();

    while (1) {
redo:
        buf = readline(">> ");
        if (!buf)
            break;
        len = strlen(buf);
        if (!len)
            continue;
        clex_open_bf_mem(buf, len);
        add_history(buf);

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

        s1.nb_types = 0;
        s1.nb_values = 0;
        do {
            next();
            switch (tok) {
#define CASE(id, ctype, ffi_type, value)\
{\
    case id:\
            dynarray_add(&s1.types, &s1.nb_types, &ffi_type);\
            ctype* x = malloc(sizeof *x);\
            *x = value;\
            dynarray_add(&s1.values, &s1.nb_values, x);\
            break;\
}
                CASE(TOK_CCHAR, char, ffi_type_schar, tokc.i);
                CASE(TOK_CINT, int, ffi_type_sint32, tokc.i);
                CASE(TOK_STR, char*, ffi_type_pointer, strdup(tokc.str.data));
                CASE(TOK_CDOUBLE, double, ffi_type_double, tokc.d);
                default:
                    if (tok == TOK_EOF)
                        break;
                    printf("invalid argument '%s'\n"
                            "expected syntax: func [arg...]\n" , get_tok_str(tok, &tokc));
                    goto redo;
            }
        } while (tok != TOK_EOF);

        ffi_status status = ffi_prep_cif(&cif, FFI_DEFAULT_ABI, s1.nb_types, &ffi_type_void, s1.types);
        if (status != FFI_OK) {
            printf("could not prepare cif\n");
            continue;
        }

        ffi_call(&cif, FFI_FN(fn), NULL, s1.values);
    }
    clex_delete();
    write_history(".repl_history");

    free(s1.types);
    dynarray_reset(&s1.values, &s1.nb_values);
}

int main(int argc, char **argv)
{
    void *handle;

    if (argc < 2)
        clex_error("Usage: %s [dll.so]", *argv);

    handle = dlopen(argv[1], RTLD_LAZY);
    if (!handle)
        clex_error("%s", dlerror());

    repl(handle);
    dlclose(handle);
    return 0;
}
