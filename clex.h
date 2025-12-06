/*
 * clex.h - Single-header C Lexer
 *
 * This code is derived from the Tiny C Compiler (TCC) source code.
 * TCC contributors have agreed to relicense core parts of the code under the MIT-style license.
 *
 * TCC Copyright (C) 2001-2006 Fabrice Bellard and TCC Contributors
 * clex.h Copyright (C) 2025 huwwana@gmail.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#ifndef CLEX_H
#define CLEX_H

#ifdef CLEX_IMPLEMENTATION

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef _WIN32
#include <unistd.h>
#include <dlfcn.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <io.h> /* open, close etc. */
#include <direct.h> /* getcwd */
#include <malloc.h> /* alloca */
#endif

#define PUB_FUNC
#ifdef _MSC_VER
# define NORETURN __declspec(noreturn)
#else
# define NORETURN __attribute__((noreturn))
#endif
#define ST_INLN static inline
#define ST_DATA static
#define ST_FUNC static

#define ACCEPT_LF_IN_STRINGS 0

#define TOK_FLAG_BOL   0x0001 /* beginning of line before */
#define TOK_FLAG_BOF   0x0002 /* beginning of file before */

#define PARSE_FLAG_TOK_NUM    0x0002 /* return numbers instead of TOK_PPNUM */
#define PARSE_FLAG_LINEFEED   0x0004 /* line feed is returned as a
                                        returned at eof */
#define PARSE_FLAG_SPACES     0x0010 /* next() returns space tokens (for -E) */
#define PARSE_FLAG_ACCEPT_STRAYS 0x0020 /* next() returns '\\' token */
#define PARSE_FLAG_TOK_STR    0x0040 /* return parsed strings instead of TOK_PPSTR */

/* isidnum_table flags: */
#define IS_SPC 1
#define IS_ID  2
#define IS_NUM 4

#define SYM_STRUCT     0x40000000 /* struct/union/enum symbol space */
#define SYM_FIELD      0x20000000 /* struct/union field symbol space */
#define SYM_FIRST_ANOM 0x10000000 /* first anonymous sym */

/* token values */

/* conditional ops */
#define TOK_LAND  0x90
#define TOK_LOR   0x91
/* warning: the following compare tokens depend on i386 asm code */
#define TOK_ULT 0x92
#define TOK_UGE 0x93
#define TOK_EQ  0x94
#define TOK_NE  0x95
#define TOK_ULE 0x96
#define TOK_UGT 0x97
#define TOK_Nset 0x98
#define TOK_Nclear 0x99
#define TOK_LT  0x9c
#define TOK_GE  0x9d
#define TOK_LE  0x9e
#define TOK_GT  0x9f

#define TOK_DEC     0x80 /* -- */
#define TOK_MID     0x81 /* inc/dec, to void constant */
#define TOK_INC     0x82 /* ++ */
#define TOK_UDIV    0x83 /* unsigned division */
#define TOK_UMOD    0x84 /* unsigned modulo */
#define TOK_PDIV    0x85 /* fast division with undefined rounding for pointers */
#define TOK_UMULL   0x86 /* unsigned 32x32 -> 64 mul */
#define TOK_ADDC1   0x87 /* add with carry generation */
#define TOK_ADDC2   0x88 /* add with carry use */
#define TOK_SUBC1   0x89 /* add with carry generation */
#define TOK_SUBC2   0x8a /* add with carry use */
#define TOK_SHL     '<' /* shift left */
#define TOK_SAR     '>' /* signed shift right */
#define TOK_SHR     0x8b /* unsigned shift right */
#define TOK_NEG     TOK_MID /* unary minus operation (for floats) */

#define TOK_ARROW   0xa0 /* -> */
#define TOK_DOTS    0xa1 /* three dots */
#define TOK_PLCHLDR 0xa4 /* placeholder token as defined in C99 */
#define TOK_SOTYPE  0xa7 /* alias of '(' for parsing sizeof (type) */

/* assignment operators */
#define TOK_A_ADD   0xb0
#define TOK_A_SUB   0xb1
#define TOK_A_MUL   0xb2
#define TOK_A_DIV   0xb3
#define TOK_A_MOD   0xb4
#define TOK_A_AND   0xb5
#define TOK_A_OR    0xb6
#define TOK_A_XOR   0xb7
#define TOK_A_SHL   0xb8
#define TOK_A_SAR   0xb9

/* tokens that carry values (in additional token string space / tokc) --> */
#define TOK_CCHAR   0xc0 /* char constant in tokc */
#define TOK_LCHAR   0xc1
#define TOK_CINT    0xc2 /* number in tokc */
#define TOK_CUINT   0xc3 /* unsigned int constant */
#define TOK_CLLONG  0xc4 /* long long constant */
#define TOK_CULLONG 0xc5 /* unsigned long long constant */
#define TOK_CLONG   0xc6 /* long constant */
#define TOK_CULONG  0xc7 /* unsigned long constant */
#define TOK_STR     0xc8 /* pointer to string in tokc */
#define TOK_LSTR    0xc9
#define TOK_CFLOAT  0xca /* float constant */
#define TOK_CDOUBLE 0xcb /* double constant */
#define TOK_CLDOUBLE 0xcc /* long double constant */
#define TOK_PPNUM   0xcd /* preprocessor number */
#define TOK_PPSTR   0xce /* preprocessor string */
#define TOK_LINENUM 0xcf /* line number info */

#define TOK_EOF       (-1)  /* end of file */
#define TOK_LINEFEED  10    /* line feed */

/* all identifiers and strings have token above that */
#define TOK_IDENT 256
enum clex_token {
    TOK_LAST = TOK_IDENT - 1
#define DEF(id, str) ,id
/* keywords */
     DEF(TOK_IF, "if")
     DEF(TOK_ELSE, "else")
     DEF(TOK_WHILE, "while")
     DEF(TOK_FOR, "for")
     DEF(TOK_DO, "do")
     DEF(TOK_CONTINUE, "continue")
     DEF(TOK_BREAK, "break")
     DEF(TOK_RETURN, "return")
     DEF(TOK_GOTO, "goto")
     DEF(TOK_SWITCH, "switch")
     DEF(TOK_CASE, "case")
     DEF(TOK_DEFAULT, "default")
     DEF(TOK_ASM1, "asm")
     DEF(TOK_ASM2, "__asm")
     DEF(TOK_ASM3, "__asm__")

     DEF(TOK_EXTERN, "extern")
     DEF(TOK_STATIC, "static")
     DEF(TOK_UNSIGNED, "unsigned")
     DEF(TOK__Atomic, "_Atomic")
     DEF(TOK_CONST1, "const")
     DEF(TOK_CONST2, "__const") /* gcc keyword */
     DEF(TOK_CONST3, "__const__") /* gcc keyword */
     DEF(TOK_VOLATILE1, "volatile")
     DEF(TOK_VOLATILE2, "__volatile") /* gcc keyword */
     DEF(TOK_VOLATILE3, "__volatile__") /* gcc keyword */
     DEF(TOK_REGISTER, "register")
     DEF(TOK_SIGNED1, "signed")
     DEF(TOK_SIGNED2, "__signed") /* gcc keyword */
     DEF(TOK_SIGNED3, "__signed__") /* gcc keyword */
     DEF(TOK_AUTO, "auto")
     DEF(TOK_INLINE1, "inline")
     DEF(TOK_INLINE2, "__inline") /* gcc keyword */
     DEF(TOK_INLINE3, "__inline__") /* gcc keyword */
     DEF(TOK_RESTRICT1, "restrict")
     DEF(TOK_RESTRICT2, "__restrict")
     DEF(TOK_RESTRICT3, "__restrict__")
     DEF(TOK_EXTENSION, "__extension__") /* gcc keyword */
     DEF(TOK_THREAD_LOCAL, "_Thread_local") /* C11 thread-local storage */

     DEF(TOK_GENERIC, "_Generic")
     DEF(TOK_STATIC_ASSERT, "_Static_assert")

     DEF(TOK_VOID, "void")
     DEF(TOK_CHAR, "char")
     DEF(TOK_INT, "int")
     DEF(TOK_FLOAT, "float")
     DEF(TOK_DOUBLE, "double")
     DEF(TOK_BOOL, "_Bool")
     DEF(TOK_COMPLEX, "_Complex")
     DEF(TOK_SHORT, "short")
     DEF(TOK_LONG, "long")
     DEF(TOK_STRUCT, "struct")
     DEF(TOK_UNION, "union")
     DEF(TOK_TYPEDEF, "typedef")
     DEF(TOK_ENUM, "enum")
     DEF(TOK_SIZEOF, "sizeof")
     DEF(TOK_ATTRIBUTE1, "__attribute")
     DEF(TOK_ATTRIBUTE2, "__attribute__")
     DEF(TOK_ALIGNOF1, "__alignof")
     DEF(TOK_ALIGNOF2, "__alignof__")
     DEF(TOK_ALIGNOF3, "_Alignof")
     DEF(TOK_ALIGNAS, "_Alignas")
     DEF(TOK_TYPEOF1, "typeof")
     DEF(TOK_TYPEOF2, "__typeof")
     DEF(TOK_TYPEOF3, "__typeof__")
     DEF(TOK_LABEL, "__label__")
#undef DEF
};

typedef struct CString {
    int size; /* size in bytes */
    char *data;
    int size_allocated;
} CString;

typedef union CValue {
    long double ld;
    double d;
    float f;
    uint64_t i;
    struct {
        int size;
        const void *data;
    } str;
} CValue;

typedef int nwchar_t;

#define IO_BUF_SIZE 8192

typedef struct BufferedFile {
    uint8_t *buf_ptr;
    uint8_t *buf_end;
    int fd;
    struct BufferedFile *prev;
    int line_num;    /* current line number - here to simplify code */
    int prev_tok_flags; /* saved tok_flags */
    char filename[1024];    /* filename */
    unsigned char unget[4];
    unsigned char buffer[1]; /* extra size for CH_EOB char */
} BufferedFile;

#define CH_EOB   '\\'
#define CH_EOF   (-1)

/* used to record tokens */
typedef struct TokenString {
    int *str;
    int len;
    int need_spc;
    int allocated_len;
    int last_line_num;
    int save_line_num;
    char alloc;
} TokenString;

#define STRING_MAX_SIZE     1024
#define TOKSTR_MAX_SIZE     256
#define PACK_STACK_SIZE     8

#define TOK_HASH_SIZE       16384 /* must be a power of two */
#define TOK_ALLOC_INCR      512  /* must be a power of two */
#define TOK_MAX_SIZE        4 /* token max size in int unit when stored in string */

/* token symbol management */
typedef struct TokenSym {
    struct TokenSym *hash_next;
    struct Sym *sym_define; /* direct pointer to define */
    struct Sym *sym_label; /* direct pointer to label */
    struct Sym *sym_struct; /* direct pointer to structure */
    struct Sym *sym_identifier; /* direct pointer to identifier */
    int tok; /* token number */
    int len;
    char str[1];
} TokenSym;

/* global variables */
ST_DATA const char clex_keywords[] =
#define DEF(id, str) str "\0"
/* keywords */
     DEF(TOK_IF, "if")
     DEF(TOK_ELSE, "else")
     DEF(TOK_WHILE, "while")
     DEF(TOK_FOR, "for")
     DEF(TOK_DO, "do")
     DEF(TOK_CONTINUE, "continue")
     DEF(TOK_BREAK, "break")
     DEF(TOK_RETURN, "return")
     DEF(TOK_GOTO, "goto")
     DEF(TOK_SWITCH, "switch")
     DEF(TOK_CASE, "case")
     DEF(TOK_DEFAULT, "default")
     DEF(TOK_ASM1, "asm")
     DEF(TOK_ASM2, "__asm")
     DEF(TOK_ASM3, "__asm__")

     DEF(TOK_EXTERN, "extern")
     DEF(TOK_STATIC, "static")
     DEF(TOK_UNSIGNED, "unsigned")
     DEF(TOK__Atomic, "_Atomic")
     DEF(TOK_CONST1, "const")
     DEF(TOK_CONST2, "__const") /* gcc keyword */
     DEF(TOK_CONST3, "__const__") /* gcc keyword */
     DEF(TOK_VOLATILE1, "volatile")
     DEF(TOK_VOLATILE2, "__volatile") /* gcc keyword */
     DEF(TOK_VOLATILE3, "__volatile__") /* gcc keyword */
     DEF(TOK_REGISTER, "register")
     DEF(TOK_SIGNED1, "signed")
     DEF(TOK_SIGNED2, "__signed") /* gcc keyword */
     DEF(TOK_SIGNED3, "__signed__") /* gcc keyword */
     DEF(TOK_AUTO, "auto")
     DEF(TOK_INLINE1, "inline")
     DEF(TOK_INLINE2, "__inline") /* gcc keyword */
     DEF(TOK_INLINE3, "__inline__") /* gcc keyword */
     DEF(TOK_RESTRICT1, "restrict")
     DEF(TOK_RESTRICT2, "__restrict")
     DEF(TOK_RESTRICT3, "__restrict__")
     DEF(TOK_EXTENSION, "__extension__") /* gcc keyword */
     DEF(TOK_THREAD_LOCAL, "_Thread_local") /* C11 thread-local storage */

     DEF(TOK_GENERIC, "_Generic")
     DEF(TOK_STATIC_ASSERT, "_Static_assert")

     DEF(TOK_VOID, "void")
     DEF(TOK_CHAR, "char")
     DEF(TOK_INT, "int")
     DEF(TOK_FLOAT, "float")
     DEF(TOK_DOUBLE, "double")
     DEF(TOK_BOOL, "_Bool")
     DEF(TOK_COMPLEX, "_Complex")
     DEF(TOK_SHORT, "short")
     DEF(TOK_LONG, "long")
     DEF(TOK_STRUCT, "struct")
     DEF(TOK_UNION, "union")
     DEF(TOK_TYPEDEF, "typedef")
     DEF(TOK_ENUM, "enum")
     DEF(TOK_SIZEOF, "sizeof")
     DEF(TOK_ATTRIBUTE1, "__attribute")
     DEF(TOK_ATTRIBUTE2, "__attribute__")
     DEF(TOK_ALIGNOF1, "__alignof")
     DEF(TOK_ALIGNOF2, "__alignof__")
     DEF(TOK_ALIGNOF3, "_Alignof")
     DEF(TOK_ALIGNAS, "_Alignas")
     DEF(TOK_TYPEOF1, "typeof")
     DEF(TOK_TYPEOF2, "__typeof")
     DEF(TOK_TYPEOF3, "__typeof__")
     DEF(TOK_LABEL, "__label__")
#undef DEF
;

/* WARNING: the content of this string encodes token numbers */
ST_DATA const unsigned char tok_two_chars[] =
/* outdated -- gr
    "<=\236>=\235!=\225&&\240||\241++\244--\242==\224<<\1>>\2+=\253"
    "-=\255*=\252/=\257%=\245&=\246^=\336|=\374->\313..\250##\266";
*/{
    '<','=', TOK_LE,
    '>','=', TOK_GE,
    '!','=', TOK_NE,
    '&','&', TOK_LAND,
    '|','|', TOK_LOR,
    '+','+', TOK_INC,
    '-','-', TOK_DEC,
    '=','=', TOK_EQ,
    '<','<', TOK_SHL,
    '>','>', TOK_SAR,
    '+','=', TOK_A_ADD,
    '-','=', TOK_A_SUB,
    '*','=', TOK_A_MUL,
    '/','=', TOK_A_DIV,
    '%','=', TOK_A_MOD,
    '&','=', TOK_A_AND,
    '^','=', TOK_A_XOR,
    '|','=', TOK_A_OR,
    '-','>', TOK_ARROW,
    0
};

ST_DATA int tok_flags;
ST_DATA int parse_flags;
ST_DATA struct BufferedFile *file;
ST_DATA int ch, tok;
ST_DATA CValue tokc;
ST_DATA CString tokcstr;
ST_DATA TokenSym *hash_ident[TOK_HASH_SIZE];
ST_DATA char token_buf[STRING_MAX_SIZE + 1];
ST_DATA CString cstr_buf;
ST_DATA unsigned char isidnum_table[256 - CH_EOF];
ST_DATA struct TinyAlloc *toksym_alloc;
ST_DATA struct TinyAlloc *tokstr_alloc;

/* display benchmark infos */
ST_DATA int tok_ident;
ST_DATA TokenSym **table_ident;

/* function definitions */
ST_FUNC void clex_free(void *ptr);
ST_FUNC void *clex_malloc(unsigned long size);
ST_FUNC void *clex_mallocz(unsigned long size);
ST_FUNC void *clex_realloc(void *ptr, unsigned long size);
ST_FUNC void clex_open_bf(const char *filename, int initlen);
ST_FUNC int clex_open(const char *filename);
ST_FUNC void clex_close(void);
ST_FUNC char *pstrcpy(char *buf, size_t size, const char *s);
ST_FUNC int handle_eob(void);
ST_FUNC NORETURN void clex_error(const char *fmt, ...);
ST_FUNC void cstr_cat(CString *cstr, const char *str, int len);
ST_FUNC void cstr_new(CString *cstr);
ST_FUNC void cstr_free(CString *cstr);
ST_FUNC void cstr_reset(CString *cstr);
ST_FUNC uint8_t *parse_comment(uint8_t *p);
ST_FUNC const char *get_tok_str(int v, CValue *cv);
PUB_FUNC void next(void);

/* space excluding newline */
static inline int is_space(int ch) {
    return ch == ' ' || ch == '\t' || ch == '\v' || ch == '\f' || ch == '\r';
}
static inline int isid(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static inline int isnum(int c) {
    return c >= '0' && c <= '9';
}
static inline int isoct(int c) {
    return c >= '0' && c <= '7';
}
static inline int toup(int c) {
    return (c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c;
}

/* ------------------------------------------------------------------------- */
ST_FUNC int set_idnum(int c, int val)
{
    int prev = isidnum_table[c - CH_EOF];
    isidnum_table[c - CH_EOF] = val;
    return prev;
}

#ifdef _WIN32
ST_FUNC char *normalize_slashes(char *path)
{
    char *p;
    for (p = path; *p; ++p)
        if (*p == '\\')
            *p = '/';
    return path;
}
#endif

ST_FUNC void *clex_malloc(unsigned long size)
{
    void *p;
    p = malloc(size);
    if (!p && size)
        clex_error("memory full (malloc)");
    return p;
}

ST_FUNC void *clex_mallocz(unsigned long size)
{
    void *p;
    p = clex_malloc(size);
    memset(p, 0, size);
    return p;
}

ST_FUNC void *clex_realloc(void *ptr, unsigned long size)
{
    void *ptr1;
    ptr1 = realloc(ptr, size);
    if (!ptr1 && size)
        clex_error("memory full (realloc)");
    return ptr1;
}

ST_FUNC void clex_free(void *ptr)
{
    free(ptr);
}

ST_FUNC char *pstrcpy(char *dst, size_t size, const char *src)
{
    char *p, *p_end;
    int c;

    if (size > 0) {
        p = dst;
        p_end = dst + size - 1;
        while (p < p_end) {
            c = *src++;
            if (c == '\0')
                break;
            *p++ = c;
        }
        *p = '\0';
    }
    return dst;
}

ST_FUNC int clex_open(const char *filename)
{
    int fd;
    if (!strcmp(filename, "-"))
        fd = 0, filename = "<stdin>";
    else
        fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;
    clex_open_bf(filename, 0);
    file->fd = fd;
    return fd;
}

ST_FUNC void clex_close(void)
{
    BufferedFile *bf = file;
    if (bf->fd > 0)
        close(bf->fd);
    file = bf->prev;
    clex_free(bf);
}

ST_FUNC void clex_open_bf(const char *filename, int initlen)
{
    BufferedFile *bf;
    int buflen = initlen ? initlen : IO_BUF_SIZE;

    bf = clex_mallocz(sizeof(BufferedFile) + buflen);
    bf->buf_ptr = bf->buffer;
    bf->buf_end = bf->buffer + initlen;
    bf->buf_end[0] = CH_EOB; /* put eob symbol */
    pstrcpy(bf->filename, sizeof(bf->filename), filename);
#ifdef _WIN32
    normalize_slashes(bf->filename);
#endif
    bf->line_num = 1;
    bf->fd = -1;
    bf->prev = file;
    bf->prev_tok_flags = tok_flags;
    file = bf;
    tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
}

/* ------------------------------------------------------------------------- */
/* Custom allocator for tiny objects */

#define PP_ALLOC_INSERT(a) (a)->next = &pp_allocs; \
		           (a)->prev = pp_allocs.prev; \
		           pp_allocs.prev->next = (a); \
		           pp_allocs.prev = (a);
#define PP_ALLOC_REMOVE(a) (a)->next->prev = (a)->prev; \
		           (a)->prev->next = (a)->next;

typedef struct pp_alloc_t {
    struct pp_alloc_t *next, *prev;
} pp_alloc_t;

static pp_alloc_t pp_allocs;

#define USE_TAL

#ifndef USE_TAL
#define tal_free(al, p) clex_free_impl(p)
#define tal_realloc(al, p, size) clex_realloc_impl(p, size)
#define tal_new(a,b,c)
#define tal_delete(a)

static void clex_free_impl(void *p)
{
    if (p) {
        pp_alloc_t *alloc = ((pp_alloc_t *)p) - 1;

        PP_ALLOC_REMOVE(alloc);
        clex_free(alloc);
    }
}

static void *clex_realloc_impl(void *p, unsigned size)
{
    pp_alloc_t *alloc = NULL;

    if (p) {
        alloc = ((pp_alloc_t *)p) - 1;
        PP_ALLOC_REMOVE(alloc);
    }
    if (size) {
        alloc = clex_realloc(alloc, size + sizeof(pp_alloc_t));
        PP_ALLOC_INSERT(alloc);
        return alloc + 1;
    }
    clex_free(alloc);
    return NULL;
}
#else
#if !defined(MEM_DEBUG)
#define tal_free(al, p) tal_free_impl(al, p)
#define tal_realloc(al, p, size) tal_realloc_impl(&al, p, size)
#define TAL_DEBUG_PARAMS
#else
#define TAL_DEBUG MEM_DEBUG
//#define TAL_INFO 1 /* collect and dump allocators stats */
#define tal_free(al, p) tal_free_impl(al, p, __FILE__, __LINE__)
#define tal_realloc(al, p, size) tal_realloc_impl(&al, p, size, __FILE__, __LINE__)
#define TAL_DEBUG_PARAMS , const char *file, int line
#endif

#define TOKSYM_TAL_SIZE     (768 * 1024) /* allocator for tiny TokenSym in table_ident */
#define TOKSTR_TAL_SIZE     (768 * 1024) /* allocator for tiny TokenString instances */
#define TOKSYM_TAL_LIMIT     256 /* prefer unique limits to distinguish allocators debug msgs */
#define TOKSTR_TAL_LIMIT    1024 /* 256 * sizeof(int) */

typedef struct TinyAlloc {
    unsigned  limit;
    unsigned  size;
    uint8_t *buffer;
    uint8_t *p;
    unsigned  nb_allocs;
    struct TinyAlloc *next, *top;
#ifdef TAL_INFO
    unsigned  nb_peak;
    unsigned  nb_total;
    unsigned  nb_missed;
    uint8_t *peak_p;
#endif
} TinyAlloc;

typedef struct tal_header_t {
    size_t  size; /* word align */
#ifdef TAL_DEBUG
    int     line_num; /* negative line_num used for double free check */
    char    file_name[40];
#endif
} tal_header_t;

#define TAL_ALIGN(size) \
    (((size) + (sizeof (size_t) - 1)) & ~(sizeof (size_t) - 1))

/* ------------------------------------------------------------------------- */

static TinyAlloc *tal_new(TinyAlloc **pal, unsigned limit, unsigned size)
{
    TinyAlloc *al = clex_mallocz(sizeof(TinyAlloc));
    al->p = al->buffer = clex_malloc(size);
    al->limit = limit;
    al->size = size;
    if (pal) *pal = al;
    return al;
}

static void tal_delete(TinyAlloc *al)
{
    TinyAlloc *next;

tail_call:
    if (!al)
        return;
#ifdef TAL_INFO
    fprintf(stderr, "limit %4d  size %7d  nb_peak %5d  nb_total %7d  nb_missed %5d  usage %5.1f%%\n",
            al->limit, al->size, al->nb_peak, al->nb_total, al->nb_missed,
            (al->peak_p - al->buffer) * 100.0 / al->size);
#endif
#if TAL_DEBUG && TAL_DEBUG != 3 /* do not check TAL leaks with -DMEM_DEBUG=3 */
    if (al->nb_allocs > 0) {
        uint8_t *p;
        fprintf(stderr, "TAL_DEBUG: memory leak %d chunk(s) (limit= %d)\n",
                al->nb_allocs, al->limit);
        p = al->buffer;
        while (p < al->p) {
            tal_header_t *header = (tal_header_t *)p;
            if (header->line_num > 0) {
                fprintf(stderr, "%s:%d: chunk of %d bytes leaked\n",
                        header->file_name, header->line_num, (int)header->size);
            }
            p += header->size + sizeof(tal_header_t);
        }
#if TAL_DEBUG == 2
        exit(2);
#endif
    }
#endif
    next = al->next;
    clex_free(al->buffer);
    clex_free(al);
    al = next;
    goto tail_call;
}

static void tal_free_impl(TinyAlloc *al, void *p TAL_DEBUG_PARAMS)
{
    if (!p)
        return;
tail_call:
    if (al->buffer <= (uint8_t *)p && (uint8_t *)p < al->buffer + al->size) {
#ifdef TAL_DEBUG
        tal_header_t *header = (((tal_header_t *)p) - 1);
        if (header->line_num < 0) {
            fprintf(stderr, "%s:%d: TAL_DEBUG: double frees chunk from\n",
                    file, line);
            fprintf(stderr, "%s:%d: %d bytes\n",
                    header->file_name, (int)-header->line_num, (int)header->size);
        } else
            header->line_num = -header->line_num;
#endif
        al->nb_allocs--;
        if (!al->nb_allocs)
            al->p = al->buffer;
    } else if (al->next) {
        al = al->next;
        goto tail_call;
    }
    else {
	pp_alloc_t *alloc = ((pp_alloc_t *)p) - 1;

        PP_ALLOC_REMOVE(alloc);
        clex_free(alloc);
    }
}

static void *tal_realloc_impl(TinyAlloc **pal, void *p, unsigned size TAL_DEBUG_PARAMS)
{
    tal_header_t *header;
    void *ret;
    int is_own;
    unsigned adj_size = TAL_ALIGN(size);
    TinyAlloc *al = *pal;

tail_call:
    is_own = (al->buffer <= (uint8_t *)p && (uint8_t *)p < al->buffer + al->size);
    if ((!p || is_own) && size <= al->limit) {
        if (al->p - al->buffer + adj_size + sizeof(tal_header_t) < al->size) {
            header = (tal_header_t *)al->p;
            header->size = adj_size;
#ifdef TAL_DEBUG
            { int ofs = strlen(file) + 1 - sizeof header->file_name;
            strcpy(header->file_name, file + (ofs > 0 ? ofs : 0));
            header->line_num = line; }
#endif
            ret = al->p + sizeof(tal_header_t);
            al->p += adj_size + sizeof(tal_header_t);
            if (is_own) {
                header = (((tal_header_t *)p) - 1);
                if (p) memcpy(ret, p, header->size);
#ifdef TAL_DEBUG
                header->line_num = -header->line_num;
#endif
            } else {
                al->nb_allocs++;
            }
#ifdef TAL_INFO
            if (al->nb_peak < al->nb_allocs)
                al->nb_peak = al->nb_allocs;
            if (al->peak_p < al->p)
                al->peak_p = al->p;
            al->nb_total++;
#endif
            return ret;
        } else if (is_own) {
            al->nb_allocs--;
            ret = tal_realloc(*pal, 0, size);
            header = (((tal_header_t *)p) - 1);
            if (p) memcpy(ret, p, header->size);
#ifdef TAL_DEBUG
            header->line_num = -header->line_num;
#endif
            return ret;
        }
        if (al->next) {
            al = al->next;
        } else {
            TinyAlloc *bottom = al, *next = al->top ? al->top : al;

            al = tal_new(pal, next->limit, next->size * 2);
            al->next = next;
            bottom->top = al;
        }
        goto tail_call;
    }
    if (is_own) {
	pp_alloc_t *alloc;

        al->nb_allocs--;
        alloc = clex_malloc(size + sizeof(pp_alloc_t));
	PP_ALLOC_INSERT(alloc);
	ret = alloc + 1;
        header = (((tal_header_t *)p) - 1);
        if (p) memcpy(ret, p, header->size);
#ifdef TAL_DEBUG
        header->line_num = -header->line_num;
#endif
    } else if (al->next) {
        al = al->next;
        goto tail_call;
    } else {
	pp_alloc_t *alloc = NULL;

	if (p) {
	    alloc = ((pp_alloc_t *)p) - 1;
	    PP_ALLOC_REMOVE(alloc);
	}
	if (size) {
            alloc = clex_realloc(alloc, size + sizeof(pp_alloc_t));
	    PP_ALLOC_INSERT(alloc);
	    ret = alloc + 1;
	}
	else {
	    clex_free(alloc);
	    ret = NULL;
	}
    }
#ifdef TAL_INFO
    al->nb_missed++;
#endif
    return ret;
}

#endif /* USE_TAL */

static void tal_alloc_init(void)
{
    pp_allocs.next = pp_allocs.prev = &pp_allocs;
}

static void tal_alloc_free(void)
{
    while (pp_allocs.next != &pp_allocs)
	tal_free(toksym_alloc /* dummy */, pp_allocs.next + 1);
}

/* ------------------------------------------------------------------------- */
/* CString handling */
static void cstr_realloc(CString *cstr, int new_size)
{
    int size;

    size = cstr->size_allocated;
    if (size < 8)
        size = 8; /* no need to allocate a too small first string */
    while (size < new_size)
        size = size * 2;
    cstr->data = clex_realloc(cstr->data, size);
    cstr->size_allocated = size;
}

/* add a byte */
ST_INLN void cstr_ccat(CString *cstr, int ch)
{
    int size;
    size = cstr->size + 1;
    if (size > cstr->size_allocated)
        cstr_realloc(cstr, size);
    cstr->data[size - 1] = ch;
    cstr->size = size;
}

ST_INLN char *unicode_to_utf8 (char *b, uint32_t Uc)
{
    if (Uc<0x80) *b++=Uc;
    else if (Uc<0x800) *b++=192+Uc/64, *b++=128+Uc%64;
    else if (Uc-0xd800u<0x800) goto error;
    else if (Uc<0x10000) *b++=224+Uc/4096, *b++=128+Uc/64%64, *b++=128+Uc%64;
    else if (Uc<0x110000) *b++=240+Uc/262144, *b++=128+Uc/4096%64, *b++=128+Uc/64%64, *b++=128+Uc%64;
    else error: clex_error("0x%x is not a valid universal character", Uc);
    return b;
}

/* add a unicode character expanded into utf8 */
ST_INLN void cstr_u8cat(CString *cstr, int ch)
{
    char buf[4], *e;
    e = unicode_to_utf8(buf, (uint32_t)ch);
    cstr_cat(cstr, buf, e - buf);
}

/* add string of 'len', or of its len/len+1 when 'len' == -1/0 */
ST_FUNC void cstr_cat(CString *cstr, const char *str, int len)
{
    int size;
    if (len <= 0)
        len = strlen(str) + 1 + len;
    size = cstr->size + len;
    if (size > cstr->size_allocated)
        cstr_realloc(cstr, size);
    memmove(cstr->data + cstr->size, str, len);
    cstr->size = size;
}

ST_FUNC void cstr_new(CString *cstr)
{
    memset(cstr, 0, sizeof(CString));
}

/* free string and reset it to NULL */
ST_FUNC void cstr_free(CString *cstr)
{
    clex_free(cstr->data);
}

/* reset string to empty */
ST_FUNC void cstr_reset(CString *cstr)
{
    cstr->size = 0;
}

/* XXX: unicode ? */
static void add_char(CString *cstr, int c)
{
    if (c == '\'' || c == '\"' || c == '\\') {
        /* XXX: could be more precise if char or string */
        cstr_ccat(cstr, '\\');
    }
    if (c >= 32 && c <= 126) {
        cstr_ccat(cstr, c);
    } else {
        cstr_ccat(cstr, '\\');
        if (c == '\n') {
            cstr_ccat(cstr, 'n');
        } else {
            cstr_ccat(cstr, '0' + ((c >> 6) & 7));
            cstr_ccat(cstr, '0' + ((c >> 3) & 7));
            cstr_ccat(cstr, '0' + (c & 7));
        }
    }
}

/* ------------------------------------------------------------------------- */
/* allocate a new token */
static TokenSym *tok_alloc_new(TokenSym **pts, const char *str, int len)
{
    TokenSym *ts, **ptable;
    int i;

    if (tok_ident >= SYM_FIRST_ANOM)
        clex_error("memory full (symbols)");

    /* expand token table if needed */
    i = tok_ident - TOK_IDENT;
    if ((i % TOK_ALLOC_INCR) == 0) {
        ptable = clex_realloc(table_ident, (i + TOK_ALLOC_INCR) * sizeof(TokenSym *));
        table_ident = ptable;
    }

    ts = tal_realloc(toksym_alloc, 0, sizeof(TokenSym) + len);
    table_ident[i] = ts;
    ts->tok = tok_ident++;
    ts->sym_define = NULL;
    ts->sym_label = NULL;
    ts->sym_struct = NULL;
    ts->sym_identifier = NULL;
    ts->len = len;
    ts->hash_next = NULL;
    memcpy(ts->str, str, len);
    ts->str[len] = '\0';
    *pts = ts;
    return ts;
}

#define TOK_HASH_INIT 1
#define TOK_HASH_FUNC(h, c) ((h) + ((h) << 5) + ((h) >> 27) + (c))


/* find a token and add it if not found */
ST_FUNC TokenSym *tok_alloc(const char *str, int len)
{
    TokenSym *ts, **pts;
    int i;
    unsigned int h;

    h = TOK_HASH_INIT;
    for(i=0;i<len;i++)
        h = TOK_HASH_FUNC(h, ((unsigned char *)str)[i]);
    h &= (TOK_HASH_SIZE - 1);

    pts = &hash_ident[h];
    for(;;) {
        ts = *pts;
        if (!ts)
            break;
        if (ts->len == len && !memcmp(ts->str, str, len))
            return ts;
        pts = &(ts->hash_next);
    }
    return tok_alloc_new(pts, str, len);
}

/* return the current character, handling end of block if necessary
   (but not stray) */
static int handle_eob(void)
{
    BufferedFile *bf = file;
    int len;

    /* only tries to read if really end of buffer */
    if (bf->buf_ptr >= bf->buf_end) {
        if (bf->fd >= 0) {
#if defined(PARSE_DEBUG)
            len = 1;
#else
            len = IO_BUF_SIZE;
#endif
            len = read(bf->fd, bf->buffer, len);
            if (len < 0)
                len = 0;
        } else {
            len = 0;
        }
        bf->buf_ptr = bf->buffer;
        bf->buf_end = bf->buffer + len;
        *bf->buf_end = CH_EOB;
    }
    if (bf->buf_ptr < bf->buf_end) {
        return bf->buf_ptr[0];
    } else {
        bf->buf_ptr = bf->buf_end;
        return CH_EOF;
    }
}

/* read next char from current input file and handle end of input buffer */
static int next_c(void)
{
    int ch = *++file->buf_ptr;
    /* end of buffer/file handling */
    if (ch == CH_EOB && file->buf_ptr >= file->buf_end)
        ch = handle_eob();
    return ch;
}

/* input with '\[\r]\n' handling. */
static int handle_stray_noerror(int err)
{
    int ch;
    while ((ch = next_c()) == '\\') {
        ch = next_c();
        if (ch == '\n') {
    newl:
            file->line_num++;
        } else {
            if (ch == '\r') {
                ch = next_c();
                if (ch == '\n')
                    goto newl;
                *--file->buf_ptr = '\r';
            }
            if (err)
                clex_error("stray '\\' in program");
            /* may take advantage of 'BufferedFile.unget[4}' */
            return *--file->buf_ptr = '\\';
        }
    }
    return ch;
}

#define ninp() handle_stray_noerror(0)

/* handle '\\' in strings, comments and skipped regions */
static int handle_bs(uint8_t **p)
{
    int c;
    file->buf_ptr = *p - 1;
    c = ninp();
    *p = file->buf_ptr;
    return c;
}

/* skip the stray and handle the \\n case. Output an error if
   incorrect char after the stray */
static int handle_stray(uint8_t **p)
{
    int c;
    file->buf_ptr = *p - 1;
    c = handle_stray_noerror(!(parse_flags & PARSE_FLAG_ACCEPT_STRAYS));
    *p = file->buf_ptr;
    return c;
}

/* handle the complicated stray case */
#define PEEKC(c, p)\
{\
    c = *++p;\
    if (c == '\\')\
        c = handle_stray(&p); \
}

/* single line C++ comments */
static uint8_t *parse_line_comment(uint8_t *p)
{
    int c;
    for(;;) {
        for (;;) {
            c = *++p;
    redo:
            if (c == '\n' || c == '\\')
                break;
            c = *++p;
            if (c == '\n' || c == '\\')
                break;
        }
        if (c == '\n')
            break;
        c = handle_bs(&p);
        if (c == CH_EOF)
            break;
        if (c != '\\')
            goto redo;
    }
    return p;
}

/* C comments */
static uint8_t *parse_comment(uint8_t *p)
{
    int c;
    for(;;) {
        /* fast skip loop */
        for(;;) {
            c = *++p;
        redo:
            if (c == '\n' || c == '*' || c == '\\')
                break;
            c = *++p;
            if (c == '\n' || c == '*' || c == '\\')
                break;
        }
        /* now we can handle all the cases */
        if (c == '\n') {
            file->line_num++;
        } else if (c == '*') {
            do {
                c = *++p;
            } while (c == '*');
            if (c == '\\')
                c = handle_bs(&p);
            if (c == '/')
                break;
            goto check_eof;
        } else {
            c = handle_bs(&p);
        check_eof:
            if (c == CH_EOF)
                clex_error("unexpected end of file in comment");
            if (c != '\\')
                goto redo;
        }
    }
    return p + 1;
}

/* parse a string without interpreting escapes */
static uint8_t *parse_pp_string(uint8_t *p, int sep, CString *str)
{
    int c;
    for(;;) {
        c = *++p;
    redo:
        if (c == sep) {
            break;
        } else if (c == '\\') {
            c = handle_bs(&p);
            if (c == CH_EOF) {
        unterminated_string:
                /* XXX: indicate line number of start of string */
                tok_flags &= ~TOK_FLAG_BOL;
                clex_error("missing terminating %c character", sep);
            } else if (c == '\\') {
                if (str)
                    cstr_ccat(str, c);
                c = *++p;
                /* add char after '\\' unconditionally */
                if (c == '\\') {
                    c = handle_bs(&p);
                    if (c == CH_EOF)
                        goto unterminated_string;
                }
                goto add_char;
            } else {
                goto redo;
            }
        } else if (c == '\n') {
        add_lf:
            if (ACCEPT_LF_IN_STRINGS) {
                file->line_num++;
                goto add_char;
            } else if (str) { /* not skipping */
                goto unterminated_string;
            } else {
                //fprintf(stderr, "missing terminating %c character", sep);
                return p;
            }
        } else if (c == '\r') {
            c = *++p;
            if (c == '\\')
                c = handle_bs(&p);
            if (c == '\n')
                goto add_lf;
            if (c == CH_EOF)
                goto unterminated_string;
            if (str)
                cstr_ccat(str, '\r');
            goto redo;
        } else {
        add_char:
            if (str)
                cstr_ccat(str, c);
        }
    }
    p++;
    return p;
}

/* ------------------------------------------------------------------------- */
/* public functions */

PUB_FUNC void skip(int c)
{
    if (tok != c) {
        char tmp[40];
        pstrcpy(tmp, sizeof tmp, get_tok_str(c, &tokc));
        clex_error("'%s' expected (got '%s')", tmp, get_tok_str(tok, &tokc));
    }
    next();
}

#define PARSE2(c1, tok1, c2, tok2)              \
    case c1:                                    \
        PEEKC(c, p);                            \
        if (c == c2) {                          \
            p++;                                \
            tok = tok2;                         \
        } else {                                \
            tok = tok1;                         \
        }                                       \
        break;

PUB_FUNC void next(void)
{
    int t, c, is_long, len;
    TokenSym *ts;
    uint8_t *p, *p1;
    unsigned int h;

    p = file->buf_ptr;
 redo_no_start:
    c = *p;
    switch(c) {
    case ' ':
    case '\t':
        tok = c;
        p++;
 maybe_space:
        if (parse_flags & PARSE_FLAG_SPACES)
            goto keep_tok_flags;
        while (isidnum_table[*p - CH_EOF] & IS_SPC)
            ++p;
        goto redo_no_start;
    case '\f':
    case '\v':
    case '\r':
        p++;
        goto redo_no_start;
    case '\\':
        /* first look if it is in fact an end of buffer */
        c = handle_stray(&p);
        if (c == '\\')
            goto parse_simple;
        if (c == CH_EOF) {
            if (!(tok_flags & TOK_FLAG_BOL)) {
                /* add implicit newline */
                goto maybe_newline;
            } else {
                tok = TOK_EOF;
            }
        } else {
            goto redo_no_start;
        } break;


    case '\n':
        file->line_num++;
        p++;
maybe_newline:
        tok_flags |= TOK_FLAG_BOL;
        if (0 == (parse_flags & PARSE_FLAG_LINEFEED))
            goto redo_no_start;
        tok = TOK_LINEFEED;
        goto keep_tok_flags;

    case 'a': case 'b': case 'c': case 'd':
    case 'e': case 'f': case 'g': case 'h':
    case 'i': case 'j': case 'k': case 'l':
    case 'm': case 'n': case 'o': case 'p':
    case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x':
    case 'y': case 'z':
    case 'A': case 'B': case 'C': case 'D':
    case 'E': case 'F': case 'G': case 'H':
    case 'I': case 'J': case 'K':
    case 'M': case 'N': case 'O': case 'P':
    case 'Q': case 'R': case 'S': case 'T':
    case 'U': case 'V': case 'W': case 'X':
    case 'Y': case 'Z':
    case '_':
    parse_ident_fast:
        p1 = p;
        h = TOK_HASH_INIT;
        h = TOK_HASH_FUNC(h, c);
        while (c = *++p, isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))
            h = TOK_HASH_FUNC(h, c);
        len = p - p1;
        if (c != '\\') {
            TokenSym **pts;

            /* fast case : no stray found, so we have the full token
               and we have already hashed it */
            h &= (TOK_HASH_SIZE - 1);
            pts = &hash_ident[h];
            for(;;) {
                ts = *pts;
                if (!ts)
                    break;
                if (ts->len == len && !memcmp(ts->str, p1, len))
                    goto token_found;
                pts = &(ts->hash_next);
            }
            ts = tok_alloc_new(pts, (char *) p1, len);
        token_found: ;
        } else {
            /* slower case */
            cstr_reset(&tokcstr);
            cstr_cat(&tokcstr, (char *) p1, len);
            p--;
            PEEKC(c, p);
            while (isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))
            {
                cstr_ccat(&tokcstr, c);
                PEEKC(c, p);
            }
            ts = tok_alloc(tokcstr.data, tokcstr.size);
        }
        tok = ts->tok;
        break;
    case 'L':
        t = p[1];
        if (t == '\'' || t == '\"' || t == '\\') {
            PEEKC(c, p);
            if (c == '\'' || c == '\"') {
                is_long = 1;
                goto str_const;
            }
            *--p = c = 'L';
        }
        goto parse_ident_fast;

    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
    case '8': case '9':
        t = c;
        PEEKC(c, p);
        /* after the first digit, accept digits, alpha, '.' or sign if
           prefixed by 'eEpP' */
    parse_num:
        cstr_reset(&tokcstr);
        for(;;) {
            cstr_ccat(&tokcstr, t);
            if (!((isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))
                  || c == '.'
                  || ((c == '+' || c == '-')
                      && ( (t == 'e' || t == 'E')
                          || t == 'p' || t == 'P'))))
                break;
            t = c;
            PEEKC(c, p);
        }
        /* We add a trailing '\0' to ease parsing */
        cstr_ccat(&tokcstr, '\0');
        tokc.str.size = tokcstr.size;
        tokc.str.data = tokcstr.data;
        tok = TOK_PPNUM;
        break;

    case '.':
        /* special dot handling because it can also start a number */
        PEEKC(c, p);
        if (isnum(c)) {
            t = '.';
            goto parse_num;
        } else if ((isidnum_table['.' - CH_EOF] & IS_ID)
                   && (isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))) {
            *--p = c = '.';
            goto parse_ident_fast;
        } else if (c == '.') {
            PEEKC(c, p);
            if (c == '.') {
                p++;
                tok = TOK_DOTS;
            } else {
                *--p = '.'; /* may underflow into file->unget[] */
                tok = '.';
            }
        } else {
            tok = '.';
        }
        break;
    case '\'':
    case '\"':
        is_long = 0;
    str_const:
        cstr_reset(&tokcstr);
        if (is_long)
            cstr_ccat(&tokcstr, 'L');
        cstr_ccat(&tokcstr, c);
        p = parse_pp_string(p, c, &tokcstr);
        cstr_ccat(&tokcstr, c);
        cstr_ccat(&tokcstr, '\0');
        tokc.str.size = tokcstr.size;
        tokc.str.data = tokcstr.data;
        tok = TOK_PPSTR;
        break;

    case '<':
        PEEKC(c, p);
        if (c == '=') {
            p++;
            tok = TOK_LE;
        } else if (c == '<') {
            PEEKC(c, p);
            if (c == '=') {
                p++;
                tok = TOK_A_SHL;
            } else {
                tok = TOK_SHL;
            }
        } else {
            tok = TOK_LT;
        }
        break;
    case '>':
        PEEKC(c, p);
        if (c == '=') {
            p++;
            tok = TOK_GE;
        } else if (c == '>') {
            PEEKC(c, p);
            if (c == '=') {
                p++;
                tok = TOK_A_SAR;
            } else {
                tok = TOK_SAR;
            }
        } else {
            tok = TOK_GT;
        }
        break;

    case '&':
        PEEKC(c, p);
        if (c == '&') {
            p++;
            tok = TOK_LAND;
        } else if (c == '=') {
            p++;
            tok = TOK_A_AND;
        } else {
            tok = '&';
        }
        break;

    case '|':
        PEEKC(c, p);
        if (c == '|') {
            p++;
            tok = TOK_LOR;
        } else if (c == '=') {
            p++;
            tok = TOK_A_OR;
        } else {
            tok = '|';
        }
        break;

    case '+':
        PEEKC(c, p);
        if (c == '+') {
            p++;
            tok = TOK_INC;
        } else if (c == '=') {
            p++;
            tok = TOK_A_ADD;
        } else {
            tok = '+';
        }
        break;

    case '-':
        PEEKC(c, p);
        if (c == '-') {
            p++;
            tok = TOK_DEC;
        } else if (c == '=') {
            p++;
            tok = TOK_A_SUB;
        } else if (c == '>') {
            p++;
            tok = TOK_ARROW;
        } else {
            tok = '-';
        }
        break;

    PARSE2('!', '!', '=', TOK_NE)
    PARSE2('=', '=', '=', TOK_EQ)
    PARSE2('*', '*', '=', TOK_A_MUL)
    PARSE2('%', '%', '=', TOK_A_MOD)
    PARSE2('^', '^', '=', TOK_A_XOR)

        /* comments or operator */
    case '/':
        PEEKC(c, p);
        if (c == '*') {
            p = parse_comment(p);
            /* comments replaced by a blank */
            tok = ' ';
            goto maybe_space;
        } else if (c == '/') {
            p = parse_line_comment(p);
            tok = ' ';
            goto maybe_space;
        } else if (c == '=') {
            p++;
            tok = TOK_A_DIV;
        } else {
            tok = '/';
        }
        break;

        /* simple tokens */
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
    case ',':
    case ';':
    case ':':
    case '?':
    case '~':
    parse_simple:
        tok = c;
        p++;
        break;
    case 0xEF: /* UTF8 BOM ? */
        if (p[1] == 0xBB && p[2] == 0xBF && p == file->buffer) {
            p += 3;
            goto redo_no_start;
        }
    default:
        if (c >= 0x80 && c <= 0xFF) /* utf8 identifiers */
	    goto parse_ident_fast;
        clex_error("unrecognized character \\x%02x", c);
        break;
    }
    tok_flags = 0;
keep_tok_flags:
    file->buf_ptr = p;
#if defined(PARSE_DEBUG)
    printf("token = %d %s\n", tok, get_tok_str(tok, &tokc));
#endif
}

ST_FUNC const char *get_tok_str(int v, CValue *cv)
{
    char *p;
    int i, len;

    cstr_reset(&cstr_buf);
    p = cstr_buf.data;

    switch(v) {
    case TOK_CINT:
    case TOK_CUINT:
    case TOK_CLONG:
    case TOK_CULONG:
    case TOK_CLLONG:
    case TOK_CULLONG:
        /* XXX: not quite exact, but only useful for testing  */
        sprintf(p, "%llu", (unsigned long long)cv->i);
        break;
    case TOK_LCHAR:
        cstr_ccat(&cstr_buf, 'L');
    case TOK_CCHAR:
        cstr_ccat(&cstr_buf, '\'');
        add_char(&cstr_buf, cv->i);
        cstr_ccat(&cstr_buf, '\'');
        cstr_ccat(&cstr_buf, '\0');
        break;
    case TOK_PPNUM:
    case TOK_PPSTR:
        return (char*)cv->str.data;
    case TOK_LSTR:
        cstr_ccat(&cstr_buf, 'L');
    case TOK_STR:
        cstr_ccat(&cstr_buf, '\"');
        if (v == TOK_STR) {
            len = cv->str.size - 1;
            for(i=0;i<len;i++)
                add_char(&cstr_buf, ((unsigned char *)cv->str.data)[i]);
        } else {
            len = (cv->str.size / sizeof(nwchar_t)) - 1;
            for(i=0;i<len;i++)
                add_char(&cstr_buf, ((nwchar_t *)cv->str.data)[i]);
        }
        cstr_ccat(&cstr_buf, '\"');
        cstr_ccat(&cstr_buf, '\0');
        break;

    case TOK_CFLOAT:
        return strcpy(p, "<float>");
    case TOK_CDOUBLE:
        return strcpy(p, "<double>");
    case TOK_CLDOUBLE:
        return strcpy(p, "<long double>");
    case TOK_LINENUM:
        return strcpy(p, "<linenumber>");

    /* above tokens have value, the ones below don't */
    case TOK_LT:
        v = '<';
        goto addv;
    case TOK_GT:
        v = '>';
        goto addv;
    case TOK_DOTS:
        return strcpy(p, "...");
    case TOK_A_SHL:
        return strcpy(p, "<<=");
    case TOK_A_SAR:
        return strcpy(p, ">>=");
    case TOK_EOF:
        return strcpy(p, "<eof>");
    case 0: /* anonymous nameless symbols */
        return strcpy(p, "<no name>");
    default:
        v &= ~(SYM_FIELD | SYM_STRUCT);
        if (v < TOK_IDENT) {
            /* search in two bytes table */
            const unsigned char *q = tok_two_chars;
            while (*q) {
                if (q[2] == v) {
                    *p++ = q[0];
                    *p++ = q[1];
                    *p = '\0';
                    return cstr_buf.data;
                }
                q += 3;
            }
            if (v >= 127 || (v < 32 && !is_space(v) && v != '\n')) {
                sprintf(p, "<\\x%02x>", v);
                break;
            }
    addv:
            *p++ = v;
            *p = '\0';
        } else if (v < tok_ident) {
            return table_ident[v - TOK_IDENT]->str;
        } else if (v >= SYM_FIRST_ANOM) {
            /* special name for anonymous symbol */
            sprintf(p, "L.%u", v - SYM_FIRST_ANOM);
        } else {
            /* should never happen */
            return NULL;
        }
        break;
    }
    return cstr_buf.data;
}

PUB_FUNC NORETURN void clex_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    if (fmt[0] && fmt[strlen(fmt)-1] == ':')
        fprintf(stderr, " %s", strerror(errno));
    fputc('\n', stderr);

    exit(EXIT_FAILURE);
}

PUB_FUNC void clex_expect(const char *msg)
{
    clex_error("%s expected", msg);
}

PUB_FUNC int clex_init(const char *filename)
{
    int i, c;
    const char *p, *r;

    if (clex_open(filename) < 0)
        return -1;
    /* init isid table */
    for(i = CH_EOF; i<128; i++)
        set_idnum(i,
            is_space(i) ? IS_SPC
            : isid(i) ? IS_ID
            : isnum(i) ? IS_NUM
            : 0);

    for(i = 128; i<256; i++)
        set_idnum(i, IS_ID);

    parse_flags = PARSE_FLAG_TOK_NUM | PARSE_FLAG_TOK_STR;

    tal_new(&toksym_alloc, TOKSYM_TAL_LIMIT, TOKSYM_TAL_SIZE);
    tal_new(&tokstr_alloc, TOKSTR_TAL_LIMIT, TOKSTR_TAL_SIZE);
    tal_alloc_init();

    memset(hash_ident, 0, TOK_HASH_SIZE * sizeof(TokenSym *));

    cstr_new(&tokcstr);
    cstr_new(&cstr_buf);
    cstr_realloc(&cstr_buf, STRING_MAX_SIZE);

    tok_ident = TOK_IDENT;
    p = clex_keywords;
    while (*p) {
        r = p;
        for(;;) {
            c = *r++;
            if (c == '\0')
                break;
        }
        tok_alloc(p, r - p - 1);
        p = r;
    }
    return 1;
}

PUB_FUNC void clex_deinit(void)
{
    int i, n;

    n = tok_ident - TOK_IDENT;
    for(i = 0; i < n; i++)
        tal_free(toksym_alloc, table_ident[i]);
    clex_free(table_ident);
    table_ident = NULL;

    /* free static buffers */
    cstr_free(&tokcstr);
    cstr_free(&cstr_buf);

    /* free allocators */
    tal_alloc_free();
    tal_delete(toksym_alloc);
    toksym_alloc = NULL;
    tal_delete(tokstr_alloc);
    tokstr_alloc = NULL;

    clex_close();
}

#endif //CLEX_IMPLEMENTATION

#endif //CLEX_H
