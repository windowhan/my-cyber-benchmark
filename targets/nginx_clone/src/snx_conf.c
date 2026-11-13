#include <snx.h>

/*
 * Configuration file parser.
 * Grammar:  name arg1 arg2 ... ;      (directive)
 *           name arg1 ... { ... }     (block)
 * Directives form a tree of snx_node_t under an implicit root.
 */

typedef struct {
    uchar        *pos;
    uchar        *end;
    snx_arena_t  *arena;
    const char   *file;
    int           line;
} snx_lexer_t;

static int snx_parse_block(snx_lexer_t *lx, snx_node_t *parent);
static int snx_conf_expand(snx_node_t *node, snx_arena_t *a, int depth);

static snx_node_t *
snx_node_new(snx_lexer_t *lx, snx_node_t *parent, char *name)
{
    snx_node_t  *n;

    n = snx_acnew(lx->arena, snx_node_t);
    n->name = name;
    n->parent = parent;
    return n;
}

static void
snx_node_add_kid(snx_lexer_t *lx, snx_node_t *parent, snx_node_t *kid)
{
    snx_node_t  **k;

    k = snx_arena_alloc(lx->arena,
                        (parent->nkids + 1) * sizeof(snx_node_t *));
    memcpy(k, parent->kids, parent->nkids * sizeof(snx_node_t *));
    k[parent->nkids] = kid;
    parent->kids = k;
    parent->nkids++;
}

static void
snx_node_add_arg(snx_lexer_t *lx, snx_node_t *n, uchar *arg)
{
    uchar  **a;

    a = snx_arena_alloc(lx->arena, (n->nargs + 1) * sizeof(uchar *));
    memcpy(a, n->args, n->nargs * sizeof(uchar *));
    a[n->nargs] = arg;
    n->args = a;
    n->nargs++;
}

static int
snx_lex_space(snx_lexer_t *lx)
{
    uchar  *p;

    for (p = lx->pos; p < lx->end; p++) {
        if (*p == '\n') {
            lx->line++;
            continue;
        }
        if (*p == ' ' || *p == '\t' || *p == '\r') {
            continue;
        }
        if (*p == '#') {
            while (p < lx->end && *p != '\n') {
                p++;
            }
            p--;
            continue;
        }
        break;
    }
    lx->pos = p;
    return p < lx->end;
}

static uchar *
snx_lex_token(snx_lexer_t *lx)
{
    uchar  *s, *p;
    int     quoted = 0;

    s = lx->pos;
    if (s < lx->end && (*s == '"' || *s == '\'')) {
        quoted = *s;
        s++;
        lx->pos++;
    }

    p = lx->pos;
    if (quoted) {
        while (p < lx->end && *p != quoted) {
            p++;
        }
    } else {
        while (p < lx->end
               && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n'
               && *p != ';' && *p != '{' && *p != '}' && *p != '#')
        {
            p++;
        }
    }

    {
        uchar  *tok;
        size_t  len = p - lx->pos;

        tok = snx_arena_alloc(lx->arena, len + 1);
        memcpy(tok, lx->pos, len);
        tok[len] = '\0';

        lx->pos = quoted && p < lx->end ? p + 1 : p;
        return tok;
    }
}

static snx_node_t *
snx_parse_directive(snx_lexer_t *lx, snx_node_t *parent)
{
    snx_node_t  *n;
    uchar       *tok;

    tok = snx_lex_token(lx);
    if (tok == NULL || *tok == '\0') {
        return NULL;
    }

    n = snx_node_new(lx, parent, (char *) tok);

    for ( ;; ) {
        if (!snx_lex_space(lx)) {
            break;
        }

        if (*lx->pos == ';') {
            lx->pos++;
            return n;
        }

        if (*lx->pos == '{') {
            lx->pos++;
            if (snx_parse_block(lx, n) != SNX_OK) {
                return NULL;
            }
            return n;
        }

        tok = snx_lex_token(lx);
        snx_node_add_arg(lx, n, tok);
    }

    return n;
}

static int
snx_parse_block(snx_lexer_t *lx, snx_node_t *parent)
{
    snx_node_t  *d;

    for ( ;; ) {
        if (!snx_lex_space(lx)) {
            return SNX_ERROR;
        }

        if (*lx->pos == '}') {
            lx->pos++;
            return SNX_OK;
        }

        d = snx_parse_directive(lx, parent);
        if (d == NULL) {
            return SNX_ERROR;
        }
        snx_node_add_kid(lx, parent, d);
    }
}

snx_node_t *
snx_conf_parse(const char *path, snx_arena_t *a)
{
    int          fd;
    struct stat  st;
    uchar       *buf;
    ssize_t      n;
    snx_lexer_t  lx;
    snx_node_t  *root;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        snx_log(&snx_stderr_log, SNX_LOG_ERR,
                "open conf %s failed: %d", path, errno);
        return NULL;
    }

    if (fstat(fd, &st) == -1) {
        close(fd);
        return NULL;
    }

    buf = snx_arena_alloc(a, st.st_size + 1);
    n = read(fd, buf, st.st_size);
    close(fd);

    if (n != st.st_size) {
        return NULL;
    }
    buf[st.st_size] = '\0';

    lx.pos = buf;
    lx.end = buf + st.st_size;
    lx.arena = a;
    lx.file = path;
    lx.line = 1;

    root = snx_node_new(&lx, NULL, (char *) "root");

    while (snx_lex_space(&lx)) {
        snx_node_t  *d;

        if (*lx.pos == '}') {
            snx_log(&snx_stderr_log, SNX_LOG_ERR,
                    "%s:%d unexpected }", path, lx.line);
            return NULL;
        }

        d = snx_parse_directive(&lx, root);
        if (d == NULL) {
            snx_log(&snx_stderr_log, SNX_LOG_ERR,
                    "%s:%d parse error", path, lx.line);
            return NULL;
        }
        snx_node_add_kid(&lx, root, d);
    }

    (void) snx_conf_expand(root, a, 0);
    return root;
}

/* expand `include file;` directives in-place: the included file's
   top-level nodes are spliced where the directive stood */
static int
snx_conf_expand(snx_node_t *node, snx_arena_t *a, int depth)
{
    int           i;
    snx_node_t  **kids;
    int           nkids, cap;

    if (depth > 8 || node == NULL) {
        return SNX_OK;
    }

    kids = malloc((node->nkids + 8) * sizeof(snx_node_t *));
    nkids = 0;
    cap = node->nkids + 8;

    for (i = 0; i < node->nkids; i++) {
        snx_node_t  *d = node->kids[i];

        if (strcmp(d->name, "include") == 0 && d->nargs >= 1) {
            snx_node_t  *inc = snx_conf_parse(snx_node_arg(d, 0), a);
            int          k;
            if (inc == NULL) {
                free(kids);
                return SNX_ERROR;
            }
            for (k = 0; k < inc->nkids; k++) {
                if (nkids == cap) {
                    cap *= 2;
                    kids = realloc(kids,
                                   cap * sizeof(snx_node_t *));
                }
                inc->kids[k]->parent = node;
                kids[nkids++] = inc->kids[k];
            }
            continue;
        }

        if (nkids == cap) {
            cap *= 2;
            kids = realloc(kids, cap * sizeof(snx_node_t *));
        }
        kids[nkids++] = d;

        /* recurse into blocks first so nested includes resolve
           before this level is frozen */
        if (d->nkids > 0) {
            if (snx_conf_expand(d, a, depth + 1) != SNX_OK) {
                free(kids);
                return SNX_ERROR;
            }
        }
    }

    {
        snx_node_t  **nk = snx_arena_alloc(a,
                                    nkids * sizeof(snx_node_t *) + 1);
        memcpy(nk, kids, nkids * sizeof(snx_node_t *));
        node->kids = nk;
        node->nkids = nkids;
    }
    free(kids);
    return SNX_OK;
}

snx_node_t *
snx_node_find(snx_node_t *parent, const char *name)
{
    int  i;

    if (parent == NULL) {
        return NULL;
    }
    for (i = 0; i < parent->nkids; i++) {
        if (strcmp(parent->kids[i]->name, name) == 0) {
            return parent->kids[i];
        }
    }
    return NULL;
}

snx_node_t **
snx_node_find_all(snx_node_t *parent, const char *name, int *count)
{
    snx_node_t  **out = NULL;
    int           i, n = 0;
    snx_arena_t  *a = NULL;   /* caller arena: nodes are arena-allocated,
                               reuse parent's allocation arena via parent */

    (void) a;

    for (i = 0; i < parent->nkids; i++) {
        if (strcmp(parent->kids[i]->name, name) == 0) {
            n++;
        }
    }

    *count = n;
    if (n == 0) {
        return NULL;
    }

    /* small array on caller stack arena: nodes live in conf arena which
       outlives us, so malloc-free lifetime is fine here */
    out = malloc(n * sizeof(snx_node_t *));
    n = 0;
    for (i = 0; i < parent->nkids; i++) {
        if (strcmp(parent->kids[i]->name, name) == 0) {
            out[n++] = parent->kids[i];
        }
    }
    return out;
}

const char *
snx_node_arg(snx_node_t *n, int i)
{
    if (n == NULL || i >= n->nargs) {
        return NULL;
    }
    return (const char *) n->args[i];
}

const char *
snx_conf_arg(snx_node_t *n, const char *name)
{
    return snx_node_arg(snx_node_find(n, name), 0);
}

snx_node_t *
snx_conf_find(snx_node_t *n, const char *name)
{
    return snx_node_find(n, name);
}

/* size parser: 10k / 5m / 1g suffixes */
soff_t
snx_parse_size(const char *s)
{
    soff_t   n;
    char     suf;

    if (s == NULL) {
        return -1;
    }
    n = strtol(s, NULL, 10);
    suf = s[strlen(s) - 1];
    switch (suf) {
    case 'k': case 'K': n *= 1024; break;
    case 'm': case 'M': n *= 1024 * 1024; break;
    case 'g': case 'G': n *= 1024 * 1024 * 1024; break;
    }
    return n;
}

/* time parser: 1h30m / 600s / bare seconds */
long
snx_parse_time(const char *s)
{
    long   n = 0;
    const char *p;

    if (s == NULL) {
        return -1;
    }
    for (p = s; *p; ) {
        long  v = strtol(p, (char **) &p, 10);
        switch (*p) {
        case 'd': n += v * 86400; p++; break;
        case 'h': n += v * 3600; p++; break;
        case 'm': n += v * 60; p++; break;
        case 's': n += v; p++; break;
        case 'M': n += v * 2592000; p++; break;
        case 'y': n += v * 31536000; p++; break;
        default:  n += v; break;
        }
    }
    return n;
}
