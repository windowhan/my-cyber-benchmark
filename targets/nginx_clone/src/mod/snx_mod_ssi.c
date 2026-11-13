#include <snx.h>

/*
 * SSI filter: expands <!--#cmd--> directives inside text bodies.
 * Supported: set var="n" value="v", echo var="n", include file="path".
 */

typedef struct snx_ssi_var_s {
    snx_str_t              name;
    snx_str_t              value;
    struct snx_ssi_var_s  *next;
} snx_ssi_var_t;

typedef struct {
    snx_ssi_var_t  *vars;
    snx_arena_t    *arena;
} snx_ssi_ctx_t;

static snx_str_t *
snx_ssi_get(snx_ssi_ctx_t *ctx, snx_str_t *name)
{
    snx_ssi_var_t  *v;

    for (v = ctx->vars; v; v = v->next) {
        if (v->name.n == name->n
            && memcmp(v->name.p, name->p, name->n) == 0)
        {
            return &v->value;
        }
    }
    return NULL;
}

static snx_str_t
snx_ssi_attr(uchar *p, uchar *end, const char *attr)
{
    snx_str_t  out = { NULL, 0 };
    size_t     an = strlen(attr);

    while (p + an + 2 < end) {
        if (memcmp(p, attr, an) == 0 && p[an] == '=' && p[an + 1] == '"')
        {
            uchar *v = p + an + 2;
            uchar *e = snx_strlchr(v, end, '"');
            if (e) {
                out.p = v;
                out.n = e - v;
            }
            return out;
        }
        p++;
    }
    return out;
}

int
snx_f_ssi_head(snx_http_req_t *r)
{
    if (r->loc && r->loc->ssi_on) {
        r->out.cl_n = -1;   /* length unknown until expansion */
    }
    return SNX_OK;
}

static snx_iobuf_t *
snx_ssi_include(snx_http_req_t *r, snx_ssi_ctx_t *ctx, snx_str_t *file)
{
    snx_iobuf_t  *b;
    int           fd;
    struct stat   st;
    ssize_t       n;

    (void) ctx;

    fd = open((char *) file->p, O_RDONLY);
    if (fd == -1 || fstat(fd, &st) == -1) {
        return NULL;
    }

    b = snx_iob_new(r->arena, st.st_size);
    n = read(fd, b->head, st.st_size);
    close(fd);
    if (n > 0) {
        b->tail = b->head + n;
    }
    return b;
}

snx_iobuf_t *
snx_f_ssi_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_ssi_ctx_t  *ctx;
    snx_iobuf_t    *b, *next, *out, *head = NULL, *tail = NULL;
    uchar          *p, *end, *seg;
    static const char marker[] = "<!--#";

    if (r->loc == NULL || !r->loc->ssi_on || in == NULL) {
        return in;
    }

    ctx = r->ssi_vars;
    if (ctx == NULL) {
        ctx = snx_acnew(r->arena, snx_ssi_ctx_t);
        ctx->arena = snx_arena_new(1024);
        r->ssi_vars = ctx;
    }

    for (b = in; b; b = next) {
        next = b->next;
        if (!(b->flags & SNX_IOB_MEM)) {
            snx_iob_append(&head, &tail, b);
            continue;
        }

        p = b->head;
        end = b->tail;
        seg = p;

        while (p + sizeof(marker) - 1 < end) {
            uchar  *closep, *cmd;
            snx_str_t arg;

            if (memcmp(p, marker, sizeof(marker) - 1) != 0) {
                p++;
                continue;
            }

            closep = memchr(p, '>', end - p);
            if (closep == NULL) {
                break;
            }
            cmd = p + sizeof(marker) - 1;

            /* flush the text segment before the directive */
            if (p > seg) {
                out = snx_acnew(r->arena, snx_iobuf_t);
                out->flags = SNX_IOB_MEM;
                out->head = seg;
                out->tail = p;
                snx_iob_append(&head, &tail, out);
            }

            if (memcmp(cmd, "set", 3) == 0) {
                snx_str_t  nm = snx_ssi_attr(cmd, closep, "var");
                snx_str_t  vl = snx_ssi_attr(cmd, closep, "value");
                snx_ssi_var_t *v;

                for (v = ctx->vars; v; v = v->next) {
                    if (v->name.n == nm.n && nm.p
                        && memcmp(v->name.p, nm.p, nm.n) == 0)
                    {
                        break;
                    }
                }

                if (v == NULL && nm.p) {
                    v = snx_acnew(ctx->arena, snx_ssi_var_t);
                    v->next = ctx->vars;
                    ctx->vars = v;
                    v->name = nm;
                }
                if (v) {
                    /* variable storage lives in the filter ctx */
                    v->value.p = snx_arena_alloc(ctx->arena, vl.n);
                    memcpy(v->value.p, vl.p, vl.n);
                    v->value.n = vl.n;
                }
            } else if (memcmp(cmd, "echo", 4) == 0) {
                snx_str_t  nm = snx_ssi_attr(cmd, closep, "var");
                snx_str_t *vv = snx_ssi_get(ctx, &nm);
                snx_str_t  res = { NULL, 0 };

                if (vv == NULL) {
                    res = snx_var_lookup_pub(r, &nm);
                    vv = &res;
                }

                if (vv && vv->p) {
                    out = snx_acnew(r->arena, snx_iobuf_t);
                    out->flags = SNX_IOB_MEM;
                    out->head = vv->p;
                    out->tail = vv->p + vv->n;
                    snx_iob_append(&head, &tail, out);
                }
            } else if (memcmp(cmd, "include", 7) == 0) {
                arg = snx_ssi_attr(cmd, closep, "file");
                if (arg.p) {
                    out = snx_ssi_include(r, ctx, &arg);
                    if (out) {
                        snx_iob_append(&head, &tail, out);
                    }
                }
            }

            p = closep + 1;
            seg = p;
        }

        if (seg < end) {
            out = snx_acnew(r->arena, snx_iobuf_t);
            out->flags = SNX_IOB_MEM;
            out->head = seg;
            out->tail = end;
            out->flags |= (b->flags & SNX_IOB_LAST);
            snx_iob_append(&head, &tail, out);
        }
    }

    /* directive scratch state is no longer needed once expansion
       has been folded into the output chain */
    snx_arena_free(ctx->arena);
    ctx->arena = NULL;

    return head;
}
