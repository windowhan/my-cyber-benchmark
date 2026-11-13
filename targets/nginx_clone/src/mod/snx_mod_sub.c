#include <snx.h>

/*
 * sub_filter: literal string substitution on the response body.
 * Matches run case-insensitively across buffer boundaries via a
 * pending tail kept between calls.
 */

typedef struct {
    snx_str_t   from;
    snx_str_t   to;
    int         once;
    int         done;
    uchar       tail[128];
    size_t      tn;
} snx_sub_ctx_t;

static snx_sub_ctx_t *
snx_sub_ctx(snx_http_req_t *r)
{
    const char  *a0, *a1, *a2;

    if (r->sub_ctx == NULL) {
        if (r->loc == NULL || r->loc->conf == NULL) {
            return NULL;
        }
        {
            snx_node_t *d = snx_conf_find(r->loc->conf, "sub_filter");
            if (d == NULL) {
                return NULL;
            }
            a0 = snx_node_arg(d, 0);
            a1 = snx_node_arg(d, 1);
            a2 = snx_node_arg(d, 2);
            if (a0 == NULL || a1 == NULL) {
                return NULL;
            }
            r->sub_ctx = snx_acnew(r->arena, snx_sub_ctx_t);
            ((snx_sub_ctx_t *) r->sub_ctx)->from.p = (uchar *) a0;
            ((snx_sub_ctx_t *) r->sub_ctx)->from.n = strlen(a0);
            ((snx_sub_ctx_t *) r->sub_ctx)->to.p = (uchar *) a1;
            ((snx_sub_ctx_t *) r->sub_ctx)->to.n = strlen(a1);
            ((snx_sub_ctx_t *) r->sub_ctx)->once =
                a2 == NULL
                || strcmp(snx_conf_arg(r->loc->conf,
                                       "sub_filter_once"),
                          "off") != 0;
        }
    }
    return (snx_sub_ctx_t *) r->sub_ctx;
}

int
snx_f_sub_head(snx_http_req_t *r)
{
    if (snx_sub_ctx(r) == NULL) {
        return SNX_OK;
    }
    /* the rewritten length is unpredictable -> chunked */
    r->chunked_out = 1;
    r->out.cl_n = -1;
    return SNX_OK;
}

static int
snx_ci_match(uchar *p, uchar *pat, size_t n)
{
    size_t  i;
    for (i = 0; i < n; i++) {
        uchar a = p[i], b = pat[i];
        if (a >= 'A' && a <= 'Z') {
            a += 32;
        }
        if (b >= 'A' && b <= 'Z') {
            b += 32;
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

snx_iobuf_t *
snx_f_sub_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_sub_ctx_t  *ctx = snx_sub_ctx(r);
    snx_iobuf_t    *b, *next, *out = NULL, *tail = NULL;
    size_t          fn;

    if (ctx == NULL) {
        return in;
    }
    fn = ctx->from.n;

    for (b = in; b; b = next) {
        next = b->next;

        if (!(b->flags & SNX_IOB_MEM) || (ctx->once && ctx->done)) {
            snx_iob_append(&out, &tail, b);
            continue;
        }

        {
            uchar       *s = b->head, *e = b->tail;
            snx_iobuf_t *nb;
            size_t       ncap;

            ncap = snx_iob_len(b) + ctx->tn + ctx->to.n + fn;
            nb = snx_acnew(r->arena, snx_iobuf_t);
            nb->base = snx_arena_alloc(r->arena, ncap);
            nb->head = nb->base;
            nb->cap = ncap;
            nb->flags = SNX_IOB_MEM | (b->flags & SNX_IOB_LAST);

            /* prepend the held-over tail */
            if (ctx->tn) {
                memcpy(nb->head, ctx->tail, ctx->tn);
            }

            {
                uchar *w = nb->head + ctx->tn;
                uchar *p = s;

                while (p < e) {
                    size_t  left = e - p;

                    if (left < fn) {
                        /* stash the partial tail for the next buf */
                        ctx->tn = left;
                        memcpy(ctx->tail, p, left);
                        p = e;
                        break;
                    }
                    if (snx_ci_match(p, ctx->from.p, fn)) {
                        w = snx_cpymem(w, ctx->to.p, ctx->to.n);
                        p += fn;
                        ctx->done = 1;
                        if (ctx->once) {
                            w = snx_cpymem(w, p, e - p);
                            p = e;
                        }
                        continue;
                    }
                    *w++ = *p++;
                }
                nb->tail = w;
            }

            if (b->flags & SNX_IOB_LAST && ctx->tn) {
                /* flush the held tail at stream end */
                nb->tail = snx_cpymem(nb->tail, ctx->tail, ctx->tn);
                ctx->tn = 0;
            }
            snx_iob_append(&out, &tail, nb);
        }
    }
    return out;
}
