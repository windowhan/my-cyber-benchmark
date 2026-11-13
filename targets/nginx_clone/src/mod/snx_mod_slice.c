#include <snx.h>

/*
 * slice filter: splits a large response into fixed-size slices so
 * range subrequests can be served independently.
 */

typedef struct {
    soff_t   slice_size;
    soff_t   sent;
    soff_t   total;
} snx_slice_ctx_t;

int
snx_f_slice_head(snx_http_req_t *r)
{
    snx_slice_ctx_t  *ctx;
    snx_str_t         sv;

    if (r->loc == NULL || r->loc->slice_size <= 0) {
        return SNX_OK;
    }

    ctx = snx_acnew(r->arena, snx_slice_ctx_t);
    ctx->slice_size = r->loc->slice_size;
    ctx->total = r->out.cl_n;

    /* $slice_range is produced from the range argument */
    sv.p = snx_arena_alloc(r->arena, 64);
    sv.n = snx_fmt(sv.p, sv.p + 64, "bytes=%f-%f",
                   ctx->sent, ctx->sent + ctx->slice_size - 1) - sv.p;

    {
        snx_str_t  name = { (uchar *) "slice_range", 11 };
        snx_str_t  v = sv;
        int        idx = snx_var_find(r, &name);
        if (idx < 0) {
            if (r->vars.n == r->vars.cap) {
                int        ncap = r->vars.cap ? r->vars.cap * 2 : 8;
                snx_var_t *vv = snx_arena_alloc(r->arena,
                                                ncap * sizeof(snx_var_t));
                memcpy(vv, r->vars.v, r->vars.n * sizeof(snx_var_t));
                r->vars.v = vv;
                r->vars.cap = ncap;
            }
            idx = r->vars.n++;
            r->vars.v[idx].name = name;
        }
        snx_var_set(r, idx, &v);
    }

    r->mp4_ctx = ctx;   /* shared per-request scratch slot */
    return SNX_OK;
}

snx_iobuf_t *
snx_f_slice_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_slice_ctx_t  *ctx = r->mp4_ctx;
    snx_iobuf_t      *b, *next, *head = NULL, *tail = NULL, *nb;
    soff_t            win_end;

    if (ctx == NULL || ctx->slice_size <= 0 || in == NULL) {
        return in;
    }

    win_end = ctx->sent + ctx->slice_size;

    for (b = in; b; b = next) {
        soff_t  blen;

        next = b->next;

        if (b->flags & SNX_IOB_FILE) {
            blen = b->flen;
        } else {
            blen = snx_iob_len(b);
        }

        if (ctx->sent + blen <= win_end) {
            ctx->sent += blen;
            snx_iob_append(&head, &tail, b);
            continue;
        }

        /* buffer crosses the slice boundary: emit only the leading
           portion that belongs to this slice */
        {
            soff_t  keep = ctx->slice_size;

            if (b->flags & SNX_IOB_FILE) {
                nb = snx_acnew(r->arena, snx_iobuf_t);
                *nb = *b;
                nb->flen = keep;
            } else {
                nb = snx_iob_new(r->arena, (size_t) keep);
                memcpy(nb->head, b->head, (size_t) keep);
                nb->tail = nb->head + keep;
            }
            nb->flags |= SNX_IOB_LAST;
            ctx->sent += keep;
            snx_iob_append(&head, &tail, nb);
        }
    }

    return head;
}
