#include <snx.h>

/*
 * gzip output filter + gzip_static.  The filter deflates memory
 * buffers through zlib when the client accepts gzip and the content
 * type qualifies; gzip_static prefers a pre-compressed .gz sibling.
 */

typedef struct {
    z_stream  zs;
    int       init;
    int       finished;
} snx_gz_ctx_t;

static int
snx_gzip_ok_type(snx_http_req_t *r)
{
    /* gzip_types token list, or */ static const snx_str_t any =
        { (uchar *) "text/html", 9 };

    if (snx_cfg.gzip_types.p == NULL) {
        /* mime default: html only */
        if (r->out.ctype == NULL) {
            return 0;
        }
        return r->out.ctype->n >= any.n
            && snx_ncmp(r->out.ctype->p, any.p, any.n) == 0;
    }

    if (r->out.ctype == NULL) {
        return 0;
    }
    {
        uchar *s = snx_cfg.gzip_types.p;
        uchar *e = s + snx_cfg.gzip_types.n;
        while (s < e) {
            while (s < e && *s == ' ') {
                s++;
            }
            {
                uchar *te = s;
                while (te < e && *te != ' ') {
                    te++;
                }
                if (te - s == (ptrdiff_t) r->out.ctype->n
                    && memcmp(s, r->out.ctype->p, te - s) == 0)
                {
                    return 1;
                }
                s = te;
            }
        }
    }
    return 0;
}

static int
snx_client_gzip(snx_http_req_t *r)
{
    return r->in.ae && r->in.ae->n >= 4
        && memmem(r->in.ae->p, r->in.ae->n, "gzip", 4) != NULL;
}

static snx_gz_ctx_t *
snx_gz_ctx(snx_http_req_t *r)
{
    snx_gz_ctx_t *g;

    if (r->gz_ctx) {
        return (snx_gz_ctx_t *) r->gz_ctx;
    }
    if (!snx_cfg.gzip || !snx_client_gzip(r)
        || !snx_gzip_ok_type(r)
        || (snx_cfg.gzip_min_len > 0
            && r->out.cl_n >= 0 && r->out.cl_n < snx_cfg.gzip_min_len))
    {
        return NULL;
    }
    g = snx_acnew(r->arena, snx_gz_ctx_t);
    r->gz_ctx = g;
    return g;
}

int
snx_f_gzip_head(snx_http_req_t *r)
{
    snx_gz_ctx_t *g = snx_gz_ctx(r);
    snx_str_t    *v;

    if (g == NULL) {
        return SNX_OK;
    }

    if (deflateInit2(&g->zs, snx_cfg.gzip_level, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        r->gz_ctx = NULL;
        return SNX_OK;
    }
    g->init = 1;

    v = snx_anew(r->arena, snx_str_t);
    snx_str_set(v, "gzip");
    snx_add_hdr(r, "Content-Encoding", v);
    if (snx_cfg.gzip_vary) {
        v = snx_anew(r->arena, snx_str_t);
        snx_str_set(v, "Accept-Encoding");
        snx_add_hdr(r, "Vary", v);
    }

    r->chunked_out = 1;
    r->out.cl_n = -1;
    return SNX_OK;
}

snx_iobuf_t *
snx_f_gzip_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_gz_ctx_t *g = snx_gz_ctx(r);
    snx_iobuf_t  *b, *next, *out = NULL, *tail = NULL;

    if (g == NULL || !g->init) {
        return in;
    }

    for (b = in; b; b = next) {
        next = b->next;
        if (!(b->flags & SNX_IOB_MEM)) {
            snx_iob_append(&out, &tail, b);
            continue;
        }

        {
            uchar      *cbuf = snx_arena_alloc(r->arena,
                                               snx_iob_len(b) + 512);
            snx_iobuf_t *cb = snx_acnew(r->arena, snx_iobuf_t);
            int          last = (b->flags & SNX_IOB_LAST) != 0;

            g->zs.next_in = b->head;
            g->zs.avail_in = (uInt) snx_iob_len(b);
            g->zs.next_out = cbuf;
            g->zs.avail_out = (uInt) (snx_iob_len(b) + 512);

            (void) deflate(&g->zs,
                           last && !g->finished ? Z_FINISH
                                                : Z_NO_FLUSH);
            if (last) {
                g->finished = 1;
            }

            cb->base = cbuf;
            cb->head = cbuf;
            cb->tail = cbuf + (snx_iob_len(b) + 512) - g->zs.avail_out;
            cb->cap = snx_iob_len(b) + 512;
            cb->flags = SNX_IOB_MEM | (b->flags & SNX_IOB_LAST);
            snx_iob_append(&out, &tail, cb);
        }
    }

    /* empty LAST buf must still emit the gzip trailer */
    if (out == NULL || (out->flags & SNX_IOB_LAST) == 0) {
        for (b = out, tail = NULL; b; b = b->next) {
            tail = b;
        }
        if (tail && (tail->flags & SNX_IOB_LAST)) {
            uchar      *cbuf = snx_arena_alloc(r->arena, 64);
            snx_iobuf_t *cb = snx_acnew(r->arena, snx_iobuf_t);
            g->zs.next_in = NULL;
            g->zs.avail_in = 0;
            g->zs.next_out = cbuf;
            g->zs.avail_out = 64;
            if (!g->finished) {
                (void) deflate(&g->zs, Z_FINISH);
                g->finished = 1;
            }
            cb->base = cbuf;
            cb->head = cbuf;
            cb->tail = cbuf + (64 - g->zs.avail_out);
            cb->flags = SNX_IOB_MEM;
            if (cb->tail > cb->head) {
                snx_iob_append(&out, &tail, cb);
            }
        }
    }
    return out;
}

/* gzip_static: if a <file>.gz sibling exists serve it with
   Content-Encoding: gzip; 1 = on (gzip clients only), 2 = always
   (any client — the gunzip filter inflates for non-accepting ones) */
int
snx_gzip_static_ok(snx_http_req_t *r)
{
    if (snx_cfg.gzip_static == 2) {
        return 1;
    }
    return snx_cfg.gzip_static && snx_client_gzip(r);
}

/* does any enabled body stage need memory bufs? */
int
snx_body_needs_mem(snx_http_req_t *r)
{
    if (r->loc == NULL) {
        return 0;
    }
    if (r->loc->charset.p || r->loc->src_charset.p || r->loc->ssi_on
        || r->loc->slice_size)
    {
        return 1;
    }
    if (r->loc->conf
        && (snx_conf_find(r->loc->conf, "sub_filter")
            || snx_conf_find(r->loc->conf, "gunzip")
            || snx_conf_find(r->loc->conf, "gzip")
            || snx_conf_find(r->loc->conf, "image_filter")
            || snx_conf_find(r->loc->conf, "xslt_stylesheet")))
    {
        return 1;
    }
    if (snx_cfg.gzip && snx_client_gzip(r)) {
        return 1;
    }
    return 0;
}
