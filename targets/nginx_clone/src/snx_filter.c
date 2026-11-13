#include <snx.h>

/*
 * Output pipeline: an ordered stage table.  Header stages run in order
 * before the status line is emitted; body stages each transform the
 * outgoing iobuf list.
 */

static snx_iobuf_t *snx_f_tomem_body(snx_http_req_t *r, snx_iobuf_t *in);

static const snx_stage_t snx_pipeline[] = {
    { NULL,               snx_f_tomem_body },
    { snx_f_charset_head, snx_f_charset_body },
    { snx_f_ssi_head,     snx_f_ssi_body },
    { snx_f_slice_head,   snx_f_slice_body },
    { snx_f_range_head,   snx_f_range_body },
    { snx_f_sub_head,     snx_f_sub_body },
    { snx_f_gunzip_head,  snx_f_gunzip_body },
    { snx_f_image_head,   snx_f_image_body },
    { snx_f_xslt_head,    snx_f_xslt_body },
    { snx_f_gzip_head,    snx_f_gzip_body },
    { NULL, NULL }
};

int
snx_http_send_head(snx_http_req_t *r)
{
    unsigned  i;

    for (i = 0; snx_pipeline[i].head || snx_pipeline[i].body; i++) {
        if (snx_pipeline[i].head
            && snx_pipeline[i].head(r) != SNX_OK)
        {
            return SNX_ERROR;
        }
    }
    return snx_f_send_head(r);
}

int
snx_http_body_stage(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_iobuf_t  *b = in;
    unsigned     i;

    for (i = 0; snx_pipeline[i].head || snx_pipeline[i].body; i++) {
        if (snx_pipeline[i].body == NULL) {
            continue;
        }
        b = snx_pipeline[i].body(r, b);
        if (b == (snx_iobuf_t *) -1) {
            return SNX_ERROR;
        }
    }
    b = snx_f_send_body(r, b);
    return b == (snx_iobuf_t *) -1 ? SNX_ERROR : SNX_OK;
}

int
snx_http_write(snx_http_req_t *r, snx_iobuf_t *in)
{
    return snx_http_body_stage(r, in);
}

/*
 * When a transforming stage is enabled for the location, file bodies are
 * pulled into memory so the byte-wise stages can inspect them.
 */
static snx_iobuf_t *
snx_f_tomem_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_iobuf_t  *b, *next, *out = NULL, *tail = NULL, *m;
    ssize_t       rd;

    if (!snx_body_needs_mem(r)) {
        return in;
    }

    for (b = in; b; b = next) {
        next = b->next;
        if (!(b->flags & SNX_IOB_FILE)) {
            snx_iob_append(&out, &tail, b);
            continue;
        }
        m = snx_acnew(r->arena, snx_iobuf_t);
        m->base = malloc((size_t) b->flen);
        rd = pread(b->fd, m->base, (size_t) b->flen, b->fpos);
        if (rd > 0) {
            m->flags = SNX_IOB_MEM | (b->flags & SNX_IOB_LAST);
            m->head = m->base;
            m->tail = m->base + rd;
            snx_iob_append(&out, &tail, m);
        }
    }
    return out;
}

/* ================= range stage =================
 * Parses "Range: bytes=a-b,c-d,..." into half-open ranges and emits
 * either a single 206 slice or a multipart/byteranges body. */

typedef struct {
    soff_t      start;
    soff_t      end;
} snx_range_t;

typedef struct {
    snx_range_t *ranges;
    int          nranges;
    soff_t       total;
    soff_t       fsize;
    snx_str_t    boundary;
    snx_iobuf_t *fb;
} snx_range_ctx_t;

int
snx_f_range_head(snx_http_req_t *r)
{
    snx_range_ctx_t  *ctx;
    uchar            *p, *end, *s;
    soff_t            start, endoff;
    int               cap;

    if (r->in.range == NULL || r->in.range->n < 6
        || snx_ncmp(r->in.range->p, (uchar *) "bytes=", 6) != 0
        || r->out.status != SNX_HTTP_OK || r->out.cl_n <= 0)
    {
        return SNX_OK;
    }

    /* If-Range: partial content only when the validator still
       matches; a stale validator falls back to the full body */
    if (r->in.ifr && r->etag.n
        && (r->in.ifr->n != r->etag.n
            || memcmp(r->in.ifr->p, r->etag.p, r->etag.n) != 0))
    {
        return SNX_OK;
    }

    ctx = snx_acnew(r->arena, snx_range_ctx_t);
    ctx->fsize = r->out.cl_n;
    r->range_ctx = ctx;

    cap = 4;
    ctx->ranges = snx_arena_alloc(r->arena, cap * sizeof(snx_range_t));

    p = r->in.range->p + 6;
    end = r->in.range->p + r->in.range->n;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == ',')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        s = p;
        while (p < end && ((*p >= '0' && *p <= '9') || *p == '-')) {
            p++;
        }

        if (*s == '-') {
            soff_t  suffix = snx_atooff(s + 1, p - s - 1);
            if (suffix == -1) {
                return SNX_HTTP_RANGE_BAD;
            }
            start = ctx->fsize - suffix;
            endoff = ctx->fsize;
        } else {
            uchar  *dash = snx_strlchr(s, p, '-');

            if (dash == NULL) {
                return SNX_HTTP_RANGE_BAD;
            }
            start = snx_atooff(s, dash - s);
            if (dash + 1 == p) {
                endoff = ctx->fsize;
            } else {
                endoff = snx_atooff(dash + 1, p - dash - 1) + 1;
            }
        }

        if (start >= ctx->fsize) {
            continue;
        }
        if (ctx->nranges == cap) {
            snx_range_t *nr;
            cap *= 2;
            nr = snx_arena_alloc(r->arena, cap * sizeof(snx_range_t));
            memcpy(nr, ctx->ranges, ctx->nranges * sizeof(snx_range_t));
            ctx->ranges = nr;
        }

        if (endoff > ctx->fsize) {
            endoff = ctx->fsize;
        }

        if (snx_cfg.max_ranges > 0
            && ctx->nranges >= (int) snx_cfg.max_ranges)
        {
            break;
        }

        ctx->ranges[ctx->nranges].start = start;
        ctx->ranges[ctx->nranges].end = endoff;
        ctx->nranges++;

        ctx->total += endoff - start;
    }

    if (ctx->nranges == 0) {
        r->out.status = SNX_HTTP_RANGE_BAD;
        r->out.cl_n = 0;
        return SNX_OK;
    }

    if (ctx->nranges == 1) {
        snx_range_t  *rg = &ctx->ranges[0];
        snx_str_t    *cr;

        cr = snx_anew(r->arena, snx_str_t);
        cr->p = snx_arena_alloc(r->arena, 64);
        cr->n = snx_fmt(cr->p, cr->p + 64, "bytes %f-%f/%f",
                        rg->start, rg->end - 1, ctx->fsize) - cr->p;

        r->out.crange = cr;
        r->out.status = SNX_HTTP_PARTIAL;
        r->out.cl_n = rg->end - rg->start;
        return SNX_OK;
    }

    /* multipart */
    ctx->boundary.p = snx_arena_alloc(r->arena, 40);
    ctx->boundary.n = snx_fmt(ctx->boundary.p, ctx->boundary.p + 40,
                              "%x%x", (unsigned) (uintptr_t) r,
                              (unsigned) r->t0) - ctx->boundary.p;

    {
        soff_t  len = ctx->total;
        int     i;
        for (i = 0; i < ctx->nranges; i++) {
            len += 160;
        }
        r->out.cl_n = len;
    }

    {
        snx_str_t *ct = snx_anew(r->arena, snx_str_t);
        ct->p = snx_arena_alloc(r->arena, 96);
        ct->n = snx_fmt(ct->p, ct->p + 96,
                        "multipart/byteranges; boundary=%S",
                        &ctx->boundary) - ct->p;
        r->out.ctype = ct;
    }

    r->out.status = SNX_HTTP_PARTIAL;
    return SNX_OK;
}

snx_iobuf_t *
snx_f_range_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_range_ctx_t  *ctx = r->range_ctx;
    snx_iobuf_t      *out = NULL, *tail = NULL, *cl;
    int               i;

    if (ctx == NULL || ctx->nranges == 0 || in == NULL) {
        return in;
    }

    ctx->fb = in;

    if (ctx->nranges == 1) {
        snx_range_t  *rg = &ctx->ranges[0];
        snx_iobuf_t  *b = in;

        if (b->flags & SNX_IOB_FILE) {
            b->fpos += rg->start;
            if (b->flen > rg->end - rg->start) {
                b->flen = rg->end - rg->start;
            }
        } else {
            b->head += rg->start;
            if (b->tail > b->head + (rg->end - rg->start)) {
                b->tail = b->head + (rg->end - rg->start);
            }
        }
        return in;
    }

    for (i = 0; i < ctx->nranges; i++) {
        snx_range_t  *rg = &ctx->ranges[i];

        cl = snx_iob_new(r->arena, 192);
        cl->tail = snx_fmt(cl->head, cl->head + cl->cap,
                           "--%S\r\nContent-Type: application/octet-stream\r\n"
                           "Content-Range: bytes %f-%f/%f\r\n\r\n",
                           &ctx->boundary, rg->start, rg->end - 1,
                           ctx->fsize);
        cl->flags &= ~SNX_IOB_TMP;
        snx_iob_append(&out, &tail, cl);

        cl = snx_acnew(r->arena, snx_iobuf_t);
        if (in->flags & SNX_IOB_FILE) {
            cl->flags = SNX_IOB_FILE;
            cl->fd = in->fd;
            cl->fpos = in->fpos + rg->start;
            cl->flen = rg->end - rg->start;
        } else {
            cl->flags = SNX_IOB_MEM;
            cl->head = in->head + rg->start;
            cl->tail = cl->head + (rg->end - rg->start);
        }
        snx_iob_append(&out, &tail, cl);
    }

    cl = snx_iob_new(r->arena, 96);
    cl->tail = snx_fmt(cl->head, cl->head + cl->cap,
                       "\r\n--%S--\r\n", &ctx->boundary);
    cl->flags &= ~SNX_IOB_TMP;
    cl->flags |= SNX_IOB_LAST;
    snx_iob_append(&out, &tail, cl);

    return out;
}

/* ================= final send stage ================= */

static const char *snx_status_text[] = {
    "101 Switching Protocols",
    "200 OK", "201 Created", "204 No Content", "206 Partial Content",
    "301 Moved Permanently", "302 Found", "304 Not Modified",
    "400 Bad Request", "401 Unauthorized", "403 Forbidden",
    "404 Not Found", "405 Not Allowed", "409 Conflict",
    "411 Length Required", "413 Request Entity Too Large",
    "414 Request-URI Too Large", "416 Range Not Satisfiable",
    "500 Internal Server Error", "501 Not Implemented",
    "502 Bad Gateway", "503 Service Unavailable"
};

static const int snx_status_code[] = {
    101, 200, 201, 204, 206, 301, 302, 304, 400, 401, 403, 404, 405,
    409, 411, 413, 414, 416, 500, 501, 502, 503
};

int
snx_f_send_head(snx_http_req_t *r)
{
    uchar        *p;
    size_t        len;
    snx_iobuf_t  *b;
    snx_hdr_t    *h;
    const char   *line = "200 OK";
    char          date[64];
    struct tm     tm;
    unsigned      i;
    ssize_t       n;

    if (r->out.header_sent) {
        return SNX_OK;
    }
    r->out.header_sent = 1;

    for (i = 0; i < sizeof(snx_status_code) / sizeof(int); i++) {
        if (snx_status_code[i] == r->out.status) {
            line = snx_status_text[i];
            break;
        }
    }

    /* expires directive -> Expires + Cache-Control headers */
    if (r->loc && r->loc->conf) {
        const char *ex = snx_conf_arg(r->loc->conf, "expires");
        if (ex) {
            time_t     at;
            struct tm  xtm;
            char       xb[64];
            snx_str_t *v;

            if (strcmp(ex, "off") == 0) {
                at = 0;
            } else if (strcmp(ex, "epoch") == 0) {
                at = 0;
            } else if (strcmp(ex, "max") == 0) {
                at = r->t0 + 10L * 365 * 24 * 3600;
            } else {
                at = r->t0 + snx_parse_time(ex);
            }
            gmtime_r(&at, &xtm);
            strftime(xb, sizeof(xb), "%a, %d %b %Y %H:%M:%S GMT", &xtm);
            v = snx_anew(r->arena, snx_str_t);
            v->p = (uchar *) xb;
            v->n = strlen(xb);
            {
                uchar *dup = snx_arena_alloc(r->arena, v->n);
                memcpy(dup, xb, v->n);
                v->p = dup;
            }
            snx_add_hdr(r, "Expires", v);

            v = snx_anew(r->arena, snx_str_t);
            v->p = snx_arena_alloc(r->arena, 48);
            v->n = (size_t) (snx_fmt(v->p, v->p + 48,
                                     at > r->t0 ? "max-age=%ld" : "no-cache",
                                     at - r->t0) - v->p);
            snx_add_hdr(r, "Cache-Control", v);
        }
        /* add_header lines append verbatim */
        {
            snx_node_t *c = r->loc->conf;
            int         i;
            for (i = 0; i < c->nkids; i++) {
                snx_node_t *d = c->kids[i];
                if (strcmp(d->name, "add_header") == 0 && d->nargs >= 2)
                {
                    snx_str_t *v = snx_anew(r->arena, snx_str_t);
                    const char *a1 = snx_node_arg(d, 1);
                    uchar *dv = snx_arena_alloc(r->arena, strlen(a1));
                    memcpy(dv, a1, strlen(a1));
                    v->p = dv;
                    v->n = strlen(a1);
                    snx_add_hdr(r, snx_node_arg(d, 0), v);
                }
            }
        }
    }

    gmtime_r(&r->t0, &tm);
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tm);

    len = 512;
    for (h = r->out.hdrs; h; h = h->next) {
        len += h->k.n + h->v.n + 4;
    }

    b = snx_iob_new(r->arena, len);
    p = b->head;

    p = snx_fmt(p, b->base + b->cap, "HTTP/1.1 %s\r\n", line);
    if (snx_cfg.server_tokens) {
        p = snx_fmt(p, b->base + b->cap, "Server: %s\r\n", SNX_VER);
    } else {
        p = snx_fmt(p, b->base + b->cap, "Server: snx\r\n");
    }
    p = snx_fmt(p, b->base + b->cap, "Date: %s\r\n", date);

    if (r->mtime) {
        char       mb[64];
        struct tm  mtm;
        gmtime_r(&r->mtime, &mtm);
        strftime(mb, sizeof(mb), "%a, %d %b %Y %H:%M:%S GMT", &mtm);
        p = snx_fmt(p, b->base + b->cap, "Last-Modified: %s\r\n", mb);
    }

    if (r->chunked_out && snx_cfg.chunked_te) {
        p = snx_fmt(p, b->base + b->cap,
                    "Transfer-Encoding: chunked\r\n");
    } else if (r->out.cl_n != -1) {
        p = snx_fmt(p, b->base + b->cap, "Content-Length: %f\r\n",
                    r->out.cl_n);
    }
    if (r->out.ctype) {
        p = snx_fmt(p, b->base + b->cap, "Content-Type: %S\r\n",
                    r->out.ctype);
    }
    if (r->out.crange) {
        p = snx_fmt(p, b->base + b->cap, "Content-Range: %S\r\n",
                    r->out.crange);
    }
    if (r->out.cl_n > 0 && r->out.status == SNX_HTTP_OK
        && !r->chunked_out)
    {
        p = snx_fmt(p, b->base + b->cap, "Accept-Ranges: bytes\r\n");
    }
    if (r->keepalive && snx_cfg.keepalive_timeout > 0) {
        p = snx_fmt(p, b->base + b->cap, "Keep-Alive: timeout=%d\r\n",
                    snx_cfg.keepalive_timeout);
    }

    for (h = r->out.hdrs; h; h = h->next) {
        p = snx_cpymem(p, h->k.p, h->k.n);
        p = snx_cpymem(p, (uchar *) ": ", 2);
        p = snx_cpymem(p, h->v.p, h->v.n);
        p = snx_cpymem(p, (uchar *) "\r\n", 2);
    }

    p = snx_fmt(p, b->base + b->cap, "Connection: %s\r\n\r\n",
                r->keepalive ? "keep-alive" : "close");

    b->tail = p;

    if (r->method_id == SNX_M_HEAD) {
        r->header_only = 1;
    }

    n = snx_conn_send(r->c, b->head, snx_iob_len(b));
    if (n > 0) {
        b->head += n;
    }

    return SNX_OK;
}

static int
snx_raw_send(snx_http_req_t *r, const void *data, size_t n)
{
    ssize_t  s = snx_conn_send(r->c, data, n);
    if (s > 0) {
        r->bytes_sent += s;
    }
    return (int) s;
}

/* final chunk + add_trailer lines + blank line */
static void
snx_chunked_term(snx_http_req_t *r)
{
    snx_node_t *c;
    char       *tb, *tp, *te;
    int         i, n = 0;

    (void) snx_raw_send(r, "0\r\n", 3);
    c = r->loc ? r->loc->conf : NULL;
    if (c == NULL) {
        (void) snx_raw_send(r, "\r\n", 2);
        return;
    }
    for (i = 0; i < c->nkids; i++) {
        snx_node_t *d = c->kids[i];
        if (strcmp(d->name, "add_trailer") == 0 && d->nargs >= 2) {
            n += strlen(snx_node_arg(d, 0)) + strlen(snx_node_arg(d, 1)) + 4;
        }
    }
    if (n == 0) {
        (void) snx_raw_send(r, "\r\n", 2);
        return;
    }
    tb = snx_arena_alloc(r->arena, (size_t) n + 2);
    tp = tb;
    te = tb + n + 2;
    for (i = 0; i < c->nkids; i++) {
        snx_node_t *d = c->kids[i];
        if (strcmp(d->name, "add_trailer") == 0 && d->nargs >= 2) {
            tp = snx_fmt(tp, te, "%s: %s\r\n",
                         snx_node_arg(d, 0), snx_node_arg(d, 1));
        }
    }
    *tp++ = '\r'; *tp++ = '\n';
    (void) snx_raw_send(r, tb, (size_t) (tp - tb));
}

snx_iobuf_t *
snx_f_send_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_iobuf_t  *b;
    ssize_t       n;
    char          drain[65536];
    soff_t        want;
    int           chunked = r->chunked_out && snx_cfg.chunked_te
                          && !r->header_only;
    soff_t        rate = (r->loc && r->loc->limit_rate)
                         ? r->loc->limit_rate : snx_cfg.limit_rate;

    for (b = in; b; b = b->next) {
        if (r->header_only) {
            continue;
        }

        /* limit_rate: naive per-buffer pacing */
        if (rate > 0 && r->bytes_sent > rate) {
            struct timespec now;
            long   elapsed_ms, expect_ms, sleep_ms;
            clock_gettime(CLOCK_MONOTONIC, &now);
            elapsed_ms = (now.tv_sec - r->tstart.tv_sec) * 1000
                + (now.tv_nsec - r->tstart.tv_nsec) / 1000000;
            expect_ms = r->bytes_sent * 1000 / rate;
            sleep_ms = expect_ms - elapsed_ms;
            if (sleep_ms > 0 && sleep_ms < 60000) {
                struct timespec ts = { sleep_ms / 1000,
                                       (sleep_ms % 1000) * 1000000L };
                nanosleep(&ts, NULL);
            }
        }

        if (b->flags & SNX_IOB_FILE) {
            want = b->flen;
            while (want > 0) {
                ssize_t  rd = pread(b->fd, drain,
                                    want > (soff_t) sizeof(drain)
                                    ? sizeof(drain) : (size_t) want,
                                    b->fpos);
                if (rd <= 0) {
                    break;
                }
                b->fpos += rd;
                want -= rd;

                if (chunked) {
                    char  hb[24];
                    int   hn = snprintf(hb, sizeof(hb), "%zx\r\n",
                                        (size_t) rd);
                    (void) snx_raw_send(r, hb, (size_t) hn);
                }
                n = snx_raw_send(r, drain, (size_t) rd);
                if (chunked) {
                    (void) snx_raw_send(r, "\r\n", 2);
                }
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    return (snx_iobuf_t *) -1;
                }
            }
            if (chunked && (b->flags & SNX_IOB_LAST)) {
                snx_chunked_term(r);
            }
            continue;
        }

        if (chunked && b->tail > b->head) {
            char  hb[24];
            int   hn = snprintf(hb, sizeof(hb), "%zx\r\n",
                                snx_iob_len(b));
            (void) snx_raw_send(r, hb, (size_t) hn);
        }
        while (b->head < b->tail) {
            n = snx_raw_send(r, b->head, snx_iob_len(b));
            if (n == 0) {
                n = -1;
            }
            if (n > 0) {
                b->head += n;
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* unsent tail: arm write event; keep remainder */
                r->c->wev.fn = NULL;
                snx_ev_add(&r->c->wev, SNX_EVF_WRITE);
                return in;
            }
            return (snx_iobuf_t *) -1;
        }
        if (chunked) {
            (void) snx_raw_send(r, "\r\n", 2);
        }
        if (chunked && (b->flags & SNX_IOB_LAST)) {
            snx_chunked_term(r);
        }
    }

    return in;
}
