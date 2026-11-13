#include <snx.h>
#include <zlib.h>

/*
 * gunzip filter: when a client did not send Accept-Encoding: gzip but
 * the selected response is gzip-coded (gzip_static sibling or an
 * upstream that already compressed), inflate the body on the way out.
 */

typedef struct {
    int       init;
    int       hdr_done;
    z_stream  zs;
} snx_gunzip_ctx_t;

static int
snx_gunzip_on(snx_http_req_t *r)
{
    const char  *g;
    snx_hdr_t   *h;
    int          ce_gzip = 0;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return 0;
    }
    g = snx_conf_arg(r->loc->conf, "gunzip");
    if (g == NULL || strcmp(g, "on") != 0) {
        return 0;
    }
    /* only when the client cannot take gzip itself */
    if (r->in.ae
        && memmem(r->in.ae->p, r->in.ae->n, "gzip", 4) != NULL)
    {
        return 0;
    }
    for (h = r->out.hdrs; h; h = h->next) {
        if (h->k.n == 16
            && snx_ncasecmp(h->k.p, (uchar *) "Content-Encoding", 16)
               == 0
            && h->v.n == 4
            && snx_ncasecmp(h->v.p, (uchar *) "gzip", 4) == 0)
        {
            ce_gzip = 1;
            break;
        }
    }
    return ce_gzip;
}

int
snx_f_gunzip_head(snx_http_req_t *r)
{
    snx_gunzip_ctx_t *g;
    snx_hdr_t       **hp, *h;

    if (!snx_gunzip_on(r)) {
        return SNX_OK;
    }
    g = snx_acnew(r->arena, snx_gunzip_ctx_t);
    memset(&g->zs, 0, sizeof(g->zs));
    if (inflateInit2(&g->zs, -15) != Z_OK) {
        return SNX_OK;
    }
    g->init = 1;
    r->gunzip_ctx = g;

    /* Content-Encoding: gzip no longer describes the body */
    for (hp = &r->out.hdrs; *hp; hp = &(*hp)->next) {
        h = *hp;
        if (h->k.n == 16
            && snx_ncasecmp(h->k.p, (uchar *) "Content-Encoding", 16)
               == 0)
        {
            *hp = h->next;
            break;
        }
    }
    r->chunked_out = 1;
    r->out.cl_n = -1;
    return SNX_OK;
}

/* skip the gzip member header; returns bytes of deflate payload
   consumed from *pp..end via *pp advance, or -1 when not gzip */
static long
snx_gz_hdr_skip(uchar **pp, uchar *end)
{
    uchar  *p = *pp;
    uchar   flg;

    if (end - p < 10) {
        return -1;
    }
    if (p[0] != 0x1f || p[1] != 0x8b || p[2] != 8) {
        return -1;
    }
    flg = p[3];
    p += 10;

    if (flg & 0x04) {                       /* FEXTRA */
        unsigned xl;
        if (end - p < 2) {
            return -1;
        }
        xl = p[0] | (p[1] << 8);
        p += 2 + xl;
    }
    if (flg & 0x08) {                       /* FNAME: zero-terminated */
        while (*p != 0) {
            p++;
        }
        p++;
    }
    if (flg & 0x10) {                       /* FCOMMENT */
        while (*p != 0) {
            p++;
        }
        p++;
    }
    if (flg & 0x02) {                       /* FHCRC */
        p += 2;
    }
    *pp = p;
    return (long) (end - p);
}

snx_iobuf_t *
snx_f_gunzip_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_gunzip_ctx_t *g = r->gunzip_ctx;
    snx_iobuf_t      *b, *next, *out = NULL, *tail = NULL;

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
            uchar  *p = b->head, *end = b->tail;
            int     last = (b->flags & SNX_IOB_LAST) != 0;

            if (!g->hdr_done) {
                if (snx_gz_hdr_skip(&p, end) < 0) {
                    /* not gzip after all: pass the original bytes */
                    b->next = NULL;
                    snx_iob_append(&out, &tail, b);
                    continue;
                }
                g->hdr_done = 1;
            }
            /* strip the 8-byte crc/isize trailer from the last buf */
            if (last && end - p >= 8) {
                end -= 8;
            }
            {
                uchar           obuf[8192];
                int             zrc = Z_OK;
                snx_iobuf_t    *m;

                g->zs.next_in = p;
                g->zs.avail_in = (uInt) (end - p);
                while (g->zs.avail_in > 0 && zrc == Z_OK) {
                    g->zs.next_out = obuf;
                    g->zs.avail_out = sizeof(obuf);
                    zrc = inflate(&g->zs, Z_NO_FLUSH);
                    {
                        size_t  have = sizeof(obuf) - g->zs.avail_out;
                        if (have) {
                            m = snx_acnew(r->arena, snx_iobuf_t);
                            m->base = snx_arena_alloc(r->arena, have);
                            memcpy(m->base, obuf, have);
                            m->head = m->base;
                            m->tail = m->base + have;
                            m->cap = have;
                            m->flags = SNX_IOB_MEM;
                            snx_iob_append(&out, &tail, m);
                        }
                    }
                }
            }
            if (last) {
                snx_iobuf_t *m = snx_acnew(r->arena, snx_iobuf_t);
                m->flags = SNX_IOB_MEM | SNX_IOB_LAST;
                inflateEnd(&g->zs);
                g->init = 0;
                snx_iob_append(&out, &tail, m);
            }
        }
    }
    return out ? out : in;
}
