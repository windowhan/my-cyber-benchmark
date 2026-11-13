#include <snx.h>

/*
 * SPDY/3 framing: control frames and zlib-inflated name/value blocks.
 * Compile-gated on a `listen ... spdy` port.
 */

typedef struct {
    snx_conn_t  *c;
    z_stream     z;
    int          z_init;
    uchar        inbuf[16384];
    size_t       nin;
} snx_spdy_conn_t;

static int
snx_spdy_inflate(snx_spdy_conn_t *sp, uchar *src, size_t n, uchar *dst,
                 size_t cap)
{
    int  rc;

    if (!sp->z_init) {
        memset(&sp->z, 0, sizeof(sp->z));
        if (inflateInit(&sp->z) != Z_OK) {
            return SNX_ERROR;
        }
        sp->z_init = 1;
    }

    sp->z.next_in = src;
    sp->z.avail_in = n;
    sp->z.next_out = dst;
    sp->z.avail_out = cap;

    rc = inflate(&sp->z, Z_SYNC_FLUSH);

    return rc == Z_OK || rc == Z_STREAM_END || rc == Z_BUF_ERROR
           ? (int) (cap - sp->z.avail_out) : SNX_ERROR;
}

static int
snx_spdy_syn_stream(snx_spdy_conn_t *sp, uchar *p, size_t n)
{
    uint32_t  sid;
    uchar     raw[8192];
    int       got;

    if (n < 10) {
        return SNX_ERROR;
    }
    sid = ((p[0] & 0x7f) << 24) | (p[1] << 16) | (p[2] << 8) | p[3];

    /* name/value block is zlib-compressed; inflated onto scratch */
    got = snx_spdy_inflate(sp, p + 10, n - 10, raw, sizeof(raw));
    if (got < 0) {
        return SNX_ERROR;
    }

    /* entries: {name_len32, name, val_len32, val}* */
    {
        uchar  *q = raw, *e = raw + got;
        uint32_t nvals = (q + 4 <= e)
            ? ((uint32_t) q[0] << 24) | (q[1] << 16) | (q[2] << 8) | q[3]
            : 0;
        q += 4;

        while (nvals-- && q + 4 <= e) {
            uint32_t  nl = ((uint32_t) q[0] << 24) | (q[1] << 16)
                         | (q[2] << 8) | q[3];
            uchar    *nv;
            q += 4;
            nv = snx_arena_alloc(sp->c->arena, nl);
            memcpy(nv, q, nl);
            nv[nl] = '\0';
            q += nl;
            if (q + 4 > e) {
                break;
            }
            {
                uint32_t vl = ((uint32_t) q[0] << 24) | (q[1] << 16)
                            | (q[2] << 8) | q[3];
                q += 4 + vl;
            }
        }
    }

    (void) sid;
    return SNX_OK;
}

static void
snx_spdy_ev(snx_ev_t *ev)
{
    snx_spdy_conn(ev->data);
}

void
snx_spdy_conn(snx_conn_t *c)
{
    snx_spdy_conn_t  *sp;
    ssize_t           n;
    uchar            *p, *end;

    if (c->arena == NULL) {
        c->arena = snx_arena_new(16384);
    }
    if (c->data == NULL) {
        sp = snx_acnew(c->arena, snx_spdy_conn_t);
        sp->c = c;
        c->data = sp;
        c->rev.fn = snx_spdy_ev;
    } else {
        sp = c->data;
    }

    n = recv(c->fd, sp->inbuf + sp->nin,
             sizeof(sp->inbuf) - sp->nin, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        goto out;
    }
    if (n <= 0) {
        snx_conn_free(c);
        return;
    }
    sp->nin += n;

    p = sp->inbuf;
    end = sp->inbuf + sp->nin;

    while (p + 8 <= end) {
        uint32_t  len = (p[5] << 16) | (p[6] << 8) | p[7];
        int       ctrl = p[0] & 0x80;
        uchar    *payload = p + 8;
        uint16_t  type;

        if (payload + len > end) {
            break;
        }

        if (ctrl) {
            type = (p[2] << 8) | p[3];
            if (type == 1) {          /* SYN_STREAM */
                (void) snx_spdy_syn_stream(sp, payload, len);
            }
        }

        p = payload + len;
    }

    if (p > sp->inbuf) {
        memmove(sp->inbuf, p, end - p);
        sp->nin = end - p;
    }

out:
    snx_ev_add(&c->rev, SNX_EVF_READ);
}
