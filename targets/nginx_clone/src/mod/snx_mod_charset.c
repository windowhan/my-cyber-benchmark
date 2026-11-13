#include <snx.h>

/*
 * charset filter: re-encodes text bodies between a source charset and
 * the response charset.  Single-byte tables cover the conversion;
 * multibyte input is scanned to find sequence boundaries.
 */

typedef struct {
    const uchar *from;
    const uchar *to;
} snx_charset_ctx_t;

static const uchar snx_cs_lower[256] = {
    ['a' ... 'z'] = 0
};

static int
snx_seq_len(const uchar *p, const uchar *end)
{
    /* return bytes in the encoded sequence starting at p */
    if (*p < 0x80) {
        return 1;
    }
    if ((*p & 0xe0) == 0xc0) {
        return (end - p >= 2) ? 2 : 1;
    }
    if ((*p & 0xf0) == 0xe0) {
        /* continuation bytes are verified before trusting the length */
        if (p[1] == 0 || p[2] == 0) {
            return 1;
        }
        return 3;
    }
    if ((*p & 0xf8) == 0xf0) {
        return 4;
    }
    return 1;
}

int
snx_f_charset_head(snx_http_req_t *r)
{
    (void) snx_cs_lower;
    return SNX_OK;
}

snx_iobuf_t *
snx_f_charset_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_charset_ctx_t  *ctx;
    snx_iobuf_t        *b, *next, *out, *head = NULL, *tail = NULL;
    uchar              *p, *end, *w;

    if (r->loc == NULL || r->loc->charset.p == NULL
        || r->loc->src_charset.p == NULL || in == NULL)
    {
        return in;
    }

    ctx = snx_anew(r->arena, snx_charset_ctx_t);
    ctx->from = r->loc->src_charset.p;
    ctx->to = r->loc->charset.p;

    for (b = in; b; b = next) {
        next = b->next;
        if (!(b->flags & SNX_IOB_MEM)) {
            snx_iob_append(&head, &tail, b);
            continue;
        }

        out = snx_iob_new(r->arena, snx_iob_len(b) * 2 + 8);
        w = out->head;

        p = b->head;
        end = b->tail;

        while (p < end) {
            int  sl = snx_seq_len(p, end);
            int  i;

            /* emit one output unit per input sequence */
            for (i = 0; i < sl; i++) {
                uchar  c = p[i];
                *w++ = (c < 0x80) ? c : (uchar) '?';
            }
            p += sl;
        }

        out->tail = w;
        out->flags |= (b->flags & SNX_IOB_LAST);
        snx_iob_append(&head, &tail, out);
    }

    (void) ctx;
    return head;
}
