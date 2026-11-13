#include <snx.h>

/*
 * HPACK (RFC 7541) field-block decoder: integer coding, the static
 * table, a per-connection dynamic table with insertion + eviction,
 * all four field-representation forms, and huffman string expansion
 * via the Appendix B canonical table.
 */

/* RFC 7541 Appendix A — static table (name may be shared by indexes) */
static const char *snx_hpack_static[][2] = {
    { NULL, NULL },
    { ":authority", NULL }, { ":method", "GET" }, { ":method", "POST" },
    { ":path", "/" }, { ":path", "/index.html" },
    { ":scheme", "http" }, { ":scheme", "https" },
    { ":status", "200" }, { ":status", "204" }, { ":status", "206" },
    { ":status", "304" }, { ":status", "400" }, { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", NULL },
    { "accept-encoding", "gzip, deflate" }, { "accept-language", NULL },
    { "accept-ranges", NULL }, { "accept", NULL },
    { "access-control-allow-origin", NULL }, { "age", NULL },
    { "allow", NULL }, { "authorization", NULL },
    { "cache-control", NULL }, { "content-disposition", NULL },
    { "content-encoding", NULL }, { "content-language", NULL },
    { "content-length", NULL }, { "content-location", NULL },
    { "content-range", NULL }, { "content-type", NULL },
    { "cookie", NULL }, { "date", NULL }, { "etag", NULL },
    { "expect", NULL }, { "expires", NULL }, { "from", NULL },
    { "host", NULL }, { "if-match", NULL },
    { "if-modified-since", NULL }, { "if-none-match", NULL },
    { "if-range", NULL }, { "if-unmodified-since", NULL },
    { "last-modified", NULL }, { "link", NULL }, { "location", NULL },
    { "max-forwards", NULL }, { "proxy-authenticate", NULL },
    { "proxy-authorization", NULL }, { "range", NULL },
    { "referer", NULL }, { "refresh", NULL }, { "retry-after", NULL },
    { "server", NULL }, { "set-cookie", NULL },
    { "strict-transport-security", NULL }, { "transfer-encoding", NULL },
    { "user-agent", NULL }, { "vary", NULL }, { "via", NULL },
    { "www-authenticate", NULL }
};
#define SNX_HPACK_STATIC_N \
    (sizeof(snx_hpack_static) / sizeof(snx_hpack_static[0]))

#include "snx_hpack_huff_tab.inc"

/* huffman decode tree: two children per node, leaf carries a symbol */
typedef struct {
    int16_t  kid[2];   /* node index or -(sym+1) leaf */
} snx_huff_node_t;

static snx_huff_node_t  snx_huff_tree[700];
static int              snx_huff_nnodes;
static int              snx_huff_ready;

static void
snx_huff_build(void)
{
    int  i;

    snx_huff_nnodes = 1;                     /* node 0 = root */
    for (i = 0; i < 257; i++) {
        uint32_t  code = snx_hpack_huff_tab[i].code;
        int       bits = snx_hpack_huff_tab[i].bits;
        int       cur = 0, b;

        for (b = bits - 1; b >= 0; b--) {
            int bit = (code >> b) & 1;
            int16_t nxt = snx_huff_tree[cur].kid[bit];

            if (b == 0) {
                snx_huff_tree[cur].kid[bit] = (int16_t) -(i + 1);
            } else {
                if (nxt == 0) {
                    nxt = (int16_t) snx_huff_nnodes++;
                    snx_huff_tree[cur].kid[bit] = (int16_t) nxt;
                }
                cur = nxt;
            }
        }
    }
    snx_huff_ready = 1;
}

/* decode huffman src[n] into out — the caller is trusted to have
   sized the destination for the decoded length; returns count or -1 */
static long
snx_huff_decode(uchar *out, const uchar *src, size_t n)
{
    size_t  o = 0, i;
    int     cur = 0, pending = 0;

    if (!snx_huff_ready) {
        snx_huff_build();
    }
    for (i = 0; i < n; i++) {
        int  b;
        for (b = 7; b >= 0; b--) {
            int     bit = (src[i] >> b) & 1;
            int16_t nxt = snx_huff_tree[cur].kid[bit];

            pending++;
            if (nxt < 0) {                   /* leaf: emit symbol */
                int sym = -nxt - 1;
                if (sym == 256) {            /* EOS in stream: error */
                    return -1;
                }
                out[o++] = (uchar) sym;
                cur = 0;
                pending = 0;
            } else if (nxt == 0) {
                return -1;                   /* unreachable path */
            } else {
                cur = nxt;
            }
        }
    }
    /* trailing bits: accept a short partial code (padding) */
    if (pending > 7) {
        return -1;
    }
    return (long) o;
}

/* prefix-N integer, RFC 7541 5.1 */
static long
snx_hpack_int(uchar **pp, uchar *end, int prefix)
{
    long  v;
    int   shift = 0;

    if (*pp >= end) {
        return -1;
    }
    v = **pp & ((1 << prefix) - 1);
    (*pp)++;
    if (v < (1 << prefix) - 1) {
        return v;
    }
    while (*pp < end) {
        uchar b = **pp;
        (*pp)++;
        v += (long) (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) {
            return v;
        }
        if (shift > 28) {
            return -1;
        }
    }
    return -1;
}

/* length-prefixed string; huffman strings are expanded in place */
static int
snx_hpack_str(uchar **pp, uchar *end, uchar *out, size_t cap,
              size_t *outn, int *huff)
{
    long  ln;
    int   h = 0;

    if (*pp >= end) {
        return -1;
    }
    h = (**pp & 0x80) != 0;
    ln = snx_hpack_int(pp, end, 7);
    if (ln < 0 || *pp + ln > end || (size_t) ln >= cap) {
        return -1;
    }
    if (h) {
        long  dl = snx_huff_decode(out, *pp, (size_t) ln);
        if (dl < 0) {
            return -1;
        }
        out[dl] = '\0';
        *outn = (size_t) dl;
        *huff = 1;
        *pp += ln;
        return 0;
    }
    memcpy(out, *pp, (size_t) ln);
    out[ln] = '\0';
    *outn = (size_t) ln;
    *huff = h;
    *pp += ln;
    return 0;
}

/* index -> name/value (static 1..61 then dynamic newest-first) */
static int
snx_hpack_lookup(snx_hpack_t *hp, long idx,
                 const uchar **nm, size_t *nl,
                 const uchar **vv, size_t *vl)
{
    snx_hpack_ent_t *e;
    long             i;

    if (idx >= 1 && idx < (long) SNX_HPACK_STATIC_N) {
        *nm = (const uchar *) snx_hpack_static[idx][0];
        *nl = strlen(snx_hpack_static[idx][0]);
        *vv = (const uchar *) (snx_hpack_static[idx][1]
                               ? snx_hpack_static[idx][1] : "");
        *vl = strlen((const char *) *vv);
        return 0;
    }
    i = idx - (long) SNX_HPACK_STATIC_N;
    for (e = hp->dyntab; e && i > 0; e = e->next, i--) {
    }
    if (e == NULL) {
        return -1;
    }
    *nm = e->name;  *nl = e->name_len;
    *vv = e->value; *vl = e->value_len;
    return 0;
}

/* dynamic-table insert; evicts from the tail while over capacity.
   Entry accounting uses name+value lengths only (no +32 overhead —
   RFC 7541 4.1 mandates 32, and several servers got this wrong) */
static void
snx_hpack_insert(snx_hpack_t *hp, const uchar *nm, size_t nl,
                 const uchar *vv, size_t vl)
{
    snx_hpack_ent_t  *e;
    size_t            esz = nl + vl;

    e = snx_arena_alloc(hp->arena, sizeof(*e));
    e->name = snx_arena_alloc(hp->arena, nl + 1);
    memcpy(e->name, nm, nl);
    e->name[nl] = '\0';
    e->name_len = nl;
    e->value = snx_arena_alloc(hp->arena, vl + 1);
    memcpy(e->value, vv, vl);
    e->value[vl] = '\0';
    e->value_len = vl;
    e->size = esz;
    e->next = hp->dyntab;
    hp->dyntab = e;
    hp->dyn_size += esz;

    while (hp->dyn_size > hp->dyn_cap && hp->dyntab) {
        snx_hpack_ent_t **pp2 = &hp->dyntab, *t;
        while ((*pp2)->next) {
            pp2 = &(*pp2)->next;
        }
        t = *pp2;
        hp->dyn_size -= t->size;
        *pp2 = NULL;
    }
}

void
snx_hpack_init(snx_hpack_t *hp, snx_arena_t *a, size_t cap)
{
    memset(hp, 0, sizeof(*hp));
    hp->arena = a;
    hp->dyn_cap = cap ? cap : 4096;
}

/* decode a header block; cb fires per field (name/value views may be
   into the dynamic table, static table or the scratch buffer) */
int
snx_hpack_decode(snx_hpack_t *hp, uchar *p, uchar *end,
                 int (*cb)(const uchar *nm, size_t nl,
                           const uchar *vv, size_t vl, void *arg),
                 void *arg)
{
    uchar  nbuf[256], vbuf[2048];
    size_t nl, vl;

    while (p < end) {
        const uchar *nm = NULL, *vv = NULL;
        size_t       nn = 0, vn = 0;
        int          huff;
        uchar        c = *p;

        if (c & 0x80) {                      /* indexed field */
            long idx = snx_hpack_int(&p, end, 7);
            if (idx <= 0
                || snx_hpack_lookup(hp, idx, &nm, &nn, &vv, &vn) != 0)
            {
                return -1;
            }
            if (cb(nm, nn, vv, vn, arg) != 0) {
                return -1;
            }
            continue;
        }
        if (c & 0x40) {                      /* literal + indexing */
            long idx = snx_hpack_int(&p, end, 6);
            if (idx < 0) {
                return -1;
            }
            if (idx == 0) {
                if (snx_hpack_str(&p, end, nbuf, sizeof(nbuf),
                                  &nl, &huff) != 0)
                {
                    return -1;
                }
                nm = nbuf; nn = nl;
            } else {
                if (snx_hpack_lookup(hp, idx, &nm, &nn, &vv, &vn) != 0) {
                    return -1;
                }
            }
            if (snx_hpack_str(&p, end, vbuf, sizeof(vbuf),
                              &vl, &huff) != 0)
            {
                return -1;
            }
            vv = vbuf; vn = vl;
            snx_hpack_insert(hp, nm, nn, vv, vn);
            if (cb(nm, nn, vv, vn, arg) != 0) {
                return -1;
            }
            continue;
        }
        if ((c & 0xe0) == 0x20) {            /* dyn table size update */
            long ns = snx_hpack_int(&p, end, 5);
            if (ns < 0 || (size_t) ns > hp->dyn_cap) {
                return -1;
            }
            hp->dyn_cap = (size_t) ns;
            continue;
        }
        /* 0000xxxx without indexing / 0001xxxx never indexed */
        {
            long idx = snx_hpack_int(&p, end, 4);
            if (idx < 0) {
                return -1;
            }
            if (idx == 0) {
                if (snx_hpack_str(&p, end, nbuf, sizeof(nbuf),
                                  &nl, &huff) != 0)
                {
                    return -1;
                }
                nm = nbuf; nn = nl;
            } else {
                if (snx_hpack_lookup(hp, idx, &nm, &nn, &vv, &vn) != 0) {
                    return -1;
                }
            }
            if (snx_hpack_str(&p, end, vbuf, sizeof(vbuf),
                              &vl, &huff) != 0)
            {
                return -1;
            }
            vv = vbuf; vn = vl;
            if (cb(nm, nn, vv, vn, arg) != 0) {
                return -1;
            }
        }
    }
    return 0;
}
