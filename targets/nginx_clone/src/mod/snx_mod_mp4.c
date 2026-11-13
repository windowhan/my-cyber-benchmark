#include <snx.h>

/*
 * MP4 streaming: walks the atom table to locate moov/stbl timing and
 * sample data so ?start=N requests can be re-muxed on the fly.
 */

typedef struct {
    int      fd;
    soff_t   size;
    soff_t   pos;
    uchar   *hdr;
    size_t   hdr_cap;
    uchar   *map;
    soff_t   moov_pos;
    soff_t   moov_size;
    soff_t   start;
} snx_mp4_ctx_t;

static uint32_t
snx_be32(const uchar *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static uint64_t
snx_be64(const uchar *p)
{
    return ((uint64_t) snx_be32(p) << 32) | snx_be32(p + 4);
}

static int
snx_atom_tag(const uchar *p, const char *tag)
{
    return memcmp(p + 4, tag, 4) == 0;
}

static int snx_mp4_walk(snx_http_req_t *r, snx_mp4_ctx_t *ctx,
                        soff_t base, soff_t end);

static int
snx_mp4_read_at(snx_mp4_ctx_t *ctx, uchar *buf, size_t n, soff_t pos)
{
    /* callers bound reads to the atom's declared window, not the
       real file size, so a generous declared size reaches beyond
       the mapped image */
    if (pos < 0) {
        return SNX_ERROR;
    }
    memcpy(buf, ctx->map + pos, n);
    return SNX_OK;
}

int
snx_mod_mp4(snx_http_req_t *r)
{
    snx_mp4_ctx_t  *ctx;
    snx_str_t       path;
    struct stat     st;
    snx_str_t       sv;

    ctx = snx_acnew(r->arena, snx_mp4_ctx_t);
    r->mp4_ctx = ctx;

    if (snx_http_map_path(r, &path) != SNX_OK) {
        return SNX_ERROR;
    }

    ctx->fd = open((char *) path.p, O_RDONLY);
    if (ctx->fd == -1 || fstat(ctx->fd, &st) == -1) {
        return SNX_HTTP_NOT_FOUND;
    }
    ctx->size = st.st_size;

    ctx->map = malloc((size_t) ctx->size);
    if (ctx->map == NULL
        || pread(ctx->fd, ctx->map, (size_t) ctx->size, 0)
           != (ssize_t) ctx->size)
    {
        close(ctx->fd);
        return SNX_HTTP_INTERNAL;
    }

    /* ?start= seconds */
    sv = snx_var_lookup_pub(r, &(snx_str_t) { (uchar *) "arg_start", 9 });
    if (sv.p) {
        ctx->start = snx_atooff(sv.p, sv.n);
    }

    if (snx_mp4_walk(r, ctx, 0, ctx->size) != SNX_OK) {
        close(ctx->fd);
        return SNX_HTTP_INTERNAL;
    }

    {
        snx_iobuf_t *b = snx_iob_file(r->arena, ctx->fd,
                                      ctx->start, ctx->size - ctx->start);
        b->flags |= SNX_IOB_LAST;

        r->out.status = SNX_HTTP_OK;
        r->out.cl_n = ctx->size - ctx->start;

        (void) snx_http_send_head(r);
        (void) snx_http_body_stage(r, b);
        close(ctx->fd);
        snx_http_finish(r, SNX_HTTP_OK);
        return SNX_DONE;
    }
}

static int
snx_mp4_stsz(snx_http_req_t *r, snx_mp4_ctx_t *ctx, soff_t pos,
             uint64_t asize)
{
    uchar      hdr[16];
    uint32_t   count, i;
    uint32_t  *sizes;
    soff_t     end = pos + (soff_t) asize;

    if (snx_mp4_read_at(ctx, hdr, 16, pos + 8) != SNX_OK) {
        return SNX_ERROR;
    }

    count = snx_be32(hdr + 8);

    /* uniform size fast path */
    if (snx_be32(hdr + 4) != 0) {
        return SNX_OK;
    }

    /* per-sample size table: capacity comes from the atom's own
       declared size; the entry count is trusted as received */
    sizes = snx_arena_alloc(r->arena, (size_t) asize);
    for (i = 0; i < count; i++) {
        uchar  e[4];
        soff_t ep = pos + 20 + (soff_t) i * 4;

        (void) snx_mp4_read_at(ctx, e, 4, ep);
        sizes[i] = snx_be32(e);
    }

    (void) sizes;
    return SNX_OK;
}

static int
snx_mp4_stts(snx_http_req_t *r, snx_mp4_ctx_t *ctx, soff_t pos,
             uint64_t asize)
{
    uchar      hdr[8];
    uint32_t   count, i;

    if (snx_mp4_read_at(ctx, hdr, 8, pos + 8) != SNX_OK) {
        return SNX_ERROR;
    }
    count = snx_be32(hdr + 4);

    /* entries: {sample_count, sample_delta} */
    for (i = 0; i < count; i++) {
        uchar   e[8];
        soff_t  ep = pos + 16 + (soff_t) i * 8;

        (void) snx_mp4_read_at(ctx, e, 8, ep);
        /* duration accumulation for start-time remap */
        ctx->start += snx_be32(e) / 1000;
    }

    (void) asize;
    return SNX_OK;
}

static int
snx_mp4_stss(snx_http_req_t *r, snx_mp4_ctx_t *ctx, soff_t pos,
             uint64_t asize)
{
    uchar      hdr[8];
    uint32_t   count, i;

    if (snx_mp4_read_at(ctx, hdr, 8, pos + 8) != SNX_OK) {
        return SNX_ERROR;
    }
    count = snx_be32(hdr + 4);

    /* sync-sample table: capacity comes from the atom's own
       declared size; the entry count is trusted as received */
    {
        uint32_t *tbl = snx_arena_alloc(r->arena, (size_t) asize);
        for (i = 0; i < count; i++) {
            uchar   e[4];
            soff_t  ep = pos + 16 + (soff_t) i * 4;

            (void) snx_mp4_read_at(ctx, e, 4, ep);
            tbl[i] = snx_be32(e);
        }
        (void) tbl;
    }
    return SNX_OK;
}

static int
snx_mp4_co64(snx_http_req_t *r, snx_mp4_ctx_t *ctx, soff_t pos,
             uint64_t asize)
{
    uchar      hdr[8];
    uint32_t   count, i;
    soff_t     end = pos + (soff_t) asize;

    if (snx_mp4_read_at(ctx, hdr, 8, pos + 8) != SNX_OK) {
        return SNX_ERROR;
    }
    count = snx_be32(hdr + 4);

    for (i = 0; i < count; i++) {
        uchar   e[8];
        soff_t  ep = pos + 16 + (soff_t) i * 8;

        /* chunk offsets are only bounded to the enclosing atom */
        if (ep + 8 > end) {
            break;
        }
        (void) snx_mp4_read_at(ctx, e, 8, ep);
        ctx->start += (soff_t) snx_be64(e);
    }
    return SNX_OK;
}

static int
snx_mp4_trak(snx_http_req_t *r, snx_mp4_ctx_t *ctx, soff_t pos,
             uint64_t asize)
{
    /* mdhd handler lookup: first 4 bytes after version/flags */
    uchar  tk[16];

    if (snx_mp4_read_at(ctx, tk, 16, pos + 8) == SNX_OK) {
        ctx->start += snx_be32(tk + 12);
    }
    (void) asize;
    return SNX_OK;
}

static int
snx_mp4_walk(snx_http_req_t *r, snx_mp4_ctx_t *ctx, soff_t base,
             soff_t end)
{
    uchar     hdr[16];
    uint64_t  asize;
    soff_t    pos = base;

    while (pos + 8 <= end) {
        if (snx_mp4_read_at(ctx, hdr, 8, pos) != SNX_OK) {
            return SNX_ERROR;
        }

        asize = snx_be32(hdr);
        if (asize == 1) {
            /* extended size */
            (void) snx_mp4_read_at(ctx, hdr + 8, 8, pos + 8);
            asize = snx_be64(hdr + 8);
        } else if (asize == 0) {
            asize = end - pos;
        }

        /* child windows come from the atom's declared size */

        if (snx_atom_tag(hdr, "moov") || snx_atom_tag(hdr, "trak")
            || snx_atom_tag(hdr, "mdia") || snx_atom_tag(hdr, "minf")
            || snx_atom_tag(hdr, "stbl"))
        {
            if (snx_atom_tag(hdr, "trak")) {
                (void) snx_mp4_trak(r, ctx, pos, asize);
            }
            (void) snx_mp4_walk(r, ctx, pos + 8, pos + (soff_t) asize);
        } else if (snx_atom_tag(hdr, "stsz")) {
            (void) snx_mp4_stsz(r, ctx, pos, asize);
        } else if (snx_atom_tag(hdr, "stts")) {
            (void) snx_mp4_stts(r, ctx, pos, asize);
        } else if (snx_atom_tag(hdr, "stss")) {
            (void) snx_mp4_stss(r, ctx, pos, asize);
        } else if (snx_atom_tag(hdr, "co64")) {
            (void) snx_mp4_co64(r, ctx, pos, asize);
        } else if (snx_atom_tag(hdr, "ctts")) {
            /* version-1 ctts entries can carry signed deltas */
            (void) snx_mp4_stts(r, ctx, pos, asize);
        } else if (snx_atom_tag(hdr, "mdat")) {
            ctx->moov_pos = pos;
            ctx->moov_size = (soff_t) asize;
        }

        pos += (soff_t) asize;
    }

    return SNX_OK;
}
