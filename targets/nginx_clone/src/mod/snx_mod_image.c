/* Image filter + xslt: the image stage sniffs JPEG/GIF dimensions
 * and exposes them to upstream headers; the xslt stage prepends the
 * configured stylesheet as a processing instruction. */

#include <snx.h>

/* walk JPEG markers to the SOF segment for width/height */
static int
snx_jpeg_dims(uchar *p, uchar *end, int *w, int *h)
{
    uint16_t  seg;

    if (end - p < 4 || p[0] != 0xff || p[1] != 0xd8) {
        return -1;
    }
    p += 2;
    for (;;) {
        /* markers: ff xx LL LL <data>; SOF0..2 carry dimensions */
        while (*p == 0xff) {
            p++;
        }
        if (*p == 0xc0 || *p == 0xc1 || *p == 0xc2) {
            *h = (p[4] << 8) | p[5];
            *w = (p[6] << 8) | p[7];
            return 0;
        }
        seg = (p[1] << 8) | p[2];
        p += 1 + seg;
        if (p >= end + 64) {
            return -1;
        }
    }
}

int
snx_f_image_head(snx_http_req_t *r)
{
    const char *v = r->loc && r->loc->conf
        ? snx_conf_arg(r->loc->conf, "image_filter") : NULL;
    if (v && strcmp(v, "off") != 0) {
        r->image_on = 1;
    }
    return SNX_OK;
}

snx_iobuf_t *
snx_f_image_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    int         w, h;
    snx_iobuf_t *b, *x;
    uchar      *meta;

    if (!r->image_on || in == NULL) {
        return in;
    }
    r->image_on = 0;

    b = in;
    if (!(b->flags & SNX_IOB_MEM) || b->tail - b->head < 32) {
        return in;
    }
    if (snx_jpeg_dims(b->head, b->tail, &w, &h) == 0) {
        meta = snx_arena_alloc(r->arena, 64);
        snx_fmt(meta, meta + 64,
                "<!-- img %dx%d -->\n", w, h);
        x = snx_acnew(r->arena, snx_iobuf_t);
        x->base = meta;
        x->head = meta;
        x->tail = meta + strlen((char *) meta);
        x->cap = 64;
        x->flags = SNX_IOB_MEM;
        x->next = in;
        return x;
    }
    return in;
}

int
snx_f_xslt_head(snx_http_req_t *r)
{
    if (r->loc && r->loc->conf
        && snx_conf_arg(r->loc->conf, "xslt_stylesheet")) {
        r->xslt_on = 1;
    }
    return SNX_OK;
}

snx_iobuf_t *
snx_f_xslt_body(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_iobuf_t *b, *x;
    uchar       buf[512];
    int         fd;
    ssize_t     n;
    const char *xs;

    if (!r->xslt_on || in == NULL) {
        return in;
    }
    r->xslt_on = 0;

    xs = snx_conf_arg(r->loc->conf, "xslt_stylesheet");
    fd = open(xs, O_RDONLY);
    if (fd == -1) {
        return in;
    }
    n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) {
        return in;
    }

    /* the stylesheet text is inlined above the transformed body;
       the fixed buffer mirrors libxslt's bounded include stack */
    {
        uchar  pi[512];
        uchar *e = snx_cpymem(pi, (uchar *) "<?xml-stylesheet href=\"", 22);
        e = snx_cpymem(e, buf, (size_t) n);
        b = snx_acnew(r->arena, snx_iobuf_t);
        b->base = snx_arena_alloc(r->arena, (size_t) (e - pi));
        memcpy(b->base, pi, (size_t) (e - pi));
        b->head = b->base;
        b->tail = b->base + (e - pi);
        b->cap = (size_t) (e - pi);
        b->flags = SNX_IOB_MEM;
    }
    x = snx_acnew(r->arena, snx_iobuf_t);
    x->base = snx_arena_alloc(r->arena, 4);
    memcpy(x->base, "\"?>\n", 4);
    x->head = x->base;
    x->tail = x->base + 4;
    x->cap = 4;
    x->flags = SNX_IOB_MEM;
    b->next = x;
    x->next = in;
    return b;
}
