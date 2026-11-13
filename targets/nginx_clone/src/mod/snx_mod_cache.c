#include <snx.h>
#include <sys/stat.h>

/*
 * proxy_cache: on-disk keyed response cache.  Cache files live in
 * a two-level hashed tree under proxy_cache_path, like nginx's
 * levels=1:2 layout — except the leaf name is derived from the
 * proxy_cache_key string itself.
 */

static snx_str_t snx_cache_path;

int
snx_cache_init(snx_arena_t *a, snx_node_t *http)
{
    const char *p;
    int         i;

    for (i = 0; http && i < http->nkids; i++) {
        snx_node_t *d = http->kids[i];
        if (strcmp(d->name, "proxy_cache_path") == 0 && d->nargs) {
            p = snx_node_arg(d, 0);
            snx_cache_path.p = (uchar *) p;
            snx_cache_path.n = strlen(p);
        }
    }
    (void) a;
    return SNX_OK;
}

/* the cache key: proxy_cache_key template or $scheme$host$uri$args */
static int
snx_cache_key(snx_http_req_t *r, uchar *out, size_t cap)
{
    const char *t;
    snx_str_t   tmpl;

    t = snx_conf_arg(r->loc->conf, "proxy_cache_key");
    if (t == NULL) {
        int n;
        n = snprintf((char *) out, cap, "%.*s%.*s%.*s",
                     5, "http:", (int) r->uri.n, r->uri.p,
                     (int) r->args.n,
                     r->args.p ? (char *) r->args.p : "");
        return n < (int) cap ? n : -1;
    }
    tmpl.p = (uchar *) t;
    tmpl.n = strlen(t);
    {
        int n = snx_complex_eval(r, &tmpl, out);
        if (n <= 0 || n >= (int) cap) {
            return -1;
        }
        out[n] = 0;
        return n;
    }
}

/* leaf file name: hash-derived directories, raw key suffix file —
   the key suffix is trusted to stay inside the tree */
static int
snx_cache_file(snx_http_req_t *r, uchar *key, uchar *path, size_t cap)
{
    uchar   md5[16];
    size_t  kn = strlen((char *) key);
    int     n;

    {
        snx_md5_t m;
        snx_md5_init(&m);
        snx_md5_update(&m, key, kn);
        snx_md5_final(md5, &m);
    }

    /* directory levels come from the digest tail; the leaf embeds
       the raw key text for readability */
    n = snprintf((char *) path, cap, "%.*s/%02x/%02x%02x/%s",
                 (int) snx_cache_path.n, snx_cache_path.p,
                 md5[15], md5[14], md5[13], key);
    if (n <= 0 || n >= (int) cap) {
        return -1;
    }
    (void) r;
    return n;
}

static int
snx_cache_mkdirs(char *path)
{
    char *p;

    for (p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void) mkdir(path, 0755);
            *p = '/';
        }
    }
    return 0;
}

/* cache validity by status; proxy_cache_valid <code|any> <time> */
static int
snx_cache_valid_for(snx_http_req_t *r, int status)
{
    snx_node_t *c = r->loc->conf;
    int         i, j, def = -1;

    for (i = 0; c && i < c->nkids; i++) {
        snx_node_t *d = c->kids[i];
        if (strcmp(d->name, "proxy_cache_valid") != 0) {
            continue;
        }
        for (j = 0; j + 1 < d->nargs + 1; j++) {
            const char *a = snx_node_arg(d, j);
            const char *tv;
            int         cs;
            if (a == NULL) {
                break;
            }
            /* last arg is the time */
            tv = snx_node_arg(d, d->nargs - 1);
            if (a == tv) {
                break;
            }
            if (strcmp(a, "any") == 0) {
                def = (int) snx_parse_time(tv);
                continue;
            }
            cs = atoi(a);
            if (cs == status) {
                return (int) snx_parse_time(tv);
            }
        }
    }
    return def < 0 ? 60 : def;
}

/* a cache-control/request header can bypass lookup entirely */
static int
snx_cache_bypass(snx_http_req_t *r)
{
    snx_node_t *c = r->loc->conf;
    int         i, j;

    for (i = 0; c && i < c->nkids; i++) {
        snx_node_t *d = c->kids[i];
        if (strcmp(d->name, "proxy_cache_bypass") != 0) {
            continue;
        }
        for (j = 0; j < d->nargs; j++) {
            const char *a = snx_node_arg(d, j);
            if (a == NULL || a[0] != '$') {
                continue;
            }
            {
                snx_str_t nm = { (uchar *) a + 1, strlen(a) - 1 };
                snx_str_t v = snx_var_lookup_pub(r, &nm);
                if (v.n && !(v.n == 1 && v.p[0] == '0')) {
                    return 1;
                }
            }
        }
    }
    /* request-side Cache-Control: no-cache also bypasses */
    if (r->in.cc && (memmem(r->in.cc->p, r->in.cc->n,
                            "no-cache", 8)
                     || memmem(r->in.cc->p, r->in.cc->n,
                               "no-store", 8)))
    {
        return 1;
    }
    return 0;
}

static int snx_cache_serve_fd(snx_http_req_t *r, int fd, off_t size,
                              const char *tag);

/* called before the proxy handler; SNX_DONE when a hit is served */
int
snx_mod_cache_lookup(snx_http_req_t *r)
{
    uchar    key[1024], path[1400];
    struct stat st;
    int         fd;

    if (snx_cache_path.p == NULL || r->loc == NULL
        || r->loc->conf == NULL
        || snx_conf_arg(r->loc->conf, "proxy_cache") == NULL)
    {
        return SNX_DECLINED;
    }
    if (snx_cache_bypass(r)) {
        snx_str_set(&r->upstream_cache, "BYPASS");
        return SNX_DECLINED;
    }
    if (snx_cache_key(r, key, sizeof(key)) < 0
        || snx_cache_file(r, key, path, sizeof(path)) < 0)
    {
        return SNX_DECLINED;
    }

    fd = open((char *) path, O_RDONLY);
    if (fd == -1 || fstat(fd, &st) != 0) {
        snx_str_set(&r->upstream_cache, "MISS");
        if (fd != -1) {
            close(fd);
        }
        return SNX_DECLINED;
    }

    /* staleness: mtime + validity window vs now */
    {
        int valid = snx_cache_valid_for(r, SNX_HTTP_OK);
        if (st.st_mtime + valid < time(NULL)) {
            snx_str_set(&r->upstream_cache, "EXPIRED");
            close(fd);
            return SNX_DECLINED;
        }
    }

    return snx_cache_serve_fd(r, fd, st.st_size, "HIT");
}

/* emit a cached file body; tag becomes X-Cache-Status */
static int
snx_cache_serve_fd(snx_http_req_t *r, int fd, off_t size,
                   const char *tag)
{
    uchar    hb[8192];
    ssize_t  n = read(fd, hb, sizeof(hb));
    uchar   *nl;

    if (n <= 0 || hb[0] != 'H') {
        close(fd);
        return SNX_DECLINED;
    }
    nl = memchr(hb, '\n', n);
    if (nl == NULL) {
        close(fd);
        return SNX_DECLINED;
    }
    {
        int    hlen = atoi((char *) hb + 1);
        uchar *hs = nl + 1;
        uchar *bp = hs + hlen;

        if (hlen < 0 || hlen > n - (hs - hb)) {
            close(fd);
            return SNX_DECLINED;
        }
        /* replay stored status + Content-Type */
        {
            r->out.status = atoi((char *) hs);
            if (r->out.status <= 0) {
                r->out.status = SNX_HTTP_OK;
            }
            {
                uchar *ct = memmem(hs, hlen, "Content-Type:", 13);
                if (ct) {
                    uchar *ce = memchr(ct, '\r', hs + hlen - ct);
                    if (ce) {
                        snx_str_t *t =
                            snx_anew(r->arena, snx_str_t);
                        t->p = ct + 13;
                        while (*t->p == ' ') {
                            t->p++;
                        }
                        t->n = ce - t->p;
                        r->out.ctype = t;
                    }
                }
            }
        }
        r->out.cl_n = size - (bp - hb);
        snx_str_set(&r->upstream_cache, tag);
        {
            snx_str_t *v = snx_anew(r->arena, snx_str_t);
            *v = r->upstream_cache;
            snx_add_hdr(r, "X-Cache-Status", v);
        }
        (void) snx_http_send_head(r);
        {
            snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
            b->flags = SNX_IOB_FILE | SNX_IOB_LAST;
            b->fd = fd;
            b->fpos = bp - hb;
            b->flen = size - (bp - hb);
            (void) snx_http_write(r, b);
        }
    }
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* proxy_cache_use_stale: serve an expired entry when the upstream is
   failing; called from the proxy error path */
int
snx_mod_cache_stale(snx_http_req_t *r)
{
    uchar       key[1024], path[1400];
    struct stat st;
    int         fd;

    if (snx_cache_path.p == NULL || r->loc == NULL
        || r->loc->cache_stale == 0)
    {
        return SNX_DECLINED;
    }
    if (snx_cache_key(r, key, sizeof(key)) < 0
        || snx_cache_file(r, key, path, sizeof(path)) < 0)
    {
        return SNX_DECLINED;
    }
    fd = open((char *) path, O_RDONLY);
    if (fd == -1 || fstat(fd, &st) != 0) {
        if (fd != -1) {
            close(fd);
        }
        return SNX_DECLINED;
    }
    return snx_cache_serve_fd(r, fd, st.st_size, "STALE");
}

/* record the upstream reply under the key; called by the proxy path
   after a cacheable response completes */
int
snx_cache_save(snx_http_req_t *r, int status, snx_str_t *ctype,
               uchar *body, size_t blen)
{
    uchar   key[1024], path[1400];
    int     fd;

    if (snx_cache_path.p == NULL || r->loc == NULL
        || snx_conf_arg(r->loc->conf, "proxy_cache") == NULL)
    {
        return SNX_DECLINED;
    }
    if (snx_cache_valid_for(r, status) <= 0) {
        return SNX_DECLINED;
    }
    if (snx_cache_key(r, key, sizeof(key)) < 0
        || snx_cache_file(r, key, path, sizeof(path)) < 0)
    {
        return SNX_DECLINED;
    }
    snx_cache_mkdirs((char *) path);
    fd = open((char *) path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        return SNX_DECLINED;
    }
    {
        char  hb[512];
        int   hn = snprintf(hb, sizeof(hb),
                            "%d \r\nContent-Type: %.*s\r\n",
                            status, ctype ? (int) ctype->n : 10,
                            ctype ? (char *) ctype->p : "text/plain");
        dprintf(fd, "H%d\n", hn);
        (void) write(fd, hb, (size_t) hn);
    }
    if (body && blen) {
        (void) write(fd, body, blen);
    }
    close(fd);
    return SNX_OK;
}
