#include <snx.h>
#include <dirent.h>

/*
 * Small content handlers: index files, autoindex, try_files,
 * empty_gif, stub_status, random_index, flv, return.
 */

/* ---- helpers ---- */

static snx_iobuf_t *
snx_mem_buf(snx_arena_t *a, uchar *data, size_t n)
{
    snx_iobuf_t *b = snx_acnew(a, snx_iobuf_t);
    b->base = data;
    b->head = data;
    b->tail = data + n;
    b->cap = n;
    b->flags = SNX_IOB_MEM | SNX_IOB_LAST;
    return b;
}

void
snx_add_hdr(snx_http_req_t *r, const char *k, snx_str_t *v)
{
    snx_hdr_t *h = snx_acnew(r->arena, snx_hdr_t);
    h->k.p = (uchar *) k;
    h->k.n = strlen(k);
    h->v = *v;
    *r->out.hlast = h;
    r->out.hlast = &h->next;
}

/* 301/302 redirect helper */
int
snx_http_redirect(snx_http_req_t *r, snx_str_t *loc, int status)
{
    /* absolute_redirect off strips scheme://authority, leaving the
       origin-form path in Location */
    if (!snx_cfg.absolute_redirect && loc->n > 0 && loc->p[0] != '/') {
        uchar  *s = loc->p, *e = loc->p + loc->n, *sl;
        if (loc->n > 7 && (memcmp(s, "http://", 7) == 0
                           || memcmp(s, "https://", 8) == 0))
        {
            sl = memchr(s + 8, '/', e - (s + 8));
            if (sl) {
                loc->n -= sl - s;
                loc->p = sl;
            }
        }
    }
    snx_add_hdr(r, "Location", loc);
    r->out.status = status;
    r->out.cl_n = 0;
    if (snx_http_send_head(r) != SNX_OK) {
        return SNX_ERROR;
    }
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* ---- empty_gif ---- */

int
snx_mod_empty_gif(snx_http_req_t *r)
{
    static const uchar gif[] = {
        'G','I','F','8','9','a',1,0,1,0,0x80,0,0,0,0,0,0,0,0,
        0x21,0xf9,4,1,0,0,0,0,0x2c,0,0,0,0,1,0,1,0,0,2,2,0x44,
        1,0,0x3b
    };

    r->out.status = SNX_HTTP_OK;
    r->out.cl_n = sizeof(gif);
    {
        snx_str_t *ct = snx_anew(r->arena, snx_str_t);
        snx_str_set(ct, "image/gif");
        r->out.ctype = ct;
    }
    if (snx_http_send_head(r) != SNX_OK) {
        return SNX_ERROR;
    }
    (void) snx_http_write(r,
        snx_mem_buf(r->arena, (uchar *) gif, sizeof(gif)));
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* ---- stub_status ---- */

int
snx_mod_stub_status(snx_http_req_t *r)
{
    uchar  *p = snx_arena_alloc(r->arena, 512);
    size_t  n;

    n = (size_t) (snx_fmt(p, p + 512,
        "Active connections: %d \n"
        "server accepts handled requests\n"
        " %d %d %d \n"
        "Reading: %d Writing: %d Waiting: %d \n",
        snx_conns, snx_conns_total, snx_conns_total,
        snx_conns_handled,
        snx_conns - snx_conns_waiting - snx_conns_writing,
        snx_conns_writing, snx_conns_waiting) - p);

    r->out.status = SNX_HTTP_OK;
    r->out.cl_n = n;
    {
        snx_str_t *ct = snx_anew(r->arena, snx_str_t);
        snx_str_set(ct, "text/plain");
        r->out.ctype = ct;
    }
    if (snx_http_send_head(r) != SNX_OK) {
        return SNX_ERROR;
    }
    (void) snx_http_write(r, snx_mem_buf(r->arena, p, n));
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* ---- return directive ---- */

int
snx_mod_return_node(snx_http_req_t *r, snx_node_t *d)
{
    const char  *a0, *a1;
    int          code;

    a0 = snx_node_arg(d, 0);
    a1 = snx_node_arg(d, 1);
    if (a0 == NULL) {
        return SNX_DECLINED;
    }

    code = atoi(a0);
    if (code == 0) {
        code = 200;
    }

    if (a1) {
        if (code == SNX_HTTP_MOVED || code == SNX_HTTP_FOUND
            || code == SNX_HTTP_SEE_OTHER
            || (code >= 300 && code < 400))
        {
            uchar       *w;
            snx_str_t    tmpl = { (uchar *) a1, strlen(a1) };
            snx_str_t    loc;

            /* redirects sized from the template, expanded inline */
            w = snx_arena_alloc(r->arena, tmpl.n + 8);
            loc.p = w;
            loc.n = (size_t) snx_complex_eval(r, &tmpl, w);
            return snx_http_redirect(r, &loc, code);
        }

        {
            snx_str_t   tmpl = { (uchar *) a1, strlen(a1) };
            uchar      *w;
            size_t      n;
            snx_str_t  *ct;

            w = snx_arena_alloc(r->arena, tmpl.n + 64);
            n = (size_t) snx_complex_eval(r, &tmpl, w);

            ct = snx_anew(r->arena, snx_str_t);
            snx_str_set(ct, "text/plain");
            r->out.ctype = ct;
            r->out.status = code;
            r->out.cl_n = n;
            if (snx_http_send_head(r) != SNX_OK) {
                return SNX_ERROR;
            }
            (void) snx_http_write(r, snx_mem_buf(r->arena, w, n));
            snx_http_finish(r, SNX_HTTP_OK);
            return SNX_DONE;
        }
    }

    /* bare code >= 400 goes to the error page; 2xx/3xx answer with
       an empty body */
    if (code >= 400) {
        return code;
    }
    r->out.status = code;
    r->out.cl_n = 0;
    if (snx_http_send_head(r) != SNX_OK) {
        return SNX_ERROR;
    }
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

int
snx_mod_return(snx_http_req_t *r)
{
    snx_node_t  *d;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_DECLINED;
    }
    d = snx_conf_find(r->loc->conf, "return");
    if (d == NULL) {
        return SNX_DECLINED;
    }
    return snx_mod_return_node(r, d);
}

/* ---- index directive ---- */

int
snx_try_index(snx_http_req_t *r)
{
    snx_node_t  *d;
    int          i;
    struct stat  st;

    d = r->loc->conf ? snx_conf_find(r->loc->conf, "index") : NULL;
    if (d == NULL) {
        d = r->srv->conf ? snx_conf_find(r->srv->conf, "index") : NULL;
    }

    for (i = 0; d && i < d->nargs; i++) {
        const char *ix = snx_node_arg(d, i);
        snx_str_t   nu;
        int         last = (i == d->nargs - 1);

        if (ix == NULL) {
            continue;
        }

        /* an absolute name means an internal redirect to that uri */
        if (ix[0] == '/' || ix[0] == '@') {
            nu.p = (uchar *) ix + (ix[0] == '@');
            nu.n = strlen(ix) - (ix[0] == '@');
            if (ix[0] == '@') {
                if (snx_http_find_named(r, &nu) == SNX_OK) {
                    snx_http_run(r);
                    return SNX_DONE;
                }
                return SNX_HTTP_NOT_FOUND;
            }
            snx_http_internal_redirect(r, &nu);
            return SNX_DONE;
        }

        if (last && i > 0) {
            /* last arg on a multi-arg index list is a fallback uri */
            if (snx_strlchr((uchar *) ix, (uchar *) ix + strlen(ix),
                            '=') == NULL)
            {
                nu.p = (uchar *) ix;
                nu.n = strlen(ix);
                if (ix[0] != '/') {
                    continue;
                }
            }
        }

        {
            snx_str_t  path, tail;
            tail.p = (uchar *) ix;
            tail.n = strlen(ix);
            if (snx_http_map_path(r, &path) != SNX_OK) {
                continue;
            }
            {
                uchar *f = snx_arena_alloc(r->arena,
                                         path.n + tail.n + 2);
                uchar *w = snx_cpymem(f, path.p, path.n);
                *w++ = '/';
                w = snx_cpymem(w, tail.p, tail.n);
                *w = '\0';
                if (stat((char *) f, &st) == 0 && S_ISREG(st.st_mode))
                {
                    /* internal redirect to uri + index name */
                    nu.p = snx_arena_alloc(r->arena,
                                           r->uri.n + tail.n + 2);
                    w = snx_cpymem(nu.p, r->uri.p, r->uri.n);
                    if (r->uri.n && r->uri.p[r->uri.n - 1] != '/') {
                        *w++ = '/';
                    }
                    w = snx_cpymem(w, tail.p, tail.n);
                    nu.n = w - nu.p;
                    snx_http_internal_redirect(r, &nu);
                    return SNX_DONE;
                }
            }
        }
    }
    return SNX_DECLINED;
}

/* ---- try_files ---- */

int
snx_try_files(snx_http_req_t *r)
{
    snx_node_t  *d;
    int          i;

    d = r->loc->conf ? snx_conf_find(r->loc->conf, "try_files")
                     : NULL;
    if (d == NULL || d->nargs < 2) {
        return SNX_DECLINED;
    }

    for (i = 0; i < d->nargs - 1; i++) {
        const char  *cand = snx_node_arg(d, i);
        snx_str_t    tmpl, uri;
        uchar       *w;
        struct stat  st;

        if (cand == NULL) {
            continue;
        }
        tmpl.p = (uchar *) cand;
        tmpl.n = strlen(cand);

        w = snx_arena_alloc(r->arena, r->uri.n + tmpl.n + 8);
        uri.p = w;
        uri.n = (size_t) snx_complex_eval(r, &tmpl, w);
        uri.p[uri.n] = '\0';

        {
            int  isdir = uri.n && uri.p[uri.n - 1] == '/';
            snx_str_t path;
            snx_loc_t *sv = r->loc;
            size_t    off = isdir ? uri.n - 1 : uri.n;

            /* map the candidate against the current location root */
            {
                snx_str_t save = r->uri;
                r->uri = uri;
                if (snx_http_map_path(r, &path) != SNX_OK) {
                    r->uri = save;
                    continue;
                }
                r->uri = save;
            }
            (void) off;

            if (stat((char *) path.p, &st) == 0
                && (isdir ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode)))
            {
                (void) sv;
                snx_http_internal_redirect(r, &uri);
                return SNX_DONE;
            }
        }
    }

    /* last arg: internal redirect, @name, or =code */
    {
        const char  *last = snx_node_arg(d, d->nargs - 1);
        snx_str_t    nu;

        if (last[0] == '=') {
            return atoi(last + 1) >= 400 ? atoi(last + 1)
                                       : SNX_HTTP_NOT_FOUND;
        }
        if (last[0] == '@') {
            nu.p = (uchar *) last + 1;
            nu.n = strlen(last) - 1;
            if (snx_http_find_named(r, &nu) == SNX_OK) {
                snx_http_run(r);
                return SNX_DONE;
            }
            return SNX_HTTP_NOT_FOUND;
        }

        nu.p = (uchar *) last;
        nu.n = strlen(last);
        snx_http_internal_redirect(r, &nu);
        return SNX_DONE;
    }
}

/* ---- autoindex ---- */

int
snx_mod_autoindex(snx_http_req_t *r, snx_str_t *path)
{
    DIR            *dp;
    struct dirent  *de;
    uchar          *buf, *w, *end;
    size_t          cap;
    struct stat     st;
    char            esc[1024], pbuf[4096];
    snx_str_t      *ct;

    snprintf(pbuf, sizeof(pbuf), "%.*s", (int) path->n, path->p);
    dp = opendir(pbuf);
    if (dp == NULL) {
        return SNX_HTTP_FORBIDDEN;
    }

    cap = 8192;
    buf = snx_arena_alloc(r->arena, cap);
    end = buf + cap;
    w = snx_fmt(buf, end, "<html>\r\n<head><title>Index of %S</title>"
                "</head>\r\n<body>\r\n<h1>Index of %S</h1>"
                "<hr><pre>\r\n", &r->uri, &r->uri);
    w = snx_fmt(w, end, "<a href=\"../\">../</a>\r\n");

    while ((de = readdir(dp)) != NULL) {
        char   fbuf[4096], tbuf[64];
        int    i;
        struct tm tm;

        if (de->d_name[0] == '.' && de->d_name[1] == '\0') {
            continue;
        }

        /* entry path is assembled into the scratch file buffer */
        snprintf(fbuf, sizeof(fbuf), "%s/%s", pbuf, de->d_name);
        if (stat(fbuf, &st) != 0) {
            continue;
        }

        /* html-escape the name (rough) */
        for (i = 0; de->d_name[i] && i < 1000; i++) {
            if (de->d_name[i] == '<' || de->d_name[i] == '>'
                || de->d_name[i] == '&')
            {
                esc[i] = '?';
            } else {
                esc[i] = de->d_name[i];
            }
        }
        esc[i] = '\0';

        strftime(tbuf, sizeof(tbuf), "%d-%b-%Y %H:%M",
                 localtime_r(&st.st_mtime, &tm));

        if (S_ISDIR(st.st_mode)) {
            w = snx_fmt(w, end, "<a href=\"%s/\">%s/</a>%*s%s -\r\n",
                        esc, esc, (int) (50 - strlen(esc)), "",
                        tbuf);
        } else {
            w = snx_fmt(w, end, "<a href=\"%s\">%s</a>%*s%s %f\r\n",
                        esc, esc, (int) (50 - strlen(esc)), "",
                        tbuf, (soff_t) st.st_size);
        }
        if (w >= end - 512) {
            break;
        }
    }
    closedir(dp);

    w = snx_fmt(w, end, "</pre><hr></body>\r\n</html>\r\n");

    ct = snx_anew(r->arena, snx_str_t);
    snx_str_set(ct, "text/html");
    r->out.ctype = ct;
    r->out.status = SNX_HTTP_OK;
    r->out.cl_n = w - buf;
    if (snx_http_send_head(r) != SNX_OK) {
        return SNX_ERROR;
    }
    (void) snx_http_write(r, snx_mem_buf(r->arena, buf, w - buf));
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* ---- random_index ---- */

int
snx_mod_random_index(snx_http_req_t *r, snx_str_t *path)
{
    DIR            *dp;
    struct dirent  *de;
    char           *names[256];
    char            pbuf[4096];
    int             n = 0, pick;
    snx_str_t       nu;

    snprintf(pbuf, sizeof(pbuf), "%.*s", (int) path->n, path->p);
    dp = opendir(pbuf);
    if (dp == NULL) {
        return SNX_DECLINED;
    }
    while ((de = readdir(dp)) != NULL && n < 256) {
        if (de->d_name[0] == '.') {
            continue;
        }
        names[n++] = strdup(de->d_name);
    }
    closedir(dp);
    if (n == 0) {
        return SNX_DECLINED;
    }

    pick = (int) (arc4random() % n);
    nu.p = snx_arena_alloc(r->arena, r->uri.n + strlen(names[pick]) + 2);
    {
        uchar *w = snx_cpymem(nu.p, r->uri.p, r->uri.n);
        *w++ = '/';
        w = snx_cpymem(w, (uchar *) names[pick], strlen(names[pick]));
        nu.n = w - nu.p;
    }
    while (n--) {
        free(names[n]);
    }
    snx_http_internal_redirect(r, &nu);
    return SNX_DONE;
}

/* ---- flv pseudo-streaming ---- */

int
snx_mod_flv(snx_http_req_t *r, snx_str_t *path, int fd, struct stat *st)
{
    static const uchar flvh[] = {
        'F','L','V',1,1,0,0,0,9,
        0,0,0,9
    };
    soff_t   start = 0;

    if (snx_conf_arg(r->loc->conf, "flv") == NULL) {
        return SNX_DECLINED;
    }
    {
        snx_str_t  name = { (uchar *) "start", 5 };
        snx_str_t  val;
        val = snx_var_lookup_pub(r, &name); /* arg_start via arg_ */
        {
            snx_str_t an = { (uchar *) "arg_start", 9 };
            val = snx_var_lookup_pub(r, &an);
        }
        if (val.n) {
            start = snx_atooff(val.p, val.n);
        }
    }
    if (start <= 0 || start >= st->st_size) {
        return SNX_DECLINED;
    }

    r->out.status = SNX_HTTP_OK;
    r->out.cl_n = sizeof(flvh) + (st->st_size - start);
    {
        snx_str_t *ct = snx_anew(r->arena, snx_str_t);
        snx_str_set(ct, "video/x-flv");
        r->out.ctype = ct;
    }
    if (snx_http_send_head(r) != SNX_OK) {
        return SNX_ERROR;
    }
    {
        snx_iobuf_t *b;
        b = snx_mem_buf(r->arena, (uchar *) flvh, sizeof(flvh));
        b->flags &= ~SNX_IOB_LAST;
        {
            snx_iobuf_t *f = snx_iob_file(r->arena, fd, start,
                                        st->st_size - start);
            f->flags |= SNX_IOB_LAST;
            b->next = f;
        }
        (void) snx_http_write(r, b);
    }
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}
