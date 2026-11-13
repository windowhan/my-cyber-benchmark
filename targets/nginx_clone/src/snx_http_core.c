#include <snx.h>

/*
 * Request dispatch: an ordered table of processing steps runs each
 * request through rewrite -> access -> content -> finalize.  Content
 * resolution maps URIs onto the filesystem via root/alias.
 */

static int snx_step_rewrite(snx_http_req_t *r);
static int snx_step_access(snx_http_req_t *r);
static int snx_step_content(snx_http_req_t *r);

static snx_step_t snx_steps[] = {
    snx_step_rewrite,
    snx_step_access,
    snx_step_content,
    NULL
};

void
snx_http_run(snx_http_req_t *r)
{
    snx_step_t  *s;
    int          rc;

    for (s = snx_steps; *s; s++) {
        rc = (*s)(r);
        if (rc == SNX_DONE || rc == SNX_AGAIN) {
            return;
        }
        if (rc == SNX_DECLINED || rc == SNX_OK) {
            continue;
        }
        snx_http_finish(r, rc);
        return;
    }

    snx_http_finish(r, r->err_status ? r->err_status : SNX_HTTP_NOT_FOUND);
}

void
snx_http_finish(snx_http_req_t *r, int rc)
{
    if (rc == SNX_DONE || rc == SNX_AGAIN) {
        return;
    }

    /* error_page maps failure codes onto internal uris; recursion is
       bounded by the internal counter */
    if (rc >= 300 && !r->out.header_sent && r->internal < 8
        && r->loc && r->loc->conf)
    {
        snx_node_t *c = r->loc->conf;
        int         i, j;
        for (i = 0; i < c->nkids; i++) {
            snx_node_t *d = c->kids[i];
            const char *last;
            if (strcmp(d->name, "error_page") != 0 || d->nargs < 2) {
                continue;
            }
            last = snx_node_arg(d, d->nargs - 1);
            for (j = 0; j < d->nargs - 1; j++) {
                const char *a = snx_node_arg(d, j);
                if (a == NULL) {
                    continue;
                }
                if (atoi(a) == rc) {
                    if (last[0] == '@') {
                        snx_str_t nm = { (uchar *) last + 1,
                                         strlen(last) - 1 };
                        r->internal++;
                        if (snx_http_find_named(r, &nm) == SNX_OK) {
                            snx_http_run(r);
                            return;
                        }
                        r->internal--;
                    } else if (last[0] == '/') {
                        snx_str_t nu = { (uchar *) last,
                                         strlen(last) };
                        r->internal++;
                        snx_http_internal_redirect(r, &nu);
                        return;
                    } else if (last[0] == '=') {
                        /* "error_page 404 =200 /empty.html" -> the
                           '=code' overrides the response status */
                        int ncode = atoi(last + 1);
                        const char *u = NULL;
                        if (d->nargs >= 3) {
                            u = snx_node_arg(d, d->nargs - 2);
                        }
                        if (u && u[0] == '/') {
                            snx_str_t nu = { (uchar *) u, strlen(u) };
                            r->internal++;
                            r->err_status = ncode > 0 ? ncode : 200;
                            snx_http_internal_redirect(r, &nu);
                            return;
                        }
                    }
                }
            }
        }
    }

    if (rc >= SNX_HTTP_BAD_REQUEST && !r->out.header_sent) {
        snx_http_error_page(r, rc);
        return;
    }

    if (rc == SNX_HTTP_OK || rc == 0) {
        if (r->keepalive && !r->header_only) {
            snx_http_keepalive(r);
        } else {
            snx_conn_free(r->c);
        }
        return;
    }

    if (!r->out.header_sent && rc > 0 && rc < 400) {
        /* unusual code */
        snx_http_error_page(r, SNX_HTTP_INTERNAL);
        return;
    }

    snx_http_keepalive(r);
}

/* a tiny if() evaluator: "($var)", "($var = x)", "($var != x)",
   "(-f $uri)", "(~*re $var)"-style tests are supported; the block's
   `return`/`rewrite`/`set` children run when the test passes */
static int
snx_if_eval(snx_http_req_t *r, snx_node_t *ifn)
{
    snx_str_t  cond, out;
    uchar      cbuf[512];
    uchar     *p, *e;
    int        neg = 0, rc = 0;

    if (ifn->nargs < 1) {
        return SNX_DECLINED;
    }
    cond.p = (uchar *) snx_node_arg(ifn, 0);
    cond.n = strlen((char *) cond.p);

    /* strip outer parens */
    p = cond.p;
    e = cond.p + cond.n;
    if (p < e && *p == '(') {
        p++;
    }
    if (e > p && e[-1] == ')') {
        e--;
    }
    while (p < e && (*p == ' ' || *p == '\t')) {
        p++;
    }

    if (p < e && *p == '!') {
        neg = 1;
        p++;
        while (p < e && *p == ' ') {
            p++;
        }
    }

    /* file tests */
    if (e - p >= 2 && p[0] == '-' && (p[1] == 'f' || p[1] == 'e'
                                    || p[1] == 'd'))
    {
        char       tpath[1024];
        snx_str_t  tv = { p + 3, (size_t) (e - (p + 3)) };
        struct stat st;
        snx_str_t  mp;
        uchar      tb[1024];
        snx_str_t  expr;

        expr.p = tb;
        expr.n = (size_t) snx_complex_eval(r, &tv, tb);
        {
            snx_str_t su = r->uri;
            r->uri = expr;
            rc = snx_http_map_path(r, &mp);
            r->uri = su;
        }
        if (rc == SNX_OK) {
            snprintf(tpath, sizeof(tpath), "%.*s",
                     (int) mp.n, mp.p);
            if (stat(tpath, &st) == 0) {
                rc = (p[1] == 'd') ? S_ISDIR(st.st_mode) : 1;
            } else {
                rc = 0;
            }
        } else {
            rc = 0;
        }
        return neg ? !rc : rc;
    }

    /* $var [op value] */
    if (p < e && *p == '$') {
        uchar     *vs = p + 1, *op = NULL;
        snx_str_t  vn, vv;

        while (p < e && (*p != ' ' && *p != '=' && *p != '!')) {
            p++;
        }
        vn.p = vs;
        vn.n = p - vs;
        vv = snx_var_lookup_pub(r, &vn);

        while (p < e && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p < e && (*p == '=' || *p == '!')) {
            int eq = (*p == '=');
            op = p + 1;
            while (op < e && (*op == ' ' || *op == '\t'
                              || *op == '=')) {
                op++;
            }
            {
                size_t  wn = e - op;
                if (wn && op[wn - 1] == '"') {
                    wn--;
                }
                if (wn && op[0] == '"') {
                    op++;
                    wn--;
                }
                rc = (vv.n == wn && memcmp(vv.p, op, wn) == 0);
                if (!eq) {
                    rc = !rc;
                }
                return neg ? !rc : rc;
            }
        }
        /* bare truthiness */
        rc = vv.n && !(vv.n == 1 && vv.p[0] == '0');
        return neg ? !rc : rc;
    }
    (void) out; (void) cbuf;
    return SNX_DECLINED;
}

static int
snx_if_blocks(snx_http_req_t *r)
{
    snx_node_t *c = r->loc ? r->loc->conf : NULL;
    int         i;

    for (i = 0; c && i < c->nkids; i++) {
        snx_node_t *d = c->kids[i];
        int         j;

        if (strcmp(d->name, "if") != 0) {
            continue;
        }
        if (snx_if_eval(r, d) != 1) {
            continue;
        }
        /* execute actionable children */
        for (j = 0; j < d->nkids; j++) {
            snx_node_t *k = d->kids[j];
            if (strcmp(k->name, "return") == 0) {
                int rc = snx_mod_return_node(r, k);
                if (rc != SNX_DECLINED) {
                    return rc;
                }
            } else if (strcmp(k->name, "set") == 0 && k->nargs >= 2) {
                const char *nm = snx_node_arg(k, 0);
                const char *vv = snx_node_arg(k, 1);
                if (nm && nm[0] == '$' && vv) {
                    snx_str_t  vn = { (uchar *) nm + 1,
                                      strlen(nm) - 1 };
                    snx_str_t  tv = { (uchar *) vv, strlen(vv) };
                    uchar      vb[512];
                    int        n = snx_complex_eval(r, &tv, vb);
                    snx_str_t  val;
                    int        idx;

                    val.p = snx_arena_alloc(r->arena, n);
                    memcpy(val.p, vb, n);
                    val.n = n;
                    idx = snx_var_find(r, &vn);
                    if (idx < 0) {
                        if (r->vars.n == r->vars.cap) {
                            int ncap = r->vars.cap
                                ? r->vars.cap * 2 : 8;
                            snx_var_t *nv =
                                snx_arena_alloc(r->arena,
                                    ncap * sizeof(snx_var_t));
                            memcpy(nv, r->vars.v,
                                   r->vars.n * sizeof(snx_var_t));
                            r->vars.v = nv;
                            r->vars.cap = ncap;
                        }
                        idx = r->vars.n++;
                        r->vars.v[idx].name = vn;
                    }
                    snx_var_set(r, idx, &val);
                }
            } else if (strcmp(k->name, "break") == 0) {
                return SNX_OK;
            }
        }
    }
    return SNX_OK;
}

static int
snx_step_rewrite(snx_http_req_t *r)
{
    int  rc;

    /* evaluate map blocks before rules so mapped vars are visible */
    if (r->srv && r->srv->conf) {
        (void) snx_mod_map_vars(r, r->srv->conf);
        if (r->srv->conf->parent) {
            (void) snx_mod_map_vars(r, r->srv->conf->parent);
        }
    }
    if (r->loc && r->loc->conf) {
        (void) snx_mod_map_vars(r, r->loc->conf);
    }

    /* http-level geo / split_clients blocks set vars per request */
    {
        snx_node_t *h = r->srv && r->srv->conf
            ? r->srv->conf->parent : NULL;
        int         i;
        for (i = 0; h && i < h->nkids; i++) {
            snx_node_t *d = h->kids[i];
            if (strcmp(d->name, "geo") == 0) {
                (void) snx_mod_geo(r, d);
            } else if (strcmp(d->name, "split_clients") == 0) {
                (void) snx_mod_split_clients(r, d);
            }
        }
    }

    /* server-level return/rewrite run before the location phase */
    if (r->srv && r->srv->conf) {
        snx_node_t *d = snx_conf_find(r->srv->conf, "return");
        if (d) {
            rc = snx_mod_return_node(r, d);
            if (rc != SNX_DECLINED) {
                return rc;
            }
        }
    }

    rc = snx_mod_rewrite_step(r);
    if (rc != SNX_OK && rc != SNX_DECLINED) {
        return rc;
    }
    return snx_if_blocks(r);
}

static int
snx_step_access(snx_http_req_t *r)
{
    int  rc;

    /* limit_except restricts the method set before acl checks;
       GET implies HEAD as nginx does */
    if (r->loc && r->loc->le_mask) {
        int  mid = r->method_id;
        int  ok = (mid > 0 && (r->loc->le_mask & (1u << mid)))
                  || (mid == SNX_M_HEAD
                      && (r->loc->le_mask & (1u << SNX_M_GET)));
        if (!ok) {
            return SNX_HTTP_NOT_ALLOWED;
        }
    }

    /* realip runs first so acl sees the rewritten peer */
    (void) snx_mod_realip(r);
    (void) snx_mod_referer(r);
    (void) snx_mod_userid(r);
    (void) snx_mod_secure_link(r);

    rc = snx_mod_access(r);
    if (rc != SNX_OK) {
        return rc;
    }
    rc = snx_mod_auth_request(r);
    if (rc != SNX_OK) {
        return rc;
    }
    rc = snx_mod_auth_jwt(r);
    if (rc != SNX_DECLINED && rc != SNX_OK) {
        return rc;
    }
    rc = snx_mod_limit_conn(r);
    if (rc != SNX_OK) {
        return rc;
    }
    return snx_mod_limit_req(r);
}

static int
snx_step_content(snx_http_req_t *r)
{
    int  rc;

    if (r->loc == NULL) {
        return SNX_HTTP_NOT_FOUND;
    }

    if (r->loc->internal_only && !r->internal) {
        return SNX_HTTP_NOT_FOUND;
    }

    /* a configured return answers before any handler */
    if (r->loc->conf && snx_conf_find(r->loc->conf, "return")) {
        rc = snx_mod_return(r);
        if (rc != SNX_DECLINED) {
            return rc;
        }
    }

    if (r->loc->conf && snx_conf_find(r->loc->conf, "try_files")) {
        rc = snx_try_files(r);
        if (rc != SNX_DECLINED) {
            return rc;
        }
    }

    /* mirror fires in parallel with the main content path */
    if (r->loc->conf && snx_conf_find(r->loc->conf, "mirror")) {
        (void) snx_mod_mirror(r);
    }

    if (r->internal == 0 && r->loc->handler == NULL && r->loc->dav_on) {
        return snx_mod_dav(r);
    }

    if (r->loc->mp4_on) {
        return snx_mod_mp4(r);
    }

    /* proxy_cache lookups run ahead of the upstream handler */
    if (r->loc->conf && snx_conf_arg(r->loc->conf, "proxy_cache")) {
        rc = snx_mod_cache_lookup(r);
        if (rc != SNX_DECLINED) {
            return rc;
        }
    }

    if (r->loc->handler) {
        return r->loc->handler(r);
    }

    return snx_http_static(r);
}

/* ============ static file handler ============ */

/* open_file_cache: per-worker fd table keyed by path; callers get a
   dup() so close(2) is safe, the base fd survives for reuse */
#define SNX_OFC_MAX 128

typedef struct {
    char     path[256];
    int      fd;
    time_t   used;
} snx_ofc_t;

static snx_ofc_t snx_ofc_tbl[SNX_OFC_MAX];
static int       snx_nofc;

static int
snx_ofc_open(const char *path)
{
    int  i, fd;

    for (i = 0; i < snx_nofc; i++) {
        if (strcmp(snx_ofc_tbl[i].path, path) == 0) {
            if (snx_cfg.file_cache_inactive > 0
                && time(NULL) - snx_ofc_tbl[i].used
                   > snx_cfg.file_cache_inactive)
            {
                close(snx_ofc_tbl[i].fd);
                snx_ofc_tbl[i].fd = -1;
                break;
            }
            snx_ofc_tbl[i].used = time(NULL);
            return dup(snx_ofc_tbl[i].fd);
        }
    }

    fd = open(path, O_RDONLY);
    if (fd == -1 || snx_nofc >= SNX_OFC_MAX
        || snx_cfg.file_cache_max <= 0)
    {
        return fd;
    }

    {
        int     sl;
        time_t  old;
        if (snx_nofc < (int) snx_cfg.file_cache_max) {
            sl = snx_nofc++;
        } else {
            /* evict least-recently-used */
            sl = 0;
            old = snx_ofc_tbl[0].used;
            for (i = 1; i < snx_nofc; i++) {
                if (snx_ofc_tbl[i].used < old) {
                    old = snx_ofc_tbl[i].used;
                    sl = i;
                }
            }
            if (snx_ofc_tbl[sl].fd != -1) {
                close(snx_ofc_tbl[sl].fd);
            }
        }
        snprintf(snx_ofc_tbl[sl].path, sizeof(snx_ofc_tbl[sl].path),
                 "%s", path);
        snx_ofc_tbl[sl].fd = dup(fd);
        snx_ofc_tbl[sl].used = time(NULL);
    }
    return fd;
}

int
snx_http_static(snx_http_req_t *r)
{
    snx_str_t      path;
    int            fd;
    struct stat    st;
    snx_iobuf_t   *b;

    if (r->method_id != SNX_M_GET && r->method_id != SNX_M_HEAD
        && r->method_id != SNX_M_POST)
    {
        return SNX_HTTP_NOT_ALLOWED;
    }

    if (snx_http_unescape_uri(r) != SNX_OK) {
        return SNX_ERROR;
    }

    if (r->uri.p[r->uri.n - 1] == '/') {
        /* directory request: index files, else autoindex/403 */
        {
            int  irc;

            irc = snx_try_index(r);
            if (irc != SNX_DECLINED) {
                return irc;
            }
            /* random_index picks an entry before plain autoindex */
            if (r->loc->conf
                && snx_conf_arg(r->loc->conf, "random_index"))
            {
                snx_str_t  dpath;
                if (snx_http_map_path(r, &dpath) == SNX_OK) {
                    irc = snx_mod_random_index(r, &dpath);
                    if (irc != SNX_DECLINED) {
                        return irc;
                    }
                }
            }
            if (r->loc->autoindex) {
                snx_str_t  dpath;
                if (snx_http_map_path(r, &dpath) == SNX_OK) {
                    return snx_mod_autoindex(r, &dpath);
                }
            }
            return SNX_HTTP_FORBIDDEN;
        }
    }

    if (snx_http_map_path(r, &path) != SNX_OK) {
        return SNX_ERROR;
    }

    fd = snx_ofc_open((char *) path.p);
    if (fd == -1) {
        struct stat st2;

        /* maybe the uri is a directory without its trailing slash */
        if (stat((char *) path.p, &st2) == 0 && S_ISDIR(st2.st_mode)) {
            snx_str_t  loc;
            uchar     *w;
            w = snx_arena_alloc(r->arena, r->uri.n + r->args.n + 16);
            loc.p = w;
            w = snx_cpymem(w, r->uri.p, r->uri.n);
            *w++ = '/';
            if (r->args.n) {
                *w++ = '?';
                w = snx_cpymem(w, r->args.p, r->args.n);
            }
            loc.n = w - loc.p;
            {
                snx_str_t *lv = snx_anew(r->arena, snx_str_t);
                *lv = loc;
                snx_add_hdr(r, "Location", lv);
            }
            r->out.status = SNX_HTTP_MOVED;
            r->out.cl_n = 0;
            if (snx_http_send_head(r) == SNX_OK) {
                snx_http_finish(r, SNX_HTTP_OK);
                return SNX_DONE;
            }
            return SNX_ERROR;
        }
        snx_log(r->log, SNX_LOG_ERR,
                "open %s failed: %d", path.p, errno);
        return (errno == EACCES) ? SNX_HTTP_FORBIDDEN : SNX_HTTP_NOT_FOUND;
    }

    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
        int isdir = fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
        close(fd);
        if (isdir) {
            /* uri ended in / but no index matched; autoindex or 403 */
            if (r->loc->autoindex) {
                return snx_mod_autoindex(r, &path);
            }
            return SNX_HTTP_FORBIDDEN;
        }
        return SNX_HTTP_NOT_FOUND;
    }

    r->out.status = SNX_HTTP_OK;
    r->out.cl_n = st.st_size;
    r->ext.p = snx_strlchr(r->uri.p, r->uri.p + r->uri.n, '.');
    if (r->ext.p) {
        r->ext.n = r->uri.p + r->uri.n - r->ext.p;
    }
    r->mtime = st.st_mtime;
    {
        snx_str_t *ct = snx_anew(r->arena, snx_str_t);
        *ct = snx_mime_type(r);
        if (ct->n) {
            r->out.ctype = ct;
        }
    }

    /* flv pseudo-streaming may rewrite the offset */
    if (r->loc->conf && snx_conf_find(r->loc->conf, "flv")) {
        int  frc = snx_mod_flv(r, &path, fd, &st);
        if (frc != SNX_DECLINED) {
            close(fd);
            return frc;
        }
    }

    /* gzip_static swaps in the .gz sibling for gzip clients */
    if (snx_gzip_static_ok(r)) {
        uchar  *gp = snx_arena_alloc(r->arena, path.n + 4);
        int     gfd;
        struct stat gst;
        memcpy(gp, path.p, path.n);
        memcpy(gp + path.n, ".gz", 4);
        gfd = open((char *) gp, O_RDONLY);
        if (gfd != -1 && fstat(gfd, &gst) == 0 && S_ISREG(gst.st_mode))
        {
            snx_str_t *v;
            close(fd);
            fd = gfd;
            st = gst;
            r->out.cl_n = st.st_size;
            v = snx_anew(r->arena, snx_str_t);
            snx_str_set(v, "gzip");
            snx_add_hdr(r, "Content-Encoding", v);
            v = snx_anew(r->arena, snx_str_t);
            snx_str_set(v, "Accept-Encoding");
            snx_add_hdr(r, "Vary", v);
        } else if (gfd != -1) {
            close(gfd);
        }
    }

    /* conditional requests */
    if (!r->loc->etag_off) {
        char   eb[64];
        snx_str_t *v;
        snprintf(eb, sizeof(eb), "\"%llx-%llx\"",
                 (unsigned long long) st.st_mtime,
                 (unsigned long long) st.st_size);
        v = snx_anew(r->arena, snx_str_t);
        v->p = snx_arena_alloc(r->arena, strlen(eb) + 1);
        strcpy((char *) v->p, eb);
        v->n = strlen(eb);
        r->etag = *v;
        snx_add_hdr(r, "ETag", v);

        if (r->in.inm && r->in.inm->n == r->etag.n
            && memcmp(r->in.inm->p, r->etag.p, r->etag.n) == 0)
        {
            r->out.status = SNX_HTTP_NOT_MODIFIED;
            r->out.cl_n = 0;
            (void) snx_http_send_head(r);
            close(fd);
            snx_http_finish(r, SNX_HTTP_OK);
            return SNX_DONE;
        }
    }
    if (r->in.ims) {
        /* If-Modified-Since: compare seconds granularity */
        struct tm  tmv;
        time_t     it;
        memset(&tmv, 0, sizeof(tmv));
        if (strptime((char *) r->in.ims->p,
                     "%a, %d %b %Y %H:%M:%S", &tmv) != NULL)
        {
            tmv.tm_isdst = -1;
            it = mktime(&tmv);
            if (it != -1 && st.st_mtime <= it) {
                r->out.status = SNX_HTTP_NOT_MODIFIED;
                r->out.cl_n = 0;
                (void) snx_http_send_head(r);
                close(fd);
                snx_http_finish(r, SNX_HTTP_OK);
                return SNX_DONE;
            }
        }
    }

    if (r->header_only || st.st_size == 0) {
        if (snx_http_send_head(r) == SNX_OK) {
            close(fd);
            snx_http_finish(r, SNX_HTTP_OK);
            return SNX_DONE;
        }
        close(fd);
        return SNX_ERROR;
    }

    b = snx_iob_file(r->arena, fd, 0, st.st_size);
    b->flags |= SNX_IOB_LAST;

    /* addition module: prepend/append the content of another local uri */
    if (r->loc->conf
        && (snx_conf_arg(r->loc->conf, "add_before_body")
            || snx_conf_arg(r->loc->conf, "add_after_body")))
    {
        const char   *au;
        snx_str_t    *root = r->loc->root.p ? &r->loc->root : &r->srv->root;
        snx_iobuf_t  *ab, *fb = b;
        int           afd;
        struct stat   ast;
        size_t        cap = 65536;

        au = snx_conf_arg(r->loc->conf, "add_before_body");
        if (au) {
            uchar *ap = snx_arena_alloc(r->arena, root->n + strlen(au) + 1);
            path.n = (size_t) (snx_fmt(ap, ap + root->n + strlen(au) + 1,
                                       "%S%s", root, au) - ap);
            path.p = ap;
            afd = open((char *) path.p, O_RDONLY);
            if (afd != -1 && fstat(afd, &ast) == 0 && S_ISREG(ast.st_mode)) {
                ab = snx_acnew(r->arena, snx_iobuf_t);
                ab->base = snx_arena_alloc(r->arena, cap);
                /* load capped at buf size but account the full file size */
                soff_t got = (soff_t) read(afd, ab->base, cap);
                close(afd);
                ab->flags = SNX_IOB_MEM;
                ab->head = ab->base;
                ab->tail = ab->base + got;
                ab->next = fb;
                b = ab;
                r->out.cl_n += ast.st_size;
            }
        }
        au = snx_conf_arg(r->loc->conf, "add_after_body");
        if (au) {
            uchar *ap = snx_arena_alloc(r->arena, root->n + strlen(au) + 1);
            path.n = (size_t) (snx_fmt(ap, ap + root->n + strlen(au) + 1,
                                       "%S%s", root, au) - ap);
            path.p = ap;
            afd = open((char *) path.p, O_RDONLY);
            if (afd != -1 && fstat(afd, &ast) == 0 && S_ISREG(ast.st_mode)) {
                ab = snx_acnew(r->arena, snx_iobuf_t);
                ab->base = snx_arena_alloc(r->arena, cap);
                soff_t got = (soff_t) read(afd, ab->base, cap);
                close(afd);
                ab->flags = SNX_IOB_MEM | SNX_IOB_LAST;
                ab->head = ab->base;
                ab->tail = ab->base + got;
                fb->flags &= ~SNX_IOB_LAST;
                fb->next = ab;
                r->out.cl_n += ast.st_size;
            }
        }
    }

    if (snx_http_send_head(r) != SNX_OK) {
        close(fd);
        return SNX_ERROR;
    }

    if (r->loc->aio_on) {
        int  arc = snx_mod_aio_sendfile(r, b);
        close(fd);
        if (arc == SNX_ERROR) {
            return SNX_ERROR;
        }
        snx_http_finish(r, SNX_HTTP_OK);
        return SNX_DONE;
    }

    if (snx_http_body_stage(r, b) == SNX_ERROR) {
        close(fd);
        return SNX_ERROR;
    }

    close(fd);
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* ============ error pages ============ */

static const char *snx_err_pages[][2] = {
    { "400", "<html>\r\n<head><title>400 Bad Request</title></head>\r\n"
             "<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n" },
    { "404", "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
             "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n" },
    { NULL, NULL }
};

void
snx_http_error_page(snx_http_req_t *r, int status)
{
    uchar         *p;
    size_t         plen;
    snx_iobuf_t   *b;
    const char    *page;
    int            i;

    static const char tail[] =
        "<hr><center>" SNX_VER "</center>\r\n</body>\r\n</html>\r\n";

    page = NULL;
    for (i = 0; snx_err_pages[i][0]; i++) {
        if ((int) strtol(snx_err_pages[i][0], NULL, 10) == status) {
            page = snx_err_pages[i][1];
            break;
        }
    }
    if (page == NULL) {
        page = "<html>\r\n<head><title>Error</title></head>\r\n"
               "<body>\r\n<center><h1>Error</h1></center>\r\n";
    }

    plen = strlen(page) + sizeof(tail) - 1;

    r->out.status = status;
    r->out.cl_n = plen;

    p = snx_arena_alloc(r->arena, plen);
    memcpy(p, page, strlen(page));
    memcpy(p + strlen(page), tail, sizeof(tail) - 1);

    (void) snx_http_send_head(r);

    b = snx_acnew(r->arena, snx_iobuf_t);
    b->base = p;
    b->head = p;
    b->tail = p + plen;
    b->cap = plen;
    b->flags = SNX_IOB_MEM | SNX_IOB_LAST;

    (void) snx_http_write(r, b);
    snx_http_keepalive(r);
}

/* request teardown shared by every exit path */
static void
snx_req_close(snx_http_req_t *r)
{
    (void) snx_access_log(r);
    snx_limit_conn_done(r);
}

int
snx_http_keepalive(snx_http_req_t *r)
{
    snx_conn_t  *c = r->c;

    snx_req_close(r);

    if (!r->keepalive || r->lingering) {
        snx_conn_free(c);
        return SNX_OK;
    }

    /* an unread request body must be drained before the connection
       is reused; lingering_close off takes the conn down instead */
    if (r->in.cl_n > 0 || r->in.chunked) {
        if (snx_cfg.lingering_close) {
            snx_http_discard_body(r);
        } else {
            snx_conn_free(c);
            return SNX_OK;
        }
    }

    /* bytes pipelined past the previous request carry over */
    {
        uchar   tmp[8192];
        size_t  left = 0;

        if (r->inbuf && r->inbuf->tail > r->inbuf->head
            && (size_t) (r->inbuf->tail - r->inbuf->head) <= sizeof(tmp))
        {
            left = r->inbuf->tail - r->inbuf->head;
            memcpy(tmp, r->inbuf->head, left);
        }

        c->rev.fn = snx_http_req_read;
        snx_http_req_reset(c);

        if (left) {
            snx_http_req_t *nr = c->data;
            memcpy(nr->inbuf->tail, tmp, left);
            nr->inbuf->tail += left;
            snx_ev_later(&c->rev);
        }
    }
    return SNX_OK;
}

void
snx_http_internal_redirect(snx_http_req_t *r, snx_str_t *uri)
{
    r->uri = *uri;
    r->unparsed = *uri;
    r->internal = 1;
    r->loc = NULL;

    if (snx_http_find_loc(r) == SNX_OK) {
        snx_http_run(r);
    } else {
        snx_http_finish(r, SNX_HTTP_NOT_FOUND);
    }
}
