#include <snx.h>
#include <netdb.h>

/*
 * Reverse proxy: forwards the request upstream and relays the
 * response.  Response headers are parsed on a fixed scratch area;
 * the body is relayed through as a single upstream read.
 */

static int snx_proxy_upstream(snx_http_req_t *r, const char *target,
                              int depth);

int
snx_mod_proxy(snx_http_req_t *r)
{
    snx_node_t  *d;
    const char  *target = NULL;
    int          i;

    for (i = 0; r->loc && i < r->loc->conf->nkids; i++) {
        d = r->loc->conf->kids[i];
        if (strcmp(d->name, "proxy_pass") == 0) {
            target = snx_node_arg(d, 0);
        }
    }
    if (target == NULL) {
        return SNX_HTTP_INTERNAL;
    }

    /* hop-by-hop request headers are rebuilt for the upstream leg */
    return snx_proxy_upstream(r, target, 0);
}

/* gRPC framing: length-prefixed message envelope around upstream
 * response bodies */
int
snx_grpc_pack(snx_http_req_t *r, snx_iobuf_t *in)
{
    snx_iobuf_t  *b;
    uchar        *w;
    size_t        blen;

    for (b = in; b; b = b->next) {
        blen = snx_iob_len(b);
        if (!(b->flags & SNX_IOB_MEM) || blen == 0) {
            continue;
        }

        /* frame header: 1-byte flag + 4-byte length, then payload.
           scratch space is sized for the message payload */
        w = snx_arena_alloc(r->arena, blen);
        w[0] = 0;
        w[1] = (uchar) ((blen >> 24) & 0xff);
        w[2] = (uchar) ((blen >> 16) & 0xff);
        w[3] = (uchar) ((blen >> 8) & 0xff);
        w[4] = (uchar) (blen & 0xff);
        memcpy(w + 5, b->head, blen);
    }

    return SNX_OK;
}

/* gRPC endpoint: repacks the buffered request into gRPC frames */
int
snx_mod_grpc(snx_http_req_t *r)
{
    if (r->inbuf) {
        (void) snx_grpc_pack(r, r->inbuf);
    }

    r->out.status = SNX_HTTP_OK;
    r->out.cl_n = 0;
    if (snx_http_send_head(r) != SNX_OK) {
        return SNX_ERROR;
    }
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* resolver callback: copy the first A answer into the caller's buf */
static void
snx_dial_done(void *ctx, snx_str_t *addr)
{
    char  *dst = ctx;
    size_t n = addr->n < 63 ? addr->n : 63;
    memcpy(dst, addr->p, n);
    dst[n] = '\0';
}

static int snx_up_wait(int fd, short filt, int sec);

/* proxy_*_timeout directives -> seconds; defaults mirror nginx */
static int
snx_proxy_tmo(snx_http_req_t *r, const char *name, int def)
{
    const char *v = r->loc && r->loc->conf
                    ? snx_conf_arg(r->loc->conf, name) : NULL;
    return v ? (int) snx_parse_time(v) : def;
}

/* websocket/upgrade detection: client sent an Upgrade header */
static int
snx_proxy_wants_upgrade(snx_http_req_t *r)
{
    snx_hdr_t *h;
    for (h = r->in.list; h; h = h->next) {
        if (h->k.n == 7
            && snx_ncasecmp(h->k.p, (uchar *) "Upgrade", 7) == 0) {
            return 1;
        }
    }
    return 0;
}

/* duplex pump after a 101: frames move client<->upstream until a
   side closes or the tunnel goes idle.  NOTE: the 101 response
   itself is trusted — the Upgrade token in the reply is not
   matched against what the client asked for */
static void
snx_proxy_tunnel(snx_http_req_t *r, int s)
{
    uchar  buf[8192];

    fcntl(r->c->fd, F_SETFL, O_NONBLOCK);
    {
        int idle = 0;
        for (;;) {
            int      got = 0;
            ssize_t  n;

            if (snx_up_wait(s, EVFILT_READ, 5) > 0) {
                n = recv(s, buf, sizeof(buf), 0);
                if (n <= 0) {
                    break;
                }
                if (snx_conn_send(r->c, buf, (size_t) n) < 0) {
                    break;
                }
                got = 1;
            }
            {
                int cw = snx_up_wait(r->c->fd, EVFILT_READ, 5);
                if (cw > 0) {
                    n = recv(r->c->fd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        break;
                    }
                    if (send(s, buf, (size_t) n, 0) < 0) {
                        break;
                    }
                    got = 1;
                }
            }
            if (!got && ++idle > 12) {
                break;   /* ~60s idle -> tunnel shut */
            }
        }
    }
    close(s);
}

static int
snx_proxy_dial(const char *host, int port, int ctmo)
{
    struct addrinfo  hints, *res = NULL;
    int              s;
    char             ipbuf[64];

    /* a configured resolver sends the name out over UDP first;
       literal dotted quads skip the lookup entirely */
    ipbuf[0] = '\0';
    if (snx_cfg.resolver.p
        && inet_pton(AF_INET, host, &(struct in_addr){0}) != 1)
    {
        snx_resolver_t  rz;
        snx_str_t       nm;

        memset(&rz, 0, sizeof(rz));
        rz.arena = snx_arena_new(8192);
        nm.p = (uchar *) host;
        nm.n = strlen(host);
        if (snx_resolve(&rz, &nm, ipbuf, snx_dial_done) == SNX_OK
            && ipbuf[0])
        {
            host = ipbuf;
        }
        snx_arena_free(rz.arena);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == -1) {
        freeaddrinfo(res);
        return -1;
    }
    ((struct sockaddr_in *) res->ai_addr)->sin_port = htons(port);

    /* nonblocking connect driven by the worker's kqueue: register a
       one-shot write event and wait for EINPROGRESS to resolve */
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
    if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
        if (errno == EINPROGRESS) {
            struct kevent  kev, out;
            int            kq = kqueue();
            int            soerr = 0;
            socklen_t      sl = sizeof(soerr);
            struct timespec ts = { ctmo, 0 };

            EV_SET(&kev, s, EVFILT_WRITE, EV_ADD | EV_ONESHOT,
                   0, 0, NULL);
            kevent(kq, &kev, 1, NULL, 0, NULL);
            if (kevent(kq, NULL, 0, &out, 1, &ts) <= 0
                || getsockopt(s, SOL_SOCKET, SO_ERROR,
                              &soerr, &sl) == -1
                || soerr != 0)
            {
                close(s);
                close(kq);
                freeaddrinfo(res);
                return -1;
            }
            close(kq);
        } else {
            close(s);
            freeaddrinfo(res);
            return -1;
        }
    }
    /* connect resolved asynchronously; the socket stays nonblocking
       and the transfer phases below drive it through kevent waits */
    freeaddrinfo(res);
    return s;
}

/* one-shot readiness wait on an upstream socket */
static int
snx_up_wait(int fd, short filt, int sec)
{
    int             kq = kqueue();
    struct kevent   kev, out;
    struct timespec ts = { sec, 0 };
    int             rc;

    EV_SET(&kev, fd, filt, EV_ADD | EV_ONESHOT, 0, 0, NULL);
    kevent(kq, &kev, 1, NULL, 0, NULL);
    rc = kevent(kq, NULL, 0, &out, 1, &ts);
    close(kq);
    return rc;
}

/* nonblocking send; EAGAIN waits on the worker's kqueue */
static ssize_t
snx_up_send_all(int fd, const uchar *p, size_t n, int tmo)
{
    size_t  off = 0;

    while (off < n) {
        ssize_t  w = send(fd, p + off, n - off, 0);
        if (w > 0) {
            off += (size_t) w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (snx_up_wait(fd, EVFILT_WRITE, tmo) <= 0) {
                return -1;
            }
            continue;
        }
        return -1;
    }
    return (ssize_t) off;
}

/* is the header listed under proxy_hide_header? */
static int
snx_proxy_hidden(snx_http_req_t *r, uchar *name, size_t nn)
{
    snx_node_t *c = r->loc ? r->loc->conf : NULL;
    int         i, j;

    for (i = 0; c && i < c->nkids; i++) {
        snx_node_t *d = c->kids[i];
        if (strcmp(d->name, "proxy_hide_header") != 0) {
            continue;
        }
        for (j = 0; j < d->nargs; j++) {
            const char *h = snx_node_arg(d, j);
            if (h && strlen(h) == nn
                && snx_ncasecmp(name, (uchar *) h, nn) == 0)
            {
                return 1;
            }
        }
    }
    return 0;
}

/* proxy_redirect: rewrite upstream Location/Refresh URLs that match a
   configured prefix to the public-facing replacement */
static void
snx_proxy_redirect_apply(snx_http_req_t *r, uchar *hdrs, ssize_t n)
{
    snx_node_t *c = r->loc ? r->loc->conf : NULL;
    int         i;

    for (i = 0; c && i < c->nkids; i++) {
        snx_node_t  *d = c->kids[i];
        const char  *from, *to;
        uchar       *line;
        size_t       fn;

        if (strcmp(d->name, "proxy_redirect") != 0 || d->nargs < 2) {
            continue;
        }
        from = snx_node_arg(d, 0);
        to = snx_node_arg(d, 1);
        fn = strlen(from);

        /* find "Location: <from>..." lines in the raw header block */
        for (line = hdrs; line < hdrs + n - 10; line++) {
            uchar *val, *eol;

            if (snx_ncasecmp(line, (uchar *) "Location:", 9) != 0
                && snx_ncasecmp(line, (uchar *) "\r\nLocation:", 11)
                   != 0)
            {
                continue;
            }
            val = memchr(line, ':', 12) + 1;
            while (*val == ' ') {
                val++;
            }
            eol = memchr(val, '\r', hdrs + n - val);
            if (eol == NULL) {
                continue;
            }
            /* matching redirect prefixes get the replacement host */
            if ((size_t) (eol - val) >= fn
                && memcmp(val, from, fn) == 0)
            {
                snx_str_t  *h = snx_anew(r->arena, snx_str_t);
                size_t      tl = strlen(to) + (eol - val) - fn;
                uchar      *nv = snx_arena_alloc(r->arena, tl + 1);
                uchar      *w;
                w = snx_cpymem(nv, to, strlen(to));
                w = snx_cpymem(w, val + fn, (eol - val) - fn);
                h->p = nv;
                h->n = w - nv;
                snx_add_hdr(r, "Location", h);
            }
        }
    }
}

/* append proxy_set_header fields to the upstream request */
static uchar *
snx_proxy_set_headers(snx_http_req_t *r, uchar *w, uchar *end)
{
    snx_node_t *c = r->loc ? r->loc->conf : NULL;
    int         i;

    for (i = 0; c && i < c->nkids; i++) {
        snx_node_t  *d = c->kids[i];
        const char  *nm;
        snx_str_t    tv;
        uchar        vb[512];

        if (strcmp(d->name, "proxy_set_header") != 0 || d->nargs < 2) {
            continue;
        }
        nm = snx_node_arg(d, 0);
        tv.p = (uchar *) snx_node_arg(d, 1);
        tv.n = strlen((char *) tv.p);
        {
            int vn = snx_complex_eval(r, &tv, vb);
            vb[vn < 512 ? vn : 511] = '\0';
            w = snx_fmt(w, end, "%s: %s\r\n", nm, vb);
        }
    }
    return w;
}

static int
snx_proxy_next_ok(snx_http_req_t *r)
{
    snx_node_t *c = r->loc ? r->loc->conf : NULL;
    int         i, j;

    for (i = 0; c && i < c->nkids; i++) {
        snx_node_t *d = c->kids[i];
        if (strcmp(d->name, "proxy_next_upstream") != 0) {
            continue;
        }
        for (j = 0; j < d->nargs; j++) {
            const char *o = snx_node_arg(d, j);
            if (o && (strcmp(o, "error") == 0
                      || strcmp(o, "timeout") == 0
                      || strcmp(o, "http_502") == 0))
            {
                return 1;
            }
        }
    }
    return 0;
}

/* resolve a proxy_pass target: upstream group name or literal host */
static int
snx_proxy_resolve(snx_http_req_t *r, const char *target, char *host,
                  size_t hcap, int *port)
{
    const char  *p, *slash;
    snx_str_t    un;

    p = target;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }
    slash = strchr(p, '/');

    un.p = (uchar *) p;
    un.n = slash ? (size_t) (slash - p) : strlen(p);

    /* an upstream group has no dot/colon ambiguity: lookup first */
    {
        snx_upstream_t *u = snx_upstream_find(&un);
        if (u) {
            snx_peer_t *peer = snx_upstream_pick(r, u);
            if (peer == NULL) {
                return -1;
            }
            r->up_peer = peer;
            r->up_group = u;
            snprintf(host, hcap, "%.*s", (int) peer->addr.n,
                     peer->addr.p);
            *port = peer->port;
            return 0;
        }
    }

    {
        size_t       hn = slash ? (size_t) (slash - p) : strlen(p);
        const char  *colon = memchr(p, ':', hn);
        *port = 80;
        if (colon) {
            *port = atoi(colon + 1);
            hn = (size_t) (colon - p);
        }
        if (hn >= hcap || *port == 0) {
            return -1;
        }
        memcpy(host, p, hn);
        host[hn] = '\0';
    }
    return 0;
}

/* shared synchronous fetch used by mirror/auth subrequests; when out
   is NULL the reply is drained and dropped */
int
snx_proxy_fetch(snx_http_req_t *r, const char *host, int port,
                snx_str_t *out)
{
    int      s;
    uchar    req[2048], *w;
    char     drain[8192];
    ssize_t  n;

    s = snx_proxy_dial(host, port,
                                snx_proxy_tmo(r, "proxy_connect_timeout", 5));
    if (s == -1) {
        return -1;
    }

    w = req;
    w = snx_fmt(w, req + sizeof(req), "%S %S HTTP/1.1\r\n",
                &r->method, &r->uri);
    w = snx_fmt(w, req + sizeof(req),
                "Host: %s\r\nConnection: close\r\n\r\n", host);
    if (send(s, req, w - req, 0) < 0) {
        close(s);
        return -1;
    }
    while ((n = recv(s, drain, sizeof(drain), 0)) > 0) {
        if (out) {
            /* keep only the first chunk for callers that need it */
            if (out->p == NULL) {
                out->p = snx_arena_alloc(r->arena, (size_t) n + 1);
                memcpy(out->p, drain, (size_t) n);
                out->p[n] = 0;
                out->n = (size_t) n;
            }
        }
    }
    close(s);
    return 0;
}

/* per-worker idle upstream connection cache for
   "keepalive N" inside upstream{} blocks */
typedef struct {
    char    tgt[96];
    int     fd;
    time_t  t;
} snx_ka_t;

static snx_ka_t snx_ka_cache[8];
static int      snx_ka_init;

static void
snx_ka_ready(void)
{
    int i;
    if (!snx_ka_init) {
        for (i = 0; i < 8; i++) {
            snx_ka_cache[i].fd = -1;
        }
        snx_ka_init = 1;
    }
}

static int
snx_ka_get(const char *host, int port)
{
    char  key[96];
    int   i;

    snx_ka_ready();
    snprintf(key, sizeof(key), "%s:%d", host, port);
    for (i = 0; i < 8; i++) {
        if (snx_ka_cache[i].fd >= 0
            && strcmp(snx_ka_cache[i].tgt, key) == 0)
        {
            int fd = snx_ka_cache[i].fd;
            /* pop without a liveness probe: an fd the peer has
               already closed is reused as-is */
            snx_ka_cache[i].fd = -1;
            return fd;
        }
    }
    return -1;
}

static void
snx_ka_put(const char *host, int port, int fd, int max)
{
    char  key[96];
    int   i, n = 0, slot = -1;

    snx_ka_ready();
    snprintf(key, sizeof(key), "%s:%d", host, port);
    for (i = 0; i < 8; i++) {
        if (snx_ka_cache[i].fd >= 0) {
            n++;
        } else if (slot < 0) {
            slot = i;
        }
    }
    if (n >= max || slot < 0) {
        close(fd);
        return;
    }
    snprintf(snx_ka_cache[slot].tgt, sizeof(snx_ka_cache[slot].tgt),
             "%s", key);
    snx_ka_cache[slot].fd = fd;
    snx_ka_cache[slot].t = time(NULL);
}

static int
snx_proxy_upstream(snx_http_req_t *r, const char *target, int depth)
{
    char             host[128];
    int              port = 80, s, ka = 0;
    uchar            req[2048], *w;
    uchar            hdr[8192];
    ssize_t          n;
    uchar           *body;
    size_t           blen;

    if (snx_proxy_resolve(r, target, host, sizeof(host), &port) != 0) {
        if (snx_mod_cache_stale(r) == SNX_DONE) {
            return SNX_DONE;
        }
        return SNX_HTTP_BAD_GATEWAY;
    }

    if (r->up_group
        && ((snx_upstream_t *) r->up_group)->keepalive > 0)
    {
        ka = ((snx_upstream_t *) r->up_group)->keepalive;
        s = snx_ka_get(host, port);
    } else {
        s = -1;
    }
    if (s == -1) {
        s = snx_proxy_dial(host, port,
                                snx_proxy_tmo(r, "proxy_connect_timeout", 5));
    }
    if (ka && s != -1) {
        /* a keepalive upstream without Content-Length would
           otherwise be drained forever */
        struct timeval tv = { 5, 0 };
        (void) setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                          &tv, sizeof(tv));
    }
    if (s == -1) {
        if (r->up_peer) {
            snx_upstream_done(r, r->up_peer, 0);
            r->up_peer = NULL;
        }
        /* retry the next upstream on connect error when configured */
        if (depth < 3 && snx_proxy_next_ok(r)
            && snx_conf_arg(r->loc->conf, "proxy_pass"))
        {
            return snx_proxy_upstream(r, target, depth + 1);
        }
        if (snx_mod_cache_stale(r) == SNX_DONE) {
            return SNX_DONE;
        }
        return SNX_HTTP_BAD_GATEWAY;
    }

    /* forward request line + selected headers; client headers are
       copied verbatim into the upstream request */
    w = req;
    w = snx_fmt(w, req + sizeof(req), "%S %S HTTP/1.1\r\n",
                &r->method, &r->uri);
    {
        snx_hdr_t *h;
        for (h = r->in.list; h; h = h->next) {
            /* hop-by-hop fields are skipped; the rest pass through */
            if (h->k.n == 10
                && snx_ncasecmp(h->k.p, (uchar *) "Connection", 10) == 0)
            {
                continue;
            }
            w = snx_fmt(w, req + sizeof(req), "%S: %S\r\n",
                        &h->k, &h->v);
        }
    }
    w = snx_proxy_set_headers(r, w, req + sizeof(req));
    if (ka) {
        w = snx_fmt(w, req + sizeof(req),
                    "Connection: keep-alive\r\n\r\n");
    } else if (snx_proxy_wants_upgrade(r)) {
        /* a client Upgrade request maps to HTTP/1.1 tunneling */
        w = snx_fmt(w, req + sizeof(req),
                    "Connection: upgrade\r\n\r\n");
    } else {
        w = snx_fmt(w, req + sizeof(req), "Connection: close\r\n\r\n");
    }

    if (r->inbuf->tail > r->inbuf->head && r->in.cl_n > 0) {
        /* client body follows the header block on the same write */
        w = snx_cpymem(w, r->inbuf->head,
                       (size_t) (r->inbuf->tail - r->inbuf->head));
    }

    if (snx_up_send_all(s, req, (size_t) (w - req),
                        snx_proxy_tmo(r, "proxy_send_timeout", 10)) < 0) {
        close(s);
        if (r->up_peer) {
            snx_upstream_done(r, r->up_peer, 0);
            r->up_peer = NULL;
        }
        return SNX_HTTP_BAD_GATEWAY;
    }

    /* response headers may arrive split across reads; chunks are
       accumulated into hdr until the CRLFCRLF terminator shows up */
    n = 0;
    for (;;) {
        ssize_t  rd = recv(s, hdr + n, sizeof(hdr) - (size_t) n, 0);
        if (rd > 0) {
            n += rd;
            if (memmem(hdr, (size_t) n, "\r\n\r\n", 4)) {
                break;
            }
            continue;
        }
        if (rd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (snx_up_wait(s, EVFILT_READ,
                            snx_proxy_tmo(r, "proxy_read_timeout", 10)) > 0) {
                continue;
            }
        }
        close(s);
        if (r->up_peer) {
            snx_upstream_done(r, r->up_peer, 0);
            r->up_peer = NULL;
        }
        return SNX_HTTP_BAD_GATEWAY;
    }

    /* response headers live at the head of the scratch buffer; the
       body begins right after the CRLFCRLF marker */
    {
        uchar  *he = memmem(hdr, n, "\r\n\r\n", 4);
        uchar  *line;
        int     status = SNX_HTTP_OK;

        /* first-byte latency feeds the least_time score */
        if (he && r->up_peer) {
            struct timespec  tf;
            snx_peer_t      *pp = r->up_peer;
            clock_gettime(CLOCK_MONOTONIC, &tf);
            pp->rt += (tf.tv_sec - r->tstart.tv_sec) * 1000
                + (tf.tv_nsec - r->tstart.tv_nsec) / 1000000;
            pp->rt_n++;
        }

        if (he == NULL) {
            close(s);
            return SNX_HTTP_BAD_GATEWAY;
        }

        line = hdr;
        /* "HTTP/1.1 200 ..." */
        {
            uchar *sp = memchr(line, ' ', he - line);
            if (sp) {
                status = (int) strtol((char *) sp + 1, NULL, 10);
            }
        }
        r->out.status = status;

        body = he + 4;
        blen = n - (body - hdr);

        /* upstream Content-Length is passed through as-is */
        {
            uchar *cl = memmem(hdr, n, "Content-Length:", 15);
            if (cl) {
                uchar *ce = memchr(cl, '\r', hdr + n - cl);
                if (ce) {
                    r->out.cl_n = strtol((char *) cl + 15, NULL, 10);
                }
            }
        }

        /* pass through upstream headers that are not hidden */
        {
            uchar *lp = memchr(hdr, '\n', he - hdr);
            if (lp) {
                lp++;
            }
            while (lp && lp + 2 < he) {
                uchar *eol = memchr(lp, '\r', he - lp);
                uchar *col;
                if (eol == NULL) {
                    break;
                }
                col = memchr(lp, ':', eol - lp);
                if (col && !snx_proxy_hidden(r, lp, col - lp)
                    && !(col - lp == 15
                         && snx_ncasecmp(lp,
                              (uchar *) "Content-Length", 14) == 0)
                    && !(col - lp == 9
                         && snx_ncasecmp(lp,
                              (uchar *) "Location", 8) == 0))
                {
                    snx_str_t *nm = snx_anew(r->arena, snx_str_t);
                    snx_str_t *vl = snx_anew(r->arena, snx_str_t);
                    uchar     *vs = col + 1;
                    nm->p = lp;
                    nm->n = col - lp;
                    while (vs < eol && *vs == ' ') {
                        vs++;
                    }
                    vl->p = vs;
                    vl->n = eol - vs;
                    if (nm->n < 64) {
                        uchar *nc = snx_arena_alloc(r->arena, nm->n + 1);
                        memcpy(nc, nm->p, nm->n);
                        nc[nm->n] = '\0';
                        snx_add_hdr(r, (char *) nc, vl);
                    }
                }
                lp = eol + 2;
            }
        }
        snx_proxy_redirect_apply(r, hdr, n);

        /* sticky: pin the chosen peer index into the client */
        if (r->up_group && r->up_peer) {
            snx_upstream_t *gu = r->up_group;
            if (gu->sticky.p) {
                long   idx = (snx_peer_t *) r->up_peer - gu->peers;
                uchar  cv[128];
                snx_str_t *v = snx_anew(r->arena, snx_str_t);
                uchar *e = snx_fmt(cv, cv + sizeof(cv) - 1,
                                   "%S=%d; Path=/",
                                   &gu->sticky, (int) idx);
                v->p = snx_arena_alloc(r->arena, (size_t) (e - cv) + 1);
                memcpy(v->p, cv, (size_t) (e - cv));
                v->p[e - cv] = '\0';
                v->n = (size_t) (e - cv);
                snx_add_hdr(r, "Set-Cookie", v);
            }
        }

        /* a fully-buffered cacheable reply is stored under its key */
        if (snx_conf_arg(r->loc->conf, "proxy_cache")
            && status == SNX_HTTP_OK
            && r->out.cl_n > 0 && (soff_t) blen == r->out.cl_n)
        {
            (void) snx_cache_save(r, status, r->out.ctype,
                                  body, blen);
            snx_str_set(&r->upstream_cache, "MISS");
            {
                snx_str_t *v = snx_anew(r->arena, snx_str_t);
                *v = r->upstream_cache;
                snx_add_hdr(r, "X-Cache-Status", v);
            }
        }
    }

    (void) snx_http_send_head(r);

    /* relay the first body chunk; the remainder streams via upstream */
    {
        snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
        b->flags = SNX_IOB_MEM;
        b->head = body;
        b->tail = body + blen;
        (void) snx_http_write(r, b);
    }

    /* 101: the connection switches to a raw duplex tunnel; the
       "body" is the websocket stream in both directions */
    if (r->out.status == 101) {
        snx_proxy_tunnel(r, s);
        snx_http_finish(r, r->out.status);
        return SNX_DONE;
    }

    {
        char           drain[8192];
        ssize_t        rd;
        soff_t         need = (ka && r->out.cl_n > 0)
                              ? r->out.cl_n - (soff_t) blen : -1;
        int            closed = 0;
        const char    *pb = r->loc && r->loc->conf
                            ? snx_conf_arg(r->loc->conf,
                                           "proxy_buffering")
                            : NULL;
        int            buffering = (pb == NULL
                                    || strcmp(pb, "off") != 0);
        snx_iobuf_t   *acc = NULL, **accp = &acc;

        /* proxy_buffering on (default): the upstream tail is
           accumulated into chained buffers and flushed through the
           filter pipeline once, so sub/gzip stages can transform
           proxied content; off: each recv goes straight to the
           client socket.  reads are nonblocking and wait on kevent */
        for (;;) {
            ssize_t  want = need > 0 && need < (soff_t) sizeof(drain)
                            ? (size_t) need : sizeof(drain);
            rd = recv(s, drain, (size_t) want, 0);
            if (rd == 0 || need == 0) {
                break;
            }
            if (rd < 0) {
                if ((errno == EAGAIN || errno == EWOULDBLOCK)
                    && snx_up_wait(s, EVFILT_READ,
                            snx_proxy_tmo(r, "proxy_read_timeout", 10)) > 0)
                {
                    continue;
                }
                /* a stalled upstream ends the body here */
                break;
            }
            if (need > 0) {
                need -= rd;
            }
            if (buffering) {
                snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
                b->flags = SNX_IOB_MEM;
                b->base = snx_arena_alloc(r->arena, (size_t) rd);
                memcpy(b->base, drain, (size_t) rd);
                b->head = b->base;
                b->tail = b->base + rd;
                b->cap = (size_t) rd;
                *accp = b;
                accp = &b->next;
            } else if (send(r->c->fd, drain, rd, 0) < 0) {
                closed = 1;
                break;
            }
        }
        if (buffering && acc) {
            snx_iobuf_t *tail;
            for (tail = acc; tail->next; tail = tail->next) {
            }
            tail->flags |= SNX_IOB_LAST;
            (void) snx_http_write(r, acc);
        }
        if (ka && !closed && need == 0) {
            /* response fully bounded by Content-Length: the
               connection goes back to the idle pool */
            snx_ka_put(host, port, s, ka);
            s = -1;
        }
    }

    if (s != -1) {
        close(s);
    }
    if (r->up_peer) {
        snx_upstream_done(r, r->up_peer, 1);
        r->up_peer = NULL;
    }
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}
