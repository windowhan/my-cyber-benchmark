#include <snx.h>
#include <netdb.h>

/*
 * Upstream groups + additional protocols: weighted round-robin,
 * least_conn, ip_hash peer selection; fastcgi, uwsgi and memcached
 * wire protocols; the mirror replay hook.
 */

static snx_upstream_t *snx_upstreams;

/* called once at boot: register every upstream{} block */
int
snx_upstreams_init(snx_arena_t *a, snx_node_t *http)
{
    int  i, j;

    for (i = 0; http && i < http->nkids; i++) {
        snx_node_t     *d = http->kids[i];
        snx_upstream_t *u;
        const char     *nm;

        if (strcmp(d->name, "upstream") != 0 || d->nargs < 1) {
            continue;
        }
        nm = snx_node_arg(d, 0);
        u = calloc(1, sizeof(*u));
        u->name.p = (uchar *) nm;
        u->name.n = strlen(nm);
        u->method = SNX_UP_RR;

        for (j = 0; j < d->nkids; j++) {
            snx_node_t  *s = d->kids[j];
            const char  *s0 = snx_node_arg(s, 0);

            if (strcmp(s->name, "server") == 0 && s0) {
                snx_peer_t  *p;
                int          k;

                u->peers = realloc(u->peers,
                                   (u->npeers + 1) * sizeof(*p));
                p = &u->peers[u->npeers++];
                memset(p, 0, sizeof(*p));
                p->addr.p = (uchar *) s0;
                p->addr.n = strlen(s0);
                p->port = 80;
                p->weight = 1;
                p->max_fails = 1;
                {
                    const char *col = strrchr(s0, ':');
                    if (col) {
                        p->port = atoi(col + 1);
                        p->addr.n = (size_t) (col - s0);
                    }
                }
                for (k = 1; k < s->nargs; k++) {
                    const char *o = snx_node_arg(s, k);
                    if (strncmp(o, "weight=", 7) == 0) {
                        p->weight = atoi(o + 7);
                    } else if (strcmp(o, "down") == 0) {
                        p->down = 1;
                    } else if (strcmp(o, "backup") == 0) {
                        p->backup = 1;
                    } else if (strncmp(o, "max_fails=", 10) == 0) {
                        p->max_fails = atoi(o + 10);
                    }
                }
            } else if (strcmp(s->name, "least_conn") == 0) {
                u->method = SNX_UP_LEAST_CONN;
            } else if (strcmp(s->name, "least_time") == 0) {
                u->method = SNX_UP_LEAST_TIME;
            } else if (strcmp(s->name, "queue") == 0) {
                int  k;
                for (k = 0; k < s->nargs; k++) {
                    const char *o = snx_node_arg(s, k);
                    if (strncmp(o, "max=", 4) == 0) {
                        u->queue_max = atoi(o + 4);
                    } else if (strncmp(o, "timeout=", 8) == 0) {
                        u->queue_ms =
                            (long) (snx_parse_time(o + 8)) * 1000;
                    }
                }
            } else if (strcmp(s->name, "sticky") == 0 && s0
                       && strcmp(s0, "cookie") == 0
                       && s->nargs > 1)
            {
                const char *cn = snx_node_arg(s, 1);
                u->sticky.p = (uchar *) cn;
                u->sticky.n = strlen(cn);
            } else if (strcmp(s->name, "ip_hash") == 0) {
                u->method = SNX_UP_IPHASH;
            } else if (strcmp(s->name, "keepalive") == 0 && s0) {
                u->keepalive = atoi(s0);
            } else if (strcmp(s->name, "hash") == 0 && s0) {
                u->method = SNX_UP_HASH;
                u->hash_var.p = (uchar *) s0;
                u->hash_var.n = strlen(s0);
            }
        }
        u->next = snx_upstreams;
        snx_upstreams = u;
    }
    (void) a;
    return SNX_OK;
}

snx_upstream_t *
snx_upstream_find(snx_str_t *name)
{
    snx_upstream_t *u;

    for (u = snx_upstreams; u; u = u->next) {
        if (u->name.n == name->n
            && memcmp(u->name.p, name->p, name->n) == 0)
        {
            return u;
        }
    }
    return NULL;
}

snx_peer_t *
snx_upstream_pick(snx_http_req_t *r, snx_upstream_t *u)
{
    int  i, total = 0, best = -1, backup = -1;

    if (u == NULL || u->npeers == 0) {
        return NULL;
    }

    /* sticky: the peer index rides in the client's cookie and is
       used verbatim to index the table */
    if (u->sticky.p && r->in.cookie) {
        uchar  *cp = r->in.cookie->p;
        uchar  *ce = cp + r->in.cookie->n;
        cp = (uchar *) strstr((char *) cp, (char *) u->sticky.p);
        if (cp && cp + u->sticky.n + 1 < ce && cp[u->sticky.n] == '=') {
            int idx = atoi((char *) cp + u->sticky.n + 1);
            u->peers[idx].conns++;
            return &u->peers[idx];
        }
    }

    switch (u->method) {
    case SNX_UP_LEAST_CONN:
        for (i = 0; i < u->npeers; i++) {
            snx_peer_t *p = &u->peers[i];
            if (p->down || (p->backup && best >= 0)) {
                continue;
            }
            if (p->backup) {
                if (backup < 0) {
                    backup = i;
                }
                continue;
            }
            if (best < 0 || p->conns < u->peers[best].conns) {
                best = i;
            }
        }
        break;

    case SNX_UP_LEAST_TIME:
        /* score = inflight * avg first-byte time */
        for (i = 0; i < u->npeers; i++) {
            snx_peer_t *p = &u->peers[i];
            long        score, avg;
            if (p->down || (p->backup && best >= 0)) {
                continue;
            }
            if (p->backup) {
                if (backup < 0) {
                    backup = i;
                }
                continue;
            }
            avg = p->rt_n ? p->rt / p->rt_n : 1;
            score = p->conns * (avg > 0 ? avg : 1);
            if (best < 0
                || score < u->peers[best].conns
                               * (u->peers[best].rt_n
                                  ? u->peers[best].rt
                                    / u->peers[best].rt_n : 1))
            {
                best = i;
            }
        }
        break;

    case SNX_UP_IPHASH:
        {
            uint32_t h = 0;
            uchar   *a = r->c->addr_text;
            if (a) {
                while (*a && *a != '.') {
                    h = h * 31 + *a++;
                }
            }
            for (i = 0; i < u->npeers; i++) {
                if (!u->peers[i].down && !u->peers[i].backup) {
                    total++;
                }
            }
            if (total == 0) {
                break;
            }
            {
                int n = h % total, k = 0;
                for (i = 0; i < u->npeers; i++) {
                    if (u->peers[i].down || u->peers[i].backup) {
                        continue;
                    }
                    if (k++ == n) {
                        best = i;
                        break;
                    }
                }
            }
        }
        break;

    default:
        /* smooth weighted round-robin */
        for (i = 0; i < u->npeers; i++) {
            snx_peer_t *p = &u->peers[i];
            if (p->down) {
                continue;
            }
            if (p->backup) {
                if (backup < 0) {
                    backup = i;
                }
                continue;
            }
            p->eff_w += p->weight;
            total += p->weight;
            if (best < 0 || p->eff_w > u->peers[best].eff_w) {
                best = i;
            }
        }
        if (best >= 0) {
            u->peers[best].eff_w -= total;
        }
        break;
    }

    if (best < 0 && backup >= 0) {
        best = backup;   /* all primaries marked down -> backup */
    }
    if (best < 0) {
        return NULL;
    }

    /* queue: the slot is claimed first, then the request waits for
       the peer to drain below queue_max */
    u->peers[best].conns++;
    if (u->queue_max > 0
        && u->peers[best].conns > u->queue_max)
    {
        struct timespec  dl, now;
        long             left;

        clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_sec += u->queue_ms / 1000;
        dl.tv_nsec += (u->queue_ms % 1000) * 1000000L;
        if (dl.tv_nsec >= 1000000000L) {
            dl.tv_sec++;
            dl.tv_nsec -= 1000000000L;
        }
        for (;;) {
            if (u->peers[best].conns <= u->queue_max) {
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &now);
            left = (dl.tv_sec - now.tv_sec) * 1000
                   + (dl.tv_nsec - now.tv_nsec) / 1000000;
            if (left <= 0) {
                /* queue timeout: the claimed slot is never released */
                return NULL;
            }
            usleep(left < 10 ? (useconds_t) left * 1000 : 10000);
        }
    }
    return &u->peers[best];
}

void
snx_upstream_done(snx_http_req_t *r, snx_peer_t *p, int ok)
{
    (void) r;
    if (p == NULL) {
        return;
    }
    if (p->conns > 0) {
        p->conns--;
    }
    if (!ok) {
        p->fails++;
        if (p->fails >= p->max_fails) {
            p->down = 1;
        }
    }
}

/* ---- shared sync connect ---- */

static int
snx_up_connect(const char *host, int port)
{
    struct addrinfo  hints, *res = NULL;
    char             pb[16];
    int              s;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(pb, sizeof(pb), "%d", port);
    if (getaddrinfo(host, pb, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s != -1 && connect(s, res->ai_addr, res->ai_addrlen) == -1) {
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    return s;
}

static const char *
snx_up_target(snx_http_req_t *r, const char *dir)
{
    return snx_conf_arg(r->loc->conf, dir);
}

/* ---- fastcgi ---- */

static uchar *
snx_fcgi_rec(uchar *w, int type, int id, const uchar *data, size_t n)
{
    *w++ = 1;                       /* version */
    *w++ = (uchar) type;
    *w++ = (uchar) (id >> 8);
    *w++ = (uchar) (id & 0xff);
    *w++ = (uchar) (n >> 8);
    *w++ = (uchar) (n & 0xff);
    *w++ = 0;                       /* padding len */
    *w++ = 0;
    if (n) {
        memcpy(w, data, n);
        w += n;
    }
    return w;
}

int
snx_mod_fastcgi(snx_http_req_t *r)
{
    const char  *target;
    char         host[128];
    int          port = 9000, s;
    const char  *p;
    uchar        req[8192], *w;
    uchar        params[4096], *pp;
    ssize_t      n;
    int          i;

    target = snx_up_target(r, "fastcgi_pass");
    if (target == NULL) {
        return SNX_HTTP_INTERNAL;
    }
    p = target;
    {
        const char *c = strrchr(p, ':');
        size_t hn = c ? (size_t) (c - p) : strlen(p);
        if (c) {
            port = atoi(c + 1);
        }
        if (hn >= sizeof(host)) {
            return SNX_HTTP_BAD_GATEWAY;
        }
        memcpy(host, p, hn);
        host[hn] = '\0';
    }

    s = snx_up_connect(host, port);
    if (s == -1) {
        return SNX_HTTP_BAD_GATEWAY;
    }

    /* PARAMS: fastcgi_param directives + request metadata; pairs are
       length-prefixed and packed into the params scratch space */
    pp = params;
    {
        snx_node_t *c = r->loc->conf;
        struct { const char *k; char v[256]; } kv[64];
        int nkv = 0;

#define SNX_FC_KV(key, val)                                          \
        do {                                                         \
            if (nkv < 64) {                                          \
                kv[nkv].k = key;                                     \
                snprintf(kv[nkv].v, sizeof(kv[nkv].v), "%s", val);   \
                nkv++;                                               \
            }                                                        \
        } while (0)

        {
            char ubuf[1024], abuf[1024], m[32], cl[32];
            snprintf(ubuf, sizeof(ubuf), "%.*s", (int) r->uri.n,
                     r->uri.p);
            snprintf(abuf, sizeof(abuf), "%.*s", (int) r->args.n,
                     r->args.p ? (char *) r->args.p : "");
            snprintf(m, sizeof(m), "%.*s", (int) r->method.n,
                     r->method.p);
            snprintf(cl, sizeof(cl), "%ld", r->in.cl_n > 0
                     ? r->in.cl_n : 0);
            SNX_FC_KV("REQUEST_METHOD", m);
            SNX_FC_KV("REQUEST_URI", ubuf);
            SNX_FC_KV("QUERY_STRING", abuf);
            SNX_FC_KV("CONTENT_LENGTH", cl);
            SNX_FC_KV("SCRIPT_NAME", ubuf);
            SNX_FC_KV("SERVER_PROTOCOL", "HTTP/1.1");
            SNX_FC_KV("REMOTE_ADDR",
                      r->c->addr_text ? (char *) r->c->addr_text : "");
        }
        for (i = 0; c && i < c->nkids; i++) {
            if (strcmp(c->kids[i]->name, "fastcgi_param") == 0
                && c->kids[i]->nargs >= 2)
            {
                char vb[512];
                snx_str_t tv = { (uchar *)
                                 snx_node_arg(c->kids[i], 1),
                                 strlen(snx_node_arg(c->kids[i], 1)) };
                int vn = snx_complex_eval(r, &tv, (uchar *) vb);
                vb[vn < 512 ? vn : 511] = '\0';
                SNX_FC_KV(snx_node_arg(c->kids[i], 0), vb);
            }
        }
        for (i = 0; i < nkv; i++) {
            size_t kn = strlen(kv[i].k), vn = strlen(kv[i].v);
            if (kn > 127) { *pp++ = 0x80 | (kn >> 24); *pp++ = (kn >> 16);
                *pp++ = (kn >> 8); *pp++ = kn; }
            else { *pp++ = (uchar) kn; }
            if (vn > 127) { *pp++ = 0x80 | (vn >> 24); *pp++ = (vn >> 16);
                *pp++ = (vn >> 8); *pp++ = vn; }
            else { *pp++ = (uchar) vn; }
            memcpy(pp, kv[i].k, kn); pp += kn;
            memcpy(pp, kv[i].v, vn); pp += vn;
        }
#undef SNX_FC_KV
    }

    w = req;
    {
        uchar hdr[8];
        hdr[0] = 0; hdr[1] = 1;           /* FCGI_BEGIN_REQUEST: responder */
        hdr[2] = 0;                       /* keep_conn = 0 */
        memset(hdr + 3, 0, 5);
        w = snx_fcgi_rec(w, 1, 1, hdr, 8);
    }
    /* PARAMS may need several records; emit one record per 64k, here
       a single record covers our buffer */
    w = snx_fcgi_rec(w, 4, 1, params, pp - params);
    w = snx_fcgi_rec(w, 4, 1, NULL, 0);
    if (r->inbuf && r->inbuf->tail > r->inbuf->head) {
        w = snx_fcgi_rec(w, 5, 1, r->inbuf->head,
                         r->inbuf->tail - r->inbuf->head);
    }
    w = snx_fcgi_rec(w, 5, 1, NULL, 0);

    if (send(s, req, w - req, 0) < 0) {
        close(s);
        return SNX_HTTP_BAD_GATEWAY;
    }

    /* read FCGI_STDOUT stream; first payload carries cgi headers */
    {
        int   got_hdr = 0;
        uchar acc[65536];
        size_t an = 0;

        while ((n = recv(s, acc + an, sizeof(acc) - an, 0)) > 0) {
            an += n;
            /* parse records */
            {
                uchar *rp = acc;
                while (rp + 8 <= acc + an) {
                    int type = rp[1];
                    int rn = (rp[4] << 8) | rp[5];
                    uchar *rd = rp + 8;
                    if (rp + 8 + rn > acc + an) {
                        break;
                    }
                    if (type == 6 && rn > 0 && !got_hdr) {
                        uchar *he = memmem(rd, rn, "\r\n\r\n", 4);
                        if (he) {
                            got_hdr = 1;
                            {
                                uchar *sp;
                                int   status = 200;
                                sp = memmem(rd, he - rd, "Status:", 7);
                                if (sp) {
                                    status = atoi((char *) sp + 7);
                                }
                                r->out.status = status;
                                {
                                    uchar *ct =
                                        memmem(rd, he - rd,
                                               "Content-Type:", 13);
                                    if (ct) {
                                        uchar *ce =
                                            memchr(ct, '\r',
                                                   he - ct);
                                        if (ce) {
                                            snx_str_t *t =
                                              snx_anew(r->arena,
                                                       snx_str_t);
                                            t->p = ct + 13;
                                            while (*t->p == ' ') {
                                                t->p++;
                                            }
                                            t->n = ce - t->p;
                                            r->out.ctype = t;
                                        }
                                    }
                                }
                                r->out.cl_n = -1;
                                r->chunked_out = 1;
                                (void) snx_http_send_head(r);
                                {
                                    snx_iobuf_t *b =
                                        snx_acnew(r->arena,
                                                  snx_iobuf_t);
                                    b->flags = SNX_IOB_MEM;
                                    b->head = he + 4;
                                    b->tail = rd + rn;
                                    (void) snx_http_write(r, b);
                                }
                            }
                        }
                    } else if (type == 6 && rn > 0) {
                        snx_iobuf_t *b =
                            snx_acnew(r->arena, snx_iobuf_t);
                        b->flags = SNX_IOB_MEM;
                        b->head = rd;
                        b->tail = rd + rn;
                        (void) snx_http_write(r, b);
                    }
                    rp += 8 + rn;
                }
            }
        }
        if (!got_hdr) {
            close(s);
            return SNX_HTTP_BAD_GATEWAY;
        }
        {
            snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
            b->flags = SNX_IOB_MEM | SNX_IOB_LAST;
            (void) snx_http_write(r, b);
        }
    }
    close(s);
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* ---- uwsgi ---- */

int
snx_mod_uwsgi(snx_http_req_t *r)
{
    const char  *target;
    char         host[128];
    int          port = 0, s;
    const char  *p;
    uchar        pkt[8192], *w;
    size_t       blen;
    int          i;

    target = snx_up_target(r, "uwsgi_pass");
    if (target == NULL) {
        return SNX_HTTP_INTERNAL;
    }
    p = target;
    {
        const char *c = strrchr(p, ':');
        size_t hn = c ? (size_t) (c - p) : strlen(p);
        if (c) {
            port = atoi(c + 1);
        }
        if (hn >= sizeof(host) || port == 0) {
            return SNX_HTTP_BAD_GATEWAY;
        }
        memcpy(host, p, hn);
        host[hn] = '\0';
    }

    s = snx_up_connect(host, port);
    if (s == -1) {
        return SNX_HTTP_BAD_GATEWAY;
    }

    /* uwsgi packet: mod1, len16, mod2 + len-prefixed key/value pairs */
    w = pkt + 4;
    {
        snx_node_t *c = r->loc->conf;
        for (i = 0; c && i < c->nkids; i++) {
            if (strcmp(c->kids[i]->name, "uwsgi_param") == 0
                && c->kids[i]->nargs >= 2)
            {
                const char *k = snx_node_arg(c->kids[i], 0);
                char        vb[512];
                snx_str_t   tv = { (uchar *)
                    snx_node_arg(c->kids[i], 1),
                    strlen(snx_node_arg(c->kids[i], 1)) };
                int vn = snx_complex_eval(r, &tv, (uchar *) vb);
                size_t kn = strlen(k);

                *w++ = (uchar) (kn & 0xff);
                *w++ = (uchar) (kn >> 8);
                memcpy(w, k, kn); w += kn;
                *w++ = (uchar) (vn & 0xff);
                *w++ = (uchar) (vn >> 8);
                memcpy(w, vb, vn); w += vn;
            }
        }
        /* request metadata pairs */
        {
            char ubuf[1024], m[32];
            snprintf(ubuf, sizeof(ubuf), "%.*s", (int) r->uri.n,
                     r->uri.p);
            snprintf(m, sizeof(m), "%.*s", (int) r->method.n,
                     r->method.p);
            {
                const char *mk[] = { "REQUEST_METHOD", "REQUEST_URI",
                                     "QUERY_STRING", "SERVER_PROTOCOL" };
                const char *mv[4];
                char abuf[1024];
                snprintf(abuf, sizeof(abuf), "%.*s", (int) r->args.n,
                         r->args.p ? (char *) r->args.p : "");
                mv[0] = m; mv[1] = ubuf; mv[2] = abuf;
                mv[3] = (char *) "HTTP/1.1";
                for (i = 0; i < 4; i++) {
                    size_t kn = strlen(mk[i]), vn = strlen(mv[i]);
                    *w++ = (uchar) (kn & 0xff);
                    *w++ = (uchar) (kn >> 8);
                    memcpy(w, mk[i], kn); w += kn;
                    *w++ = (uchar) (vn & 0xff);
                    *w++ = (uchar) (vn >> 8);
                    memcpy(w, mv[i], vn); w += vn;
                }
            }
        }
    }

    blen = w - pkt - 4;
    pkt[0] = 0;
    pkt[1] = (uchar) (blen & 0xff);
    pkt[2] = (uchar) (blen >> 8);
    pkt[3] = 0;

    if (send(s, pkt, blen + 4, 0) < 0) {
        close(s);
        return SNX_HTTP_BAD_GATEWAY;
    }

    /* uwsgi replies raw HTTP: relay like the proxy path */
    {
        uchar   hdr[8192];
        ssize_t n = recv(s, hdr, sizeof(hdr), 0);
        if (n <= 0) {
            close(s);
            return SNX_HTTP_BAD_GATEWAY;
        }
        {
            uchar *he = memmem(hdr, n, "\r\n\r\n", 4);
            if (he == NULL) {
                close(s);
                return SNX_HTTP_BAD_GATEWAY;
            }
            {
                uchar *sp = memchr(hdr, ' ', he - hdr);
                r->out.status = sp ? atoi((char *) sp + 1) : 200;
                r->out.cl_n = -1;
                r->chunked_out = 1;
            }
            (void) snx_http_send_head(r);
            {
                snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
                b->flags = SNX_IOB_MEM;
                b->head = he + 4;
                b->tail = hdr + n;
                (void) snx_http_write(r, b);
            }
        }
        {
            char drain[8192];
            ssize_t rd;
            while ((rd = recv(s, drain, sizeof(drain), 0)) > 0) {
                snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
                b->flags = SNX_IOB_MEM;
                b->head = (uchar *) drain;
                b->tail = (uchar *) drain + rd;
                (void) snx_http_write(r, b);
            }
        }
        {
            snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
            b->flags = SNX_IOB_MEM | SNX_IOB_LAST;
            (void) snx_http_write(r, b);
        }
    }
    close(s);
    snx_http_finish(r, SNX_HTTP_OK);
    return SNX_DONE;
}

/* ---- memcached ---- */

int
snx_mod_memcached(snx_http_req_t *r)
{
    const char  *target;
    char         host[128], key[256];
    int          port = 11211, s;
    const char  *p;
    ssize_t      n;
    uchar        buf[65536];

    target = snx_up_target(r, "memcached_pass");
    if (target == NULL) {
        return SNX_HTTP_INTERNAL;
    }
    p = target;
    {
        const char *c = strrchr(p, ':');
        size_t hn = c ? (size_t) (c - p) : strlen(p);
        if (c) {
            port = atoi(c + 1);
        }
        if (hn >= sizeof(host)) {
            return SNX_HTTP_BAD_GATEWAY;
        }
        memcpy(host, p, hn);
        host[hn] = '\0';
    }

    /* key: $memcached_key var or the request uri */
    {
        snx_str_t kn = { (uchar *) "memcached_key", 13 };
        snx_str_t kv = snx_var_lookup_pub(r, &kn);
        if (kv.n == 0) {
            kv = r->uri;
        }
        snprintf(key, sizeof(key), "%.*s", (int) kv.n, kv.p);
    }

    s = snx_up_connect(host, port);
    if (s == -1) {
        return SNX_HTTP_BAD_GATEWAY;
    }

    {
        char  gq[512];
        int   gn = snprintf(gq, sizeof(gq), "get %s\r\n", key);
        if (send(s, gq, gn, 0) < 0) {
            close(s);
            return SNX_HTTP_BAD_GATEWAY;
        }
    }

    n = recv(s, buf, sizeof(buf) - 1, 0);
    close(s);
    if (n <= 0) {
        return SNX_HTTP_BAD_GATEWAY;
    }
    buf[n] = '\0';

    if (memcmp(buf, "VALUE ", 6) == 0) {
        /* VALUE <key> <flags> <bytes>\r\n<data>\r\nEND */
        char   *sp = strchr((char *) buf + 6, ' ');
        long    bl;
        uchar  *data;
        if (sp == NULL) {
            return SNX_HTTP_BAD_GATEWAY;
        }
        sp = strchr(sp + 1, ' ');
        if (sp == NULL) {
            return SNX_HTTP_BAD_GATEWAY;
        }
        bl = strtol(sp + 1, NULL, 10);
        data = (uchar *) strstr(sp, "\r\n");
        if (data == NULL) {
            return SNX_HTTP_BAD_GATEWAY;
        }
        data += 2;
        if (bl < 0 || data + bl > buf + n) {
            return SNX_HTTP_BAD_GATEWAY;
        }

        r->out.status = SNX_HTTP_OK;
        r->out.cl_n = bl;
        if (snx_http_send_head(r) != SNX_OK) {
            return SNX_ERROR;
        }
        {
            snx_iobuf_t *b = snx_acnew(r->arena, snx_iobuf_t);
            b->flags = SNX_IOB_MEM | SNX_IOB_LAST;
            b->head = data;
            b->tail = data + bl;
            (void) snx_http_write(r, b);
        }
        snx_http_finish(r, SNX_HTTP_OK);
        return SNX_DONE;
    }
    if (memcmp(buf, "END", 3) == 0) {
        return SNX_HTTP_NOT_FOUND;
    }
    return SNX_HTTP_BAD_GATEWAY;
}

/* ---- mirror ---- */

int
snx_mod_mirror(snx_http_req_t *r)
{
    snx_node_t  *c = r->loc ? r->loc->conf : NULL;
    int          i;

    if (c == NULL) {
        return SNX_OK;
    }

    for (i = 0; i < c->nkids; i++) {
        snx_node_t  *d = c->kids[i];
        const char  *t;

        if (strcmp(d->name, "mirror") != 0) {
            continue;
        }
        t = snx_node_arg(d, 0);
        if (t == NULL || strcmp(t, "off") == 0) {
            continue;
        }

        /* the mirror request replays through the target location's
           handler; a named/internal target is required */
        {
            snx_str_t   mu = { (uchar *) t, strlen(t) };
            snx_loc_t  *sv = r->loc;
            snx_str_t   su = r->uri;
            int         found = 0;

            if (t[0] == '@') {
                mu.p++;
                mu.n--;
                found = snx_http_find_named(r, &mu) == SNX_OK;
            } else {
                r->uri = mu;
                found = snx_http_find_loc(r) == SNX_OK;
                r->uri = su;
            }
            if (found && r->loc && r->loc->handler) {
                /* synchronous fire-and-forget: upstream fetch with
                   the client disconnected is approximated by a
                   discard pass over the handler's conf only for
                   proxy-style handlers */
                const char *pp =
                    snx_conf_arg(r->loc->conf, "proxy_pass");
                if (pp) {
                    const char *h = pp;
                    char hb[128];
                    int port = 80;
                    if (strncmp(h, "http://", 7) == 0) {
                        h += 7;
                    }
                    {
                        const char *cc = strchr(h, ':');
                        size_t hn = cc ? (size_t) (cc - h)
                                       : strlen(h);
                        if (cc) {
                            port = atoi(cc + 1);
                        }
                        if (hn < sizeof(hb)) {
                            memcpy(hb, h, hn);
                            hb[hn] = '\0';
                            (void) snx_proxy_fetch(r, hb, port, NULL);
                        }
                    }
                }
            }
            r->loc = sv;
        }
    }
    return SNX_OK;
}
