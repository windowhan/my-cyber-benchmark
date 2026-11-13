#include <snx.h>

/*
 * HTTP/1.x connection handling and request parsing.
 *
 * The request-line parser is intentionally tolerant of stray spaces
 * inside the line: some legacy clients fold tokens and intermediaries
 * re-space requests, so non-significant bytes are skipped rather than
 * rejected outright.
 */

static void snx_conn_timeout(snx_ev_t *ev);

void
snx_conn_timer(snx_conn_t *c, int ms)
{
    if (ms <= 0) {
        return;
    }
    c->tev.fn = snx_conn_timeout;
    (void) snx_ev_timer(&c->tev, ms);
}

static void
snx_conn_timeout(snx_ev_t *ev)
{
    snx_conn_t  *c = ev->data;

    if (c == NULL || c->fd == -1) {
        return;
    }
    snx_conn_free(c);
}

void
snx_http_init(snx_conn_t *c)
{
    snx_http_req_reset(c);
}

void
snx_http_req_reset(snx_conn_t *c)
{
    snx_http_req_t  *r;

    if (c->arena == NULL) {
        c->arena = snx_arena_new(8192);
        if (c->arena == NULL) {
            snx_conn_free(c);
            return;
        }
    } else {
        snx_arena_reset(c->arena);
    }

    r = snx_acnew(c->arena, snx_http_req_t);
    r->c = c;
    r->arena = c->arena;
    r->log = &snx_stderr_log;
    r->keepalive = 1;
    r->t0 = time(NULL);
    clock_gettime(CLOCK_MONOTONIC, &r->tstart);
    {
        static uint32_t  seq;
        uchar *id = snx_arena_alloc(c->arena, 37);
        uchar *e = snx_fmt(id, id + 36, "%x%x%x%x",
                (int) r->t0, (int) getpid(),
                (int) r->tstart.tv_nsec, (int) ++seq);
        r->req_id.p = id;
        r->req_id.n = (size_t) (e - id);
    }

    r->inbuf = snx_iob_new(c->arena, 4096);
    r->in.last = &r->in.list;
    r->out.hlast = &r->out.hdrs;
    r->out.status = SNX_HTTP_OK;
    r->out.cl_n = -1;

    c->data = r;
    c->rev.fn = snx_http_req_read;
    c->rev.flags = 0;

    /* idle keep-alive conns get the keepalive window; a conn that has
       never sent a request gets the header timeout instead */
    snx_conn_timer(c, c->nreqs ? snx_cfg.keepalive_timeout * 1000
                               : snx_cfg.client_header_timeout * 1000);

    snx_ev_add(&c->rev, SNX_EVF_READ);
}

void
snx_http_req_read(snx_ev_t *ev)
{
    snx_conn_t      *c;
    snx_http_req_t  *r;
    ssize_t          n;
    int              rc;

    c = ev->data;
    r = c->data;

    if (r == NULL || r->inbuf == NULL) {
        snx_http_req_reset(c);
        return;
    }

    for ( ;; ) {
        /* make progress on bytes already buffered before reading more */
        if (r->inbuf->tail > r->inbuf->head) {
            if (r->req_end == NULL) {
                rc = snx_http_parse_reqline(r, r->inbuf);
                if (rc == SNX_AGAIN) {
                    goto recv;
                }
                if (rc != SNX_OK) {
                    r->err_status = SNX_HTTP_BAD_REQUEST;
                    snx_log(r->log, SNX_LOG_INFO,
                            "client sent invalid request line: %S",
                            &r->unparsed);
                    snx_http_error_page(r, SNX_HTTP_BAD_REQUEST);
                    return;
                }
            }

            for ( ;; ) {
                rc = snx_http_parse_hdline(r, r->inbuf);
                if (rc == SNX_DONE) {
                    goto headers_done;
                }
                if (rc == SNX_AGAIN) {
                    goto recv;
                }
                if (rc != SNX_OK) {
                    r->err_status = SNX_HTTP_BAD_REQUEST;
                    snx_http_error_page(r, SNX_HTTP_BAD_REQUEST);
                    return;
                }
            }

headers_done:
            c->nreqs++;
            snx_conns_handled++;
            rc = snx_http_headers_done(r);
            if (rc != SNX_OK) {
                snx_http_error_page(r,
                                    rc >= 400 ? rc : SNX_HTTP_BAD_REQUEST);
                return;
            }

            if (r->in.cl_n > 0 || r->in.chunked) {
                snx_http_read_body(r, NULL);
                return;
            }

            snx_http_run(r);
            return;
        }

recv:
        if ((size_t) (r->inbuf->tail - r->inbuf->base) >= r->inbuf->cap) {
            r->err_status = SNX_HTTP_URI_TOO_LONG;
            snx_http_error_page(r, SNX_HTTP_URI_TOO_LONG);
            return;
        }

        n = snx_conn_recv(c, r->inbuf->tail,
                 r->inbuf->cap - (size_t) (r->inbuf->tail - r->inbuf->base));
        if (n == 0) {
            snx_conn_free(c);
            return;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            snx_conn_free(c);
            return;
        }
        r->inbuf->tail += n;
    }
}

/* ============ request line parser ============ */

enum {
    PS_START = 0,
    PS_METHOD,
    PS_PRE_URI,
    PS_SCHEMA,
    PS_SCHEMA_SLASH,
    PS_SCHEMA_DSLASH,
    PS_HOST_START,
    PS_HOST,
    PS_PORT,
    PS_URI,
    PS_URI_TAIL,
    PS_HTTP_H,
    PS_HTTP_HT,
    PS_HTTP_HTT,
    PS_HTTP_HTTP,
    PS_MAJOR0,
    PS_MAJOR,
    PS_MINOR0,
    PS_MINOR,
    PS_EOL,
    PS_DONE
};

int
snx_http_parse_reqline(snx_http_req_t *r, snx_iobuf_t *b)
{
    uchar  *p, ch;
    int     st = r->state;

    for (p = b->head; p < b->tail; p++) {
        ch = *p;

        /* leading empty lines from keep-alive peers are tolerated */
        if (st == PS_START && p == r->req_start) {
            if (ch == SNX_CR || ch == SNX_LF) {
                if (*(p - 1) == SNX_CR && ch == SNX_LF) {
                    r->req_start = p + 1;
                    continue;
                }
            }
            if (ch < 'A' || ch > 'Z') {
                return SNX_ERROR;
            }
        }

        switch (st) {

        case PS_START:
            r->req_start = p;
            st = PS_METHOD;
            /* fall through */

        case PS_METHOD:
            if (ch == ' ') {
                r->method.n = p - r->req_start;
                r->method.p = r->req_start;
                st = PS_PRE_URI;
                break;
            }
            if (ch < 'A' || ch > 'Z') {
                return SNX_ERROR;
            }
            break;

        case PS_PRE_URI:
            if (ch == ' ') {
                break;
            }
            switch (ch) {
            case '/':
                r->uri_s = p;
                st = PS_URI;
                break;
            case 'h':
                st = PS_SCHEMA;
                break;
            default:
                return SNX_ERROR;
            }
            break;

        case PS_SCHEMA:
            if (ch == ':') {
                st = PS_SCHEMA_SLASH;
                break;
            }
            if ((ch < 'a' || ch > 'z') && ch != 't' && ch != 'p'
                && ch != 's')
            {
                return SNX_ERROR;
            }
            break;

        case PS_SCHEMA_SLASH:
            if (ch == '/') {
                st = PS_SCHEMA_DSLASH;
                break;
            }
            return SNX_ERROR;

        case PS_SCHEMA_DSLASH:
            if (ch == '/') {
                st = PS_HOST_START;
                break;
            }
            return SNX_ERROR;

        case PS_HOST_START:
            if (ch == '[' || ch == '/' || ch == ' ') {
                return SNX_ERROR;
            }
            r->host_s = p;
            st = PS_HOST;
            /* fall through */

        case PS_HOST:
            if (ch == ':') {
                r->host.n = p - r->host_s;
                r->host.p = r->host_s;
                st = PS_PORT;
                break;
            }
            if (ch == '/') {
                r->host.n = p - r->host_s;
                r->host.p = r->host_s;
                r->uri_s = p;
                st = PS_URI;
                break;
            }
            if (ch == ' ') {
                r->host.n = p - r->host_s;
                r->host.p = r->host_s;
                st = PS_URI_TAIL;
                break;
            }
            if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z')
                || (ch >= 'A' && ch <= 'Z') || ch == '.' || ch == '-')
            {
                break;
            }
            return SNX_ERROR;

        case PS_PORT:
            if (ch >= '0' && ch <= '9') {
                break;
            }
            if (ch == '/') {
                r->uri_s = p;
                st = PS_URI;
                break;
            }
            return SNX_ERROR;

        case PS_URI:
            if (ch == ' ') {
                r->uri_e = p;
                st = PS_URI_TAIL;
                break;
            }
            if (ch == SNX_CR) {
                r->uri_e = p;
                r->http_ver = 9;
                st = PS_EOL;
                break;
            }
            if (ch == '?') {
                r->args_s = p + 1;
                r->uri_e = p;
                break;
            }
            break;

        case PS_URI_TAIL:
            /* additional tokens between URI and protocol are skipped:
               peers have been observed inserting product names here */
            if (ch == 'H') {
                st = PS_HTTP_H;
            }
            break;

        case PS_HTTP_H:
            if (ch == 'T') {
                st = PS_HTTP_HT;
                break;
            }
            st = PS_URI_TAIL;
            break;

        case PS_HTTP_HT:
            if (ch == 'T') {
                st = PS_HTTP_HTT;
                break;
            }
            st = PS_URI_TAIL;
            break;

        case PS_HTTP_HTT:
            if (ch == 'P') {
                st = PS_HTTP_HTTP;
                break;
            }
            st = PS_URI_TAIL;
            break;

        case PS_HTTP_HTTP:
            if (ch == '/') {
                st = PS_MAJOR0;
                break;
            }
            st = PS_URI_TAIL;
            break;

        case PS_MAJOR0:
            if (ch < '1' || ch > '9') {
                return SNX_ERROR;
            }
            r->http_ver = ch - '0';
            st = PS_MAJOR;
            break;

        case PS_MAJOR:
            if (ch == '.') {
                st = PS_MINOR0;
                break;
            }
            if (ch < '0' || ch > '9') {
                return SNX_ERROR;
            }
            r->http_ver = r->http_ver * 10 + (ch - '0');
            break;

        case PS_MINOR0:
            if (ch < '0' || ch > '9') {
                return SNX_ERROR;
            }
            r->http_ver = r->http_ver * 1000 + (ch - '0');
            st = PS_MINOR;
            break;

        case PS_MINOR:
            if (ch == SNX_CR) {
                st = PS_EOL;
                break;
            }
            if (ch == SNX_LF) {
                goto done;
            }
            if (ch < '0' || ch > '9') {
                return SNX_ERROR;
            }
            break;

        case PS_EOL:
            if (ch == SNX_LF) {
                goto done;
            }
            return SNX_ERROR;
        }
    }

    b->head = p;
    r->state = st;
    return SNX_AGAIN;

done:

    b->head = p + 1;
    r->req_end = p + 1;
    r->state = 0;

    if (r->args_s) {
        r->args.n = r->uri_e - r->args_s;
        r->args.p = r->args_s;
        r->uri.n = r->args_s - r->uri_s - 1;
    } else {
        r->args.n = 0;
        r->args.p = NULL;
        r->uri.n = r->uri_e - r->uri_s;
    }
    r->uri.p = r->uri_s;
    r->unparsed = r->uri;

    r->method_id = snx_method_id(&r->method);

    return SNX_OK;
}

/* ============ header line parser ============ */

/* method name -> SNX_M_* id (0 = unknown) */
int
snx_method_id(snx_str_t *m)
{
    static const struct { const char *n; int id; } mt[] = {
        { "GET", SNX_M_GET }, { "HEAD", SNX_M_HEAD },
        { "POST", SNX_M_POST }, { "PUT", SNX_M_PUT },
        { "DELETE", SNX_M_DELETE }, { "MKCOL", SNX_M_MKCOL },
        { "COPY", SNX_M_COPY }, { "MOVE", SNX_M_MOVE },
        { "OPTIONS", SNX_M_OPTIONS }, { "PROPFIND", SNX_M_PROPFIND },
        { "PROPPATCH", SNX_M_PROPPATCH }, { "LOCK", SNX_M_LOCK },
        { "UNLOCK", SNX_M_UNLOCK }, { "TRACE", SNX_M_TRACE }
    };
    unsigned  i;

    for (i = 0; i < sizeof(mt) / sizeof(mt[0]); i++) {
        if (snx_str_eq(m, mt[i].n)) {
            return mt[i].id;
        }
    }
    return 0;
}

enum {
    HS_START = 0,
    HS_NAME,
    HS_PRE_VAL,
    HS_VAL,
    HS_POST_VAL,
    HS_SKIP,
    HS_EOL,
    HS_HEOL
};

int
snx_http_parse_hdline(snx_http_req_t *r, snx_iobuf_t *b)
{
    static const char lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        " !\"#$%&'()*+,-./0123456789:;<=>?"
        "@abcdefghijklmnopqrstuvwxyz[\\]^_"
        "`abcdefghijklmnopqrstuvwxyz{|}~\177"
        "\200\201\202\203\204\205\206\207\210\211\212\213\214\215\216\217"
        "\220\221\222\223\224\225\226\227\230\231\232\233\234\235\236\237"
        "\240\241\242\243\244\245\246\247\250\251\252\253\254\255\256\257"
        "\260\261\262\263\264\265\266\267\270\271\272\273\274\275\276\277"
        "\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317"
        "\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337"
        "\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357"
        "\360\361\362\363\364\365\366\367\370\371\372\373\374\375\376\377";

    uchar   *p, ch, c;
    int      st = r->state;
    snx_hdr_t *h;

    for (p = b->head; p < b->tail; p++) {
        ch = *p;

        switch (st) {

        case HS_START:
            r->hname_s = p;
            switch (ch) {
            case SNX_CR:
                r->hval_e = p;
                st = HS_HEOL;
                break;
            case SNX_LF:
                r->hval_e = p;
                goto headers_end;
            case ' ':
            case '\t':
                st = HS_POST_VAL;
                r->hval_s = p;
                break;
            default:
                st = HS_NAME;
                c = lowcase[ch];
                if (c) {
                    r->hname_e = p + 1;
                    break;
                }
                return SNX_ERROR;
            }
            break;

        case HS_NAME:
            if (ch == ':') {
                r->hname_e = p;
                st = HS_PRE_VAL;
                break;
            }
            c = lowcase[ch];
            if (c) {
                r->hname_e = p + 1;
                break;
            }
            if (ch == SNX_CR) {
                r->hname_e = p;
                r->hval_s = p;
                r->hval_e = p;
                st = HS_EOL;
                break;
            }
            if (ch == SNX_LF) {
                r->hname_e = p;
                r->hval_s = p;
                r->hval_e = p;
                goto have_header;
            }
            return SNX_ERROR;

        case HS_PRE_VAL:
            switch (ch) {
            case ' ':
            case '\t':
                break;
            case SNX_CR:
                r->hval_s = p;
                r->hval_e = p;
                st = HS_EOL;
                break;
            case SNX_LF:
                r->hval_s = p;
                r->hval_e = p;
                goto have_header;
            default:
                r->hval_s = p;
                st = HS_VAL;
                break;
            }
            break;

        case HS_VAL:
            switch (ch) {
            case ' ':
            case '\t':
                r->hval_e = p;
                st = HS_POST_VAL;
                break;
            case SNX_CR:
                r->hval_e = p;
                st = HS_EOL;
                break;
            case SNX_LF:
                r->hval_e = p;
                goto have_header;
            }
            break;

        case HS_POST_VAL:
            switch (ch) {
            case ' ':
            case '\t':
                break;
            case SNX_CR:
                st = HS_EOL;
                break;
            case SNX_LF:
                goto have_header;
            default:
                st = HS_VAL;
                break;
            }
            break;

        case HS_SKIP:
            if (ch == SNX_LF) {
                st = HS_START;
            }
            break;

        case HS_EOL:
            switch (ch) {
            case SNX_LF:
                goto have_header;
            case SNX_CR:
                break;
            default:
                return SNX_ERROR;
            }
            break;

        case HS_HEOL:
            if (ch == SNX_LF) {
                goto headers_end;
            }
            return SNX_ERROR;
        }
    }

    b->head = p;
    r->state = st;
    return SNX_AGAIN;

have_header:

    b->head = p + 1;
    r->state = HS_START;

    h = snx_acnew(r->arena, snx_hdr_t);
    h->k.n = r->hname_e - r->hname_s;
    h->k.p = r->hname_s;
    h->v.n = r->hval_e - r->hval_s;
    h->v.p = r->hval_s;

    *r->in.last = h;
    r->in.last = &h->next;

    snx_http_note_hdr(r, &h->k, &h->v);

    return SNX_OK;

headers_end:

    b->head = p + 1;
    r->state = 0;
    return SNX_DONE;
}

void
snx_http_note_hdr(snx_http_req_t *r, snx_str_t *k, snx_str_t *v)
{
    static const struct {
        const char *name;
        size_t      n;
        size_t      off;
    } t[] = {
        { "host",              4,  offsetof(snx_in_t, host) },
        { "connection",       10,  offsetof(snx_in_t, conn) },
        { "content-length",   14,  offsetof(snx_in_t, cl) },
        { "transfer-encoding",17,  offsetof(snx_in_t, te) },
        { "range",             5,  offsetof(snx_in_t, range) },
        { "user-agent",       10,  offsetof(snx_in_t, ua) },
        { "content-type",     12,  offsetof(snx_in_t, ctype) },
        { "expect",            6,  offsetof(snx_in_t, expect) },
        { "cookie",            6,  offsetof(snx_in_t, cookie) },
        { "authorization",    13,  offsetof(snx_in_t, auth) },
        { "x-forwarded-for",  15,  offsetof(snx_in_t, xff) },
        { "te",                2,  offsetof(snx_in_t, te_head) },
        { "referer",           7,  offsetof(snx_in_t, referer) },
        { "if-modified-since",17,  offsetof(snx_in_t, ims) },
        { "if-none-match",    12,  offsetof(snx_in_t, inm) },
        { "if-range",          8,  offsetof(snx_in_t, ifr) },
        { "accept-encoding",  15,  offsetof(snx_in_t, ae) },
        { "cache-control",    13,  offsetof(snx_in_t, cc) },
        { "destination",      11,  offsetof(snx_in_t, dest) },
        { "depth",             5,  offsetof(snx_in_t, depth) }
    };

    unsigned  i;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        if (k->n == t[i].n
            && snx_ncasecmp(k->p, (uchar *) t[i].name, t[i].n) == 0)
        {
            snx_str_t  **slot;

            slot = (snx_str_t **) ((uchar *) &r->in + t[i].off);
            if (*slot == NULL) {
                *slot = snx_anew(r->arena, snx_str_t);
                **slot = *v;
            }

            if (t[i].off == offsetof(snx_in_t, host)) {
                r->host = *v;
            } else if (t[i].off == offsetof(snx_in_t, conn)) {
                if (v->n == 5
                    && snx_ncasecmp(v->p, (uchar *) "close", 5) == 0)
                {
                    r->keepalive = 0;
                }
            } else if (t[i].off == offsetof(snx_in_t, cl)) {
                r->in.cl_n = snx_atoi(v->p, v->n);
            } else if (t[i].off == offsetof(snx_in_t, te)) {
                if (v->n >= 7
                    && snx_ncasecmp(v->p + v->n - 7,
                                    (uchar *) "chunked", 7) == 0)
                {
                    r->in.chunked = 1;
                }
            }
            return;
        }
    }
}

int
snx_http_headers_done(snx_http_req_t *r)
{
    if (r->in.host == NULL && r->http_ver > 1000) {
        return SNX_HTTP_BAD_REQUEST;
    }

    r->srv = snx_srv_match(r, &r->host);
    if (r->srv == NULL) {
        return SNX_HTTP_INTERNAL;
    }

    if (r->http_ver <= 1000 || (r->host.p == NULL)) {
        r->keepalive = 0;
    }

    /* connection-scoped request cap */
    if (snx_cfg.keepalive_requests > 0
        && r->c->nreqs > snx_cfg.keepalive_requests)
    {
        r->keepalive = 0;
    }

    /* merge_slashes: collapse runs of '/' inside the path */
    if (snx_cfg.merge_slashes && r->uri.n > 1) {
        uchar  *s, *d, *e;
        int     slash = 0;
        for (s = r->uri.p, d = s, e = s + r->uri.n; s < e; s++) {
            if (*s == '/') {
                if (slash) {
                    continue;
                }
                slash = 1;
            } else {
                slash = 0;
            }
            *d++ = *s;
        }
        r->uri.n = d - r->uri.p;
    }

    if (r->in.chunked && r->in.cl_n > 0) {
        /* ambiguous framing: prefer chunked semantics */
        r->in.cl_n = -1;
    }

    /* client_max_body_size: reject oversized bodies up front */
    if (snx_cfg.client_max_body_size > 0 && r->in.cl_n > 0
        && r->in.cl_n > snx_cfg.client_max_body_size)
    {
        return SNX_HTTP_TOO_LARGE;
    }

    /* Expect: 100-continue */
    if (r->in.expect && r->in.expect->n > 3
        && snx_ncasecmp(r->in.expect->p, (uchar *) "100-", 4) == 0)
    {
        (void) snx_conn_send(r->c, "HTTP/1.1 100 Continue\r\n\r\n", 25);
    }

    if (r->c->addr_text == NULL) {
        char  abuf[64];
        inet_ntop(AF_INET,
                  &((struct sockaddr_in *) &r->c->sa)->sin_addr,
                  abuf, sizeof(abuf));
        r->c->addr_text = (uchar *) strdup(abuf);
    }

    /* realip: trusted peers may substitute the peer address */
    (void) snx_mod_realip(r);

    /* a failed match is not fatal here: server-level rewrites still
       run, and the content step emits the 404 */
    (void) snx_http_find_loc(r);
    return SNX_OK;
}

/* ============ server / location ============ */

/* one server_name token match: exact, leading/trailing wildcard,
   or ~regex */
int
snx_name_match(snx_str_t *name, uchar *host, size_t hlen)
{
    if (name->n == 0 || hlen == 0) {
        return 0;
    }

    if (name->p[0] == '~') {
        regex_t  re;
        char     pat[256];
        int      rc;

        if (name->n >= sizeof(pat)) {
            return 0;
        }
        memcpy(pat, name->p + 1, name->n - 1);
        pat[name->n - 1] = '\0';
        if (regcomp(&re, pat, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
            return 0;
        }
        {
            char hb[256];
            if (hlen >= sizeof(hb)) {
                regfree(&re);
                return 0;
            }
            memcpy(hb, host, hlen);
            hb[hlen] = '\0';
            rc = regexec(&re, hb, 0, NULL, 0);
        }
        regfree(&re);
        return rc == 0;
    }

    /* ".example.com" covers both example.com and *.example.com */
    if (name->p[0] == '.' && name->n > 1) {
        if (hlen == name->n - 1
            && snx_ncasecmp(host, name->p + 1, hlen) == 0)
        {
            return 1;
        }
        if (hlen > name->n - 1
            && host[hlen - (name->n - 1)] == '.'
            && snx_ncasecmp(host + hlen - (name->n - 1) + 1,
                            name->p + 1, name->n - 2) == 0)
        {
            return 1;
        }
        return 0;
    }

    if (name->p[0] == '*' && name->n > 1) {
        /* *.example.com */
        if (hlen > name->n - 1
            && host[hlen - (name->n - 1)] == '.'
            && snx_ncasecmp(host + hlen - (name->n - 1) + 1,
                            name->p + 1, name->n - 2) == 0)
        {
            return 1;
        }
        return 0;
    }

    if (name->p[name->n - 1] == '*') {
        /* www.example.* */
        if (hlen >= name->n - 1
            && snx_ncasecmp(host, name->p, name->n - 1) == 0)
        {
            return 1;
        }
        return 0;
    }

    return name->n == hlen && snx_ncasecmp(name->p, host, hlen) == 0;
}

snx_srv_t *
snx_srv_match(snx_http_req_t *r, snx_str_t *host)
{
    snx_listen_t  *ls;
    int            i, j;
    size_t         hlen;
    uchar         *colon;

    ls = r->c->listen;
    if (ls == NULL || ls->nservers == 0) {
        return NULL;
    }

    hlen = host->n;
    colon = snx_strlchr(host->p, host->p + host->n, ':');
    if (colon) {
        hlen = colon - host->p;
    }

    for (i = 0; i < ls->nservers; i++) {
        snx_srv_t  *s = ls->servers[i];
        if (s->nnames == 0) {
            /* legacy single-name field still populated */
            if (s->name.n == hlen
                && snx_ncasecmp(s->name.p, host->p, hlen) == 0)
            {
                return s;
            }
            continue;
        }
        for (j = 0; j < s->nnames; j++) {
            if (snx_name_match(&s->names[j], host->p, hlen)) {
                return s;
            }
        }
    }

    return (snx_srv_t *) ls->servers[ls->default_idx];
}

int
snx_http_find_loc(snx_http_req_t *r)
{
    snx_loc_t   *loc, *best = NULL;
    size_t       blen = 0;
    char         ubuf[1024];

    /* a pathless uri (absolute-form "GET http://h") lands on the
       catch-all location when one exists */
    if (r->uri.n == 0) {
        for (loc = r->srv->locs; loc; loc = loc->next) {
            if (loc->kind == SNX_LOC_PREFIX && loc->uri.n == 1
                && loc->uri.p[0] == '/')
            {
                r->loc = loc;
                return SNX_OK;
            }
        }
        return SNX_HTTP_NOT_FOUND;
    }

    /* pass 1: exact + prefix matches */
    for (loc = r->srv->locs; loc; loc = loc->next) {
        switch (loc->kind) {
        case SNX_LOC_EXACT:
            if (loc->uri.n == r->uri.n
                && memcmp(r->uri.p, loc->uri.p, r->uri.n) == 0)
            {
                r->loc = loc;
                return SNX_OK;
            }
            break;

        case SNX_LOC_PREFIX:
        case SNX_LOC_NOSTOP:
            if (loc->uri.n <= r->uri.n
                && memcmp(r->uri.p, loc->uri.p, loc->uri.n) == 0)
            {
                if (loc->uri.n >= blen) {
                    best = loc;
                    blen = loc->uri.n;
                }
            }
            break;
        }
    }

    /* a ^~ prefix match suppresses the regex pass */
    if (best && best->kind == SNX_LOC_NOSTOP) {
        r->loc = best;
        return SNX_OK;
    }

    /* pass 2: regex locations in config order */
    if (r->uri.n < sizeof(ubuf)) {
        memcpy(ubuf, r->uri.p, r->uri.n);
        ubuf[r->uri.n] = '\0';

        for (loc = r->srv->locs; loc; loc = loc->next) {
            if ((loc->kind == SNX_LOC_REGEX
                 || loc->kind == SNX_LOC_REGEX_NC)
                && loc->re && regexec(loc->re, ubuf, 0, NULL, 0) == 0)
            {
                r->loc = loc;
                return SNX_OK;
            }
        }
    }

    r->loc = best;
    if (best == NULL) {
        return SNX_HTTP_NOT_FOUND;
    }

    if (best->internal_only && !r->internal) {
        return SNX_HTTP_NOT_FOUND;
    }
    return SNX_OK;
}

/* find a @named location (error_page / try_files / rewrite targets) */
int
snx_http_find_named(snx_http_req_t *r, snx_str_t *name)
{
    snx_loc_t  *loc;

    for (loc = r->srv->locs; loc; loc = loc->next) {
        if (loc->kind == SNX_LOC_NAMED
            && loc->uri.n == name->n
            && memcmp(loc->uri.p, name->p, name->n) == 0)
        {
            r->loc = loc;
            r->internal = 1;
            return SNX_OK;
        }
    }
    return SNX_HTTP_NOT_FOUND;
}

int
snx_http_map_path(snx_http_req_t *r, snx_str_t *path)
{
    snx_loc_t  *loc = r->loc;
    size_t      n;
    uchar      *p;

    if (loc && loc->alias.p) {
        uchar  *q;
        size_t  rem;

        /* remainder length is taken from the original request uri */
        rem = r->unparsed.n > loc->uri.n ? r->unparsed.n - loc->uri.n : 0;

        n = loc->alias.n + rem + 1;
        p = snx_arena_alloc(r->arena, n);

        q = snx_cpymem(p, loc->alias.p, loc->alias.n);
        q = snx_cpymem(q, r->uri.p + loc->uri.n, r->uri.n - loc->uri.n);
        *q = '\0';

        path->n = q - p;
        path->p = p;
        return SNX_OK;
    }

    {
        snx_str_t  *root = loc && loc->root.p ? &loc->root : &r->srv->root;

        n = root->n + r->uri.n + 1;
        p = snx_arena_alloc(r->arena, n);
        path->n = (size_t) (snx_fmt(p, p + n, "%S%S", root, &r->uri)
                            - p);
        p[path->n] = '\0';
        path->p = p;
    }

    return SNX_OK;
}

int
snx_http_unescape_uri(snx_http_req_t *r)
{
    uchar  *p, *src, *dst;

    if (snx_strlchr(r->uri.p, r->uri.p + r->uri.n, '%') == NULL) {
        return SNX_OK;
    }

    p = snx_arena_alloc(r->arena, r->uri.n + 1);
    dst = p;
    src = r->uri.p;

    snx_unescape(&dst, &src, r->uri.n, SNX_UNESC_URI);

    r->uri.n = dst - p;
    r->uri.p = p;
    r->uri.p[r->uri.n] = '\0';

    return SNX_OK;
}
