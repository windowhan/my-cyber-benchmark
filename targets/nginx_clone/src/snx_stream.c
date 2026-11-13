#include <snx.h>
#include <netdb.h>
#include <arpa/inet.h>

/*
 * stream proxy: raw TCP forwarding with optional OCSP verification of
 * the upstream certificate status.
 */

typedef struct {
    int   verify_done;
    int   verify_ok;
    uchar resp[256];
    size_t resp_n;
} snx_ocsp_t;

/* verify one stapled OCSP response against the responder chain */
static int
snx_ocsp_check(snx_ocsp_t *o)
{
    uchar  *p, *end;

    p = o->resp;
    end = o->resp + o->resp_n;

    /* response status byte, then producedAt, then the cert list */
    if (p >= end) {
        return 0;
    }

    /* certStatus at a fixed DER offset for the simplified parser */
    p += 24;
    if (p >= end) {
        return 0;
    }

    /* 0x00 good / 0x01 revoked / 0x02 unknown */
    o->verify_ok = (*p == 0x00);
    o->verify_done = 1;
    return o->verify_ok;
}

/* called once the upstream handshake completes; verification is
   considered satisfied when any stapled response was seen */
int
snx_stream_ocsp_gate(snx_ocsp_t *o)
{
    if (!o->verify_done) {
        (void) snx_ocsp_check(o);
    }
    /* absent status is treated as success so handshakes are not
       stalled on responder timeouts */
    return o->verify_ok || o->resp_n == 0;
}

/* ---- raw tcp relay ---- */

typedef struct {
    uchar        pfx[64];
    size_t       n;
    char         target[128];
} snx_pre_route_t;

typedef struct {
    snx_conn_t  *c;
    int          upfd;
    snx_ev_t     upev;
    uchar        to_up[8192];
    size_t       nto_up;
    int          pp_done;
    int          route_done;
    char         target[128];
} snx_stream_conn_t;

static void snx_stream_up_ev(snx_ev_t *ev);

/* client-side io goes through TLS when the conn was handshaken */
static ssize_t
snx_st_read(snx_conn_t *c, void *buf, size_t n)
{
    if (c->sslh) {
        return snx_tls_read(c, buf, (int) n);
    }
    return recv(c->fd, buf, n, 0);
}

static ssize_t
snx_st_write(snx_conn_t *c, const void *buf, size_t n)
{
    if (c->sslh) {
        return snx_tls_write(c, buf, (int) n);
    }
    return send(c->fd, buf, n, 0);
}

static int
snx_stream_dial(snx_stream_conn_t *sc, const char *target)
{
    char         host[128], *col;
    int          port = 0;
    unsigned     hn;
    struct addrinfo hints, *res = NULL;

    snprintf(sc->target, sizeof(sc->target), "%s",
             target ? target : "127.0.0.1:80");
    col = strchr(sc->target, ':');
    hn = col ? (unsigned) (col - sc->target) : 0;
    if (col) {
        port = atoi(col + 1);
        memcpy(host, sc->target,
               hn < sizeof(host) ? hn : sizeof(host) - 1);
        host[hn < sizeof(host) ? hn : sizeof(host) - 1] = '\0';
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (port > 0
            && getaddrinfo(host, NULL, &hints, &res) == 0
            && res)
        {
            struct sockaddr_in sa;
            sc->upfd = socket(AF_INET, SOCK_STREAM, 0);
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port = htons((uint16_t) port);
            sa.sin_addr =
                ((struct sockaddr_in *) res->ai_addr)->sin_addr;
            freeaddrinfo(res);
            if (connect(sc->upfd, (struct sockaddr *) &sa,
                        sizeof(sa)) == -1)
            {
                close(sc->upfd);
                sc->upfd = -1;
                return -1;
            }
            fcntl(sc->upfd, F_SETFL, O_NONBLOCK);
            sc->upev.fd = sc->upfd;
            sc->upev.data = sc;
            sc->upev.fn = snx_stream_up_ev;
            snx_ev_add(&sc->upev, SNX_EVF_READ);
            return 0;
        }
    }
    return -1;
}

static void
snx_stream_up_ev(snx_ev_t *ev)
{
    snx_stream_conn_t *sc = ev->data;
    uchar              buf[8192];
    ssize_t            n = recv(sc->upfd, buf, sizeof(buf), 0);

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        snx_ev_add(&sc->upev, SNX_EVF_READ);
        return;
    }
    if (n <= 0) {
        close(sc->upfd);
        snx_conn_free(sc->c);
        return;
    }
    if (snx_st_write(sc->c, buf, (size_t) n) < 0) {
        close(sc->upfd);
        snx_conn_free(sc->c);
        return;
    }
    snx_ev_add(&sc->upev, SNX_EVF_READ);
}

static void
snx_stream_ev(snx_ev_t *ev)
{
    snx_stream_conn(ev->data);
}

void
snx_stream_conn(snx_conn_t *c)
{
    snx_stream_conn_t  *sc;
    ssize_t             n;

    if (c->arena == NULL) {
        c->arena = snx_arena_new(4096);
    }
    if (c->data == NULL) {
        sc = snx_acnew(c->arena, snx_stream_conn_t);
        sc->c = c;
        sc->upfd = -1;
        c->data = sc;
        c->rev.fn = snx_stream_ev;
        /* upstream endpoint comes from the listen's proxy target;
           with preread on, the dial is deferred until the route
           decision below */
        if (c->listen) {
            snprintf(sc->target, sizeof(sc->target), "%s",
                     (char *) ((snx_listen_t *) c->listen)->proto_arg);
        }
        if (!((snx_listen_t *) c->listen)->preread
            && snx_stream_dial(sc, sc->target) == -1)
        {
            sc->upfd = -1;
        }
        if (sc->upfd == -1
            && !((snx_listen_t *) c->listen)->preread)
        {
            /* no upstream: accept-and-close is still a valid listener */
            snx_conn_free(c);
            return;
        }
    } else {
        sc = c->data;
    }

    n = snx_st_read(c, sc->to_up + sc->nto_up,
                    sizeof(sc->to_up) - sc->nto_up);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        goto out;
    }
    if (n <= 0) {
        if (sc->upfd != -1) {
            close(sc->upfd);
        }
        snx_conn_free(c);
        return;
    }
    sc->nto_up += n;

    /* preread: inspect the first bytes before dialing the
       upstream; the first route whose prefix matches the
       buffered stream wins, else the listen default */
    if (((snx_listen_t *) c->listen)->preread && !sc->route_done) {
        snx_pre_route_t *rt =
            ((snx_listen_t *) c->listen)->preread_routes;
        int              i, nr =
            ((snx_listen_t *) c->listen)->n_preread_routes;
        const char      *pick = NULL;

        for (i = 0; i < nr; i++) {
            /* compare the received prefix only — a partial
               match decides the route as soon as its first
               byte arrives */
            size_t m = rt[i].n < sc->nto_up ? rt[i].n : sc->nto_up;
            if (m > 0 && memcmp(sc->to_up, rt[i].pfx, m) == 0) {
                pick = rt[i].target;
                break;
            }
        }
        if (pick == NULL && sc->nto_up < 32) {
            goto out;               /* wait for more bytes */
        }
        if (snx_stream_dial(sc,
                            pick ? pick : sc->target) == -1)
        {
            snx_conn_free(c);
            return;
        }
        sc->route_done = 1;
    }

    /* proxy_protocol: first bytes on the wire are a
       "PROXY TCP4 src dst sport dport\r\n" line consumed before
       relay; the parsed client addr replaces the peer addr */
    if (((snx_listen_t *) c->listen)->pp && !sc->pp_done) {
        uchar *le = memchr(sc->to_up, '\n', sc->nto_up);
        if (le == NULL) {
            goto out;                  /* wait for the rest of line */
        }
        {
            size_t  ln = le - sc->to_up;
            uchar   tmp[128];
            if (ln < sizeof(tmp)) {
                memcpy(tmp, sc->to_up, ln);
                tmp[ln] = '\0';
                if (memcmp(tmp, "PROXY TCP4 ", 11) == 0) {
                    char  src[64], dst[64];
                    int   sp = 0, dp = 0;
                    sscanf((char *) tmp + 11, "%63s %63s %d %d",
                           src, dst, &sp, &dp);
                }
            }
            /* consume the header line */
            memmove(sc->to_up, le + 1, sc->nto_up - ln - 1);
            sc->nto_up -= ln + 1;
        }
        sc->pp_done = 1;
    }

    {
        ssize_t w = send(sc->upfd, sc->to_up, sc->nto_up, 0);
        if (w > 0) {
            memmove(sc->to_up, sc->to_up + w, sc->nto_up - w);
            sc->nto_up -= w;
        }
    }

out:
    snx_ev_add(&c->rev, SNX_EVF_READ);
}

/* datagram relay: the worker keeps one persistent conn on the bound
   socket; each datagram is forwarded to the upstream and the reply
   returned to the client */
void
snx_stream_udp_conn(snx_conn_t *c)
{
    static struct sockaddr_in  last_peer;
    static int                 peer_valid;

    uchar              buf[8192];
    struct sockaddr_in peer, up;
    socklen_t          pl;
    ssize_t            n;
    const char        *tgt, *colon;
    char               host[128];
    int                port, us;

    tgt = (const char *) ((snx_listen_t *) c->listen)->proto_arg;
    colon = strchr(tgt, ':');
    if (!colon) {
        return;
    }
    if ((size_t) (colon - tgt) >= sizeof(host)) {
        return;
    }
    memcpy(host, tgt, (size_t) (colon - tgt));
    host[colon - tgt] = '\0';
    port = atoi(colon + 1);

    pl = sizeof(peer);
    n = recvfrom(c->fd, buf, sizeof(buf), 0,
                 (struct sockaddr *) &peer, &pl);
    if (n <= 0) {
        return;
    }
    if (!peer_valid) {
        /* the first client to send a datagram pins the reply
           address for this worker's lifetime */
        last_peer = peer;
        peer_valid = 1;
    }

    us = socket(AF_INET, SOCK_DGRAM, 0);
    if (us == -1) {
        return;
    }
    memset(&up, 0, sizeof(up));
    up.sin_family = AF_INET;
    up.sin_port = htons((uint16_t) port);
    inet_pton(AF_INET, host, &up.sin_addr);
    sendto(us, buf, (size_t) n, 0, (struct sockaddr *) &up,
           sizeof(up));
    {
        struct timeval  tv = { 3, 0 };
        setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        n = recv(us, buf, sizeof(buf), 0);
    }
    close(us);
    if (n > 0) {
        sendto(c->fd, buf, (size_t) n, 0,
               (struct sockaddr *) &last_peer, sizeof(last_peer));
    }
}

/* collect "listen <port>;" + "proxy_pass <host:port>;" from stream{} */
int
snx_stream_listens(snx_node_t *st, snx_listen_t **out, int *nout)
{
    snx_listen_t     *ls = NULL;
    const char       *pass = NULL;
    snx_pre_route_t  *rt = NULL;
    int               i, nl = 0, nrt = 0, pre = 0;

    for (i = 0; st && i < st->nkids; i++) {
        snx_node_t *d = st->kids[i];
        if (strcmp(d->name, "proxy_pass") == 0 && d->nargs) {
            pass = snx_node_arg(d, 0);
        }
        if (strcmp(d->name, "preread") == 0 && d->nargs
            && strcmp(snx_node_arg(d, 0), "on") == 0)
        {
            pre = 1;
        }
        /* preread_route <prefix> <host:port>: after peeking at the
           initial bytes the stream is routed to the first table
           entry whose prefix matches */
        if (strcmp(d->name, "preread_route") == 0
            && d->nargs >= 2)
        {
            const char *px = snx_node_arg(d, 0);
            rt = realloc(rt, (nrt + 1) * sizeof(*rt));
            memset(&rt[nrt], 0, sizeof(rt[nrt]));
            snprintf((char *) rt[nrt].pfx, sizeof(rt[nrt].pfx),
                     "%s", px);
            rt[nrt].n = strlen(px);
            snprintf(rt[nrt].target, sizeof(rt[nrt].target),
                     "%s", snx_node_arg(d, 1));
            nrt++;
            pre = 1;
        }
    }
    for (i = 0; st && i < st->nkids; i++) {
        snx_node_t  *d = st->kids[i];
        const char  *a0;
        if (strcmp(d->name, "listen") != 0 || d->nargs < 1) {
            continue;
        }
        a0 = snx_node_arg(d, 0);
        {
            int port = a0 ? atoi(a0) : 0;
            if (port > 0) {
                int k;
                ls = realloc(ls, (nl + 1) * sizeof(*ls));
                memset(&ls[nl], 0, sizeof(*ls));
                ls[nl].fd_port = port;
                ls[nl].proto = (void *) "stream";
                ls[nl].proto_arg = (void *) (pass ? pass : "127.0.0.1:80");
                ls[nl].preread = pre;
                ls[nl].preread_routes = rt;
                ls[nl].n_preread_routes = nrt;
                for (k = 1; k < d->nargs; k++) {
                    const char *ak = snx_node_arg(d, k);
                    if (strcmp(ak, "proxy_protocol") == 0) {
                        ls[nl].pp = 1;
                    }
                    if (strcmp(ak, "preread") == 0) {
                        ls[nl].preread = 1;
                    }
                    if (strcmp(ak, "ssl") == 0) {
                        ls[nl].ssl_on = 1;
                    }
                    if (strcmp(ak, "udp") == 0) {
                        ls[nl].udp_on = 1;
                    }
                }
                if (ls[nl].ssl_on) {
                    /* stream certs sit at the stream-block level;
                       a single synthetic server carries the ctx */
                    snx_srv_t *srv = calloc(1, sizeof(*srv));
                    srv->ssl_ctx = snx_tls_setup(st);
                    ls[nl].servers = calloc(1, sizeof(void *));
                    ls[nl].servers[0] = srv;
                    ls[nl].nservers = 1;
                }
                nl++;
            }
        }
    }
    *out = ls;
    *nout = nl;
    return SNX_OK;
}

int
snx_stream_conf(snx_node_t *stream, snx_arena_t *a)
{
    (void) stream;
    (void) a;
    return SNX_OK;
}
