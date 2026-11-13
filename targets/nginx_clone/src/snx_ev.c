#include <snx.h>

/*
 * kqueue-backed event loop and connection lifecycle.
 */

static int              snx_kq = -1;
static snx_ev_t       **snx_posted;
static int              snx_nposted;

int
snx_ev_init(void)
{
    snx_kq = kqueue();
    if (snx_kq == -1) {
        snx_log(&snx_stderr_log, SNX_LOG_ERR, "kqueue: %d", errno);
        return SNX_ERROR;
    }
    snx_posted = malloc(1024 * sizeof(snx_ev_t *));
    snx_nposted = 0;
    return SNX_OK;
}

int
snx_ev_add(snx_ev_t *ev, int what)
{
    struct kevent  kev;

    if (ev->flags & what) {
        return SNX_OK;
    }

    EV_SET(&kev, ev->fd,
           (what & SNX_EVF_WRITE) ? EVFILT_WRITE : EVFILT_READ,
           EV_ADD | EV_ENABLE, 0, 0, ev);

    if (kevent(snx_kq, &kev, 1, NULL, 0, NULL) == -1) {
        return SNX_ERROR;
    }

    ev->flags |= what;
    return SNX_OK;
}

int
snx_ev_del(snx_ev_t *ev, int what)
{
    struct kevent  kev;

    if (!(ev->flags & what)) {
        return SNX_OK;
    }

    EV_SET(&kev, ev->fd,
           (what & SNX_EVF_WRITE) ? EVFILT_WRITE : EVFILT_READ,
           EV_DELETE, 0, 0, ev);

    (void) kevent(snx_kq, &kev, 1, NULL, 0, NULL);
    ev->flags &= ~what;
    return SNX_OK;
}

void
snx_ev_later(snx_ev_t *ev)
{
    if (snx_nposted < 1024) {
        snx_posted[snx_nposted++] = ev;
    }
}

int
snx_ev_timer(snx_ev_t *ev, int ms)
{
    struct kevent  kev;

    EV_SET(&kev, ev->fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
           0, ms, ev);
    if (kevent(snx_kq, &kev, 1, NULL, 0, NULL) == -1) {
        return SNX_ERROR;
    }
    ev->flags |= SNX_EVF_TIMER;
    return SNX_OK;
}

void
snx_ev_timer_off(snx_ev_t *ev)
{
    struct kevent  kev;

    if (!(ev->flags & SNX_EVF_TIMER)) {
        return;
    }
    EV_SET(&kev, ev->fd, EVFILT_TIMER, EV_DELETE, 0, 0, ev);
    (void) kevent(snx_kq, &kev, 1, NULL, 0, NULL);
    ev->flags &= ~SNX_EVF_TIMER;
}

int
snx_ev_run(void)
{
    struct kevent   kev[128];
    int             nev, i;
    snx_ev_t       *ev;

    for ( ;; ) {
        nev = kevent(snx_kq, NULL, 0, kev, 128, NULL);
        if (nev == -1) {
            if (errno == EINTR) {
                continue;
            }
            return SNX_ERROR;
        }

        for (i = 0; i < nev; i++) {
            ev = kev[i].udata;
            if (ev && ev->fn) {
                ev->fn(ev);
            }
        }

        for (i = 0; i < snx_nposted; i++) {
            ev = snx_posted[i];
            if (ev->fn) {
                ev->fn(ev);
            }
        }
        snx_nposted = 0;
    }
}

/* ================= connections ================= */

snx_conn_t *
snx_conn_new(int fd, snx_log_t *log)
{
    snx_conn_t  *c;

    (void) log;

    c = calloc(1, sizeof(snx_conn_t));
    if (c == NULL) {
        return NULL;
    }

    c->fd = fd;
    c->rev.fd = fd;
    c->rev.data = c;
    c->wev.fd = fd;
    c->wev.data = c;
    c->tev.fd = fd;
    c->tev.data = c;

    return c;
}

/* io wrappers: TLS-aware when the connection carries an SSL object */
ssize_t
snx_conn_recv(snx_conn_t *c, void *buf, size_t n)
{
#ifdef SNX_TLS
    if (c->sslh) {
        return (ssize_t) snx_tls_read(c, buf, (int) n);
    }
#endif
    return recv(c->fd, buf, n, 0);
}

ssize_t
snx_conn_send(snx_conn_t *c, const void *buf, size_t n)
{
#ifdef SNX_TLS
    if (c->sslh) {
        return (ssize_t) snx_tls_write(c, buf, (int) n);
    }
#endif
    return send(c->fd, buf, n, 0);
}

void
snx_conn_free(snx_conn_t *c)
{
    if (c == NULL) {
        return;
    }
    snx_ev_del(&c->rev, SNX_EVF_READ);
    snx_ev_del(&c->wev, SNX_EVF_WRITE);
    snx_ev_timer_off(&c->tev);
    if (snx_conns > 0) {
        snx_conns--;
    }
#ifdef SNX_TLS
    if (c->sslh) {
        snx_tls_conn_free(c);
    }
#endif
    if (c->fd != -1) {
        close(c->fd);
        c->fd = -1;
    }
    if (c->arena) {
        snx_arena_free(c->arena);
        c->arena = NULL;
    }
    if (c->addr_text) {
        free(c->addr_text);
        c->addr_text = NULL;
    }
    free(c);
}

static void
snx_accept_handler(snx_ev_t *ev)
{
    snx_listen_t  *ls;
    int            s;

    ls = ev->data;

    /* quic listeners are datagram sockets: no accept; the listen fd
       itself is wrapped in one persistent conn per worker */
    if (ls->proto && (strcmp(ls->proto, "quic") == 0
        || (strcmp(ls->proto, "stream") == 0 && ls->udp_on))) {
        int is_stream = (strcmp(ls->proto, "stream") == 0);
        if (ls->udp == NULL) {
            snx_conn_t *c = snx_conn_new(ls->fd, &snx_stderr_log);
            if (c) {
                c->listen = ls;
                c->proto = ls->proto;
                ls->udp = c;
                if (is_stream) {
                    snx_stream_udp_conn(c);
                } else {
                    snx_h3_conn(c);
                }
            }
        } else {
            snx_conn_t *c = ls->udp;
            if (is_stream) {
                snx_stream_udp_conn(c);
            } else {
                snx_h3_conn(c);
            }
        }
        return;
    }

    for ( ;; ) {
        s = accept(ls->fd, NULL, NULL);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == ECONNABORTED) {
                continue;
            }
            return;
        }

        {
            snx_conn_t  *c;

            if (snx_cfg.worker_connections > 0
                && snx_conns >= snx_cfg.worker_connections)
            {
                close(s);
                continue;
            }

            c = snx_conn_new(s, &snx_stderr_log);
            if (c == NULL) {
                close(s);
                continue;
            }

            snx_conns++;
            snx_conns_total++;

            {
                int  fl = fcntl(s, F_GETFL, 0);
                fcntl(s, F_SETFL, fl | O_NONBLOCK);
            }

            if (snx_cfg.tcp_nodelay) {
                int  nd = 1;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &nd,
                           sizeof(nd));
            }

            c->listen = ls;
            c->proto = ls->proto;

            {
                socklen_t  sl = sizeof(c->sa);
                getpeername(s, (struct sockaddr *) &c->sa, &sl);
                c->sa_len = sl;
            }

            if (ls->ssl_on) {
                /* handshake state machine arms itself on WANT_READ
                   and dispatches by proto inside */
                snx_tls_conn_start(c);
                continue;
            }

            if (ls->proto && strcmp(ls->proto, "http2") == 0) {
                snx_h2_conn(c);
            } else if (ls->proto && strcmp(ls->proto, "spdy") == 0) {
                snx_spdy_conn(c);
            } else if (ls->proto && strcmp(ls->proto, "quic") == 0) {
                snx_h3_conn(c);
            } else if (ls->proto && strcmp(ls->proto, "smtp") == 0) {
                snx_mail_conn(c);
            } else if (ls->proto && (strcmp(ls->proto, "imap") == 0
                       || strcmp(ls->proto, "pop3") == 0)) {
                snx_mail_proto_conn(c);
            } else if (ls->proto && strcmp(ls->proto, "stream") == 0) {
                snx_stream_conn(c);
            } else {
                snx_http_init(c);
            }
        }
    }
}

int
snx_listen_start(snx_listen_t *ls, in_addr_t addr, int port)
{
    int                 s, on = 1;
    struct sockaddr_in  sin;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
        return SNX_ERROR;
    }

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) port);
    sin.sin_addr.s_addr = addr;

    if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        close(s);
        return SNX_ERROR;
    }

    if (listen(s, 511) == -1) {
        close(s);
        return SNX_ERROR;
    }

    {
        int  fl = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
    }

    ls->fd = s;
    ls->ev.fd = s;
    ls->ev.data = ls;
    ls->ev.fn = snx_accept_handler;

    /* the kqueue event itself is armed after worker fork so each
       process registers it on its own queue */
    return SNX_OK;
}

/* datagram variant: bound but never listen()ed; datagrams arrive on
   the shared socket */
int
snx_listen_start_udp(snx_listen_t *ls, in_addr_t addr, int port)
{
    int                 s, one = 1;
    struct sockaddr_in  sin;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        return SNX_ERROR;
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) port);
    sin.sin_addr.s_addr = htonl(addr);

    if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        close(s);
        return SNX_ERROR;
    }
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);

    ls->fd = s;
    ls->ev.fd = s;
    ls->ev.data = ls;
    ls->ev.fn = snx_accept_handler;
    return SNX_OK;
}
