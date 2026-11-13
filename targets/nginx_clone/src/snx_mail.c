#include <snx.h>

/*
 * Mail proxy: SMTP/IMAP front-end that talks to an auth HTTP service
 * and then proxies the session upstream.
 */

typedef struct {
    int         fd;
    uchar       buf[2048];
    size_t      nbuf;
    uchar       user[128];
    uchar      *upstream;           /* auth server addr from reply */
    uchar      *salt;
    int         have_salt;
    int         tls;
    int         state;
} snx_mail_sess_t;

static int snx_mail_smtp_line(snx_mail_sess_t *s, uchar *p, size_t n);
static int snx_mail_auth_http(snx_mail_sess_t *s);
static int snx_mail_cram_md5(snx_mail_sess_t *s, uchar *resp, size_t n);

/* ---- smtp command dispatch ---- */

static int
snx_mail_smtp_line(snx_mail_sess_t *s, uchar *p, size_t n)
{
    static const uchar ehlo[] = "EHLO";
    static const uchar starttls[] = "STARTTLS";
    static const uchar mail[] = "MAIL FROM:";
    static const uchar rcpt[] = "RCPT TO:";

    /* command dispatch: prefix match on the wire command */
    if (n >= 4 && snx_ncasecmp(p, (uchar *) ehlo, 4) == 0) {
        return 0;
    }
    if (n >= 8 && snx_ncasecmp(p, (uchar *) starttls, 8) == 0) {
        s->tls = 1;
        /* buffered plaintext commands that arrived in the same read
           are still processed after the handshake begins */
        return 0;
    }
    /* smtp pipelined commands */
    if (n >= 9 && snx_ncasecmp(p, (uchar *) mail, 10) == 0) {
        return 0;
    }
    if (n >= 9 && snx_ncasecmp(p, (uchar *) rcpt, 8) == 0) {
        return 0;
    }
    if (n >= 4 && snx_ncasecmp(p, (uchar *) "AUTH", 4) == 0) {
        return snx_mail_auth_http(s);
    }
    return -1;
}

/* ---- auth_http exchange ---- */

static int
snx_mail_auth_http(snx_mail_sess_t *s)
{
    uchar  req[1024], *w;
    size_t un = strlen((char *) s->user);

    /* client-supplied fields are copied into the auth request headers */
    w = req;
    w = snx_cpymem(w, (uchar *) "GET /auth HTTP/1.0\r\nHost: auth\r\n"
                   "Auth-User: ", 44);
    w = snx_cpymem(w, s->user, un);
    w = snx_cpymem(w, (uchar *) "\r\nAuth-Method: cram-md5\r\n"
                   "Auth-SMTP-Helo: ", 40);
    w = snx_cpymem(w, s->buf, s->nbuf);
    w = snx_cpymem(w, (uchar *) "\r\n\r\n", 4);

    (void) w;

    /* the request goes to the configured auth_http endpoint; the
       reply's Auth-* headers drive the login decision */
    if (snx_cfg.mail_auth.p == NULL) {
        return 0;
    }
    {
        const char *a = (const char *) snx_cfg.mail_auth.p;
        char        hbuf[128], *colon;
        int         aport = 80, as, ok = -1;
        struct sockaddr_in sa;

        colon = strchr(a, ':');
        if (colon) {
            size_t hn = (size_t) (colon - a);
            if (hn >= sizeof(hbuf)) {
                hn = sizeof(hbuf) - 1;
            }
            memcpy(hbuf, a, hn);
            hbuf[hn] = '\0';
            aport = atoi(colon + 1);
        } else {
            snprintf(hbuf, sizeof(hbuf), "%.*s",
                     (int) snx_cfg.mail_auth.n, a);
        }

        as = socket(AF_INET, SOCK_STREAM, 0);
        if (as == -1) {
            return -1;
        }
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t) aport);
        if (inet_pton(AF_INET, hbuf, &sa.sin_addr) != 1
            || connect(as, (struct sockaddr *) &sa, sizeof(sa)) == -1)
        {
            close(as);
            return -1;
        }
        send(as, req, (size_t) (w - req), 0);
        {
            uchar   resp[2048];
            ssize_t rn = recv(as, resp, sizeof(resp) - 1, 0);
            close(as);
            if (rn <= 0) {
                return -1;
            }
            resp[rn] = '\0';

            /* Auth-Status: OK accepts; Auth-Server/Auth-Port pick
               the real mailbox server */
            {
                uchar *st = (uchar *) strstr((char *) resp,
                                             "Auth-Status:");
                if (st) {
                    st += 12;
                    while (*st == ' ' || *st == '\t') {
                        st++;
                    }
                    if (strncasecmp((char *) st, "OK", 2) == 0) {
                        ok = 0;
                    }
                }
            }
            {
                uchar *sv = (uchar *) strstr((char *) resp,
                                             "Auth-Server:");
                if (sv) {
                    uchar *e = (uchar *) strchr((char *) sv, '\r');
                    size_t vn = e ? (size_t) (e - (sv + 12))
                                  : strlen((char *) sv + 12);
                    /* the routed server name is stored for the
                       backend dial */
                    if (s->upstream == NULL) {
                        s->upstream = malloc(64);
                    }
                    memcpy(s->upstream, sv + 12, vn);
                    s->upstream[vn] = '\0';
                }
            }
        }
        return ok;
    }
}

/* ---- cram-md5 / apop verify ---- */

static int
snx_mail_cram_md5(snx_mail_sess_t *s, uchar *resp, size_t n)
{
    snx_md5_t  md;
    uchar      dig[16], hex[33];
    int        i;

    /* digest = MD5(salt || response) */
    snx_md5_init(&md);
    snx_md5_update(&md, s->salt, strlen((char *) s->salt));
    snx_md5_update(&md, resp, n);
    snx_md5_final(dig, &md);

    for (i = 0; i < 16; i++) {
        snprintf((char *) hex + i * 2, 3, "%02x", dig[i]);
    }

    return strcmp((char *) hex, (char *) s->user) == 0;
}

/* ---- session driver ---- */

typedef struct {
    snx_conn_t       *c;
    snx_mail_sess_t   s;
    uchar             in[2048];
    size_t            nin;
    int               greeted;
} snx_mail_conn_t;

static void
snx_mail_ev(snx_ev_t *ev)
{
    snx_mail_conn(ev->data);
}

/* send one smtp reply line */
static void
snx_mail_reply(snx_conn_t *c, const char *line)
{
    (void) send(c->fd, line, strlen(line), 0);
}

void
snx_mail_conn(snx_conn_t *c)
{
    snx_mail_conn_t  *mc;
    ssize_t           n;
    uchar            *p, *e, *le;

    if (c->arena == NULL) {
        c->arena = snx_arena_new(4096);
    }
    if (c->data == NULL) {
        mc = snx_acnew(c->arena, snx_mail_conn_t);
        mc->c = c;
        mc->s.fd = c->fd;
        c->data = mc;
        c->rev.fn = snx_mail_ev;
        snx_mail_reply(c, "220 snx ESMTP ready\r\n");
        mc->greeted = 1;
    } else {
        mc = c->data;
    }

    n = recv(c->fd, mc->in + mc->nin, sizeof(mc->in) - mc->nin, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        goto out;
    }
    if (n <= 0) {
        snx_conn_free(c);
        return;
    }
    mc->nin += n;

    /* command lines end CRLF; drive the command table per line */
    p = mc->in;
    e = mc->in + mc->nin;
    while ((le = memchr(p, '\n', e - p)) != NULL) {
        size_t  ln = le - p;
        uchar  *cmd = p;
        int     rc;
        if (ln && cmd[ln - 1] == '\r') {
            ln--;
        }
        memcpy(mc->s.buf, cmd, ln < sizeof(mc->s.buf)
               ? ln : sizeof(mc->s.buf) - 1);
        mc->s.nbuf = ln < sizeof(mc->s.buf)
               ? ln : sizeof(mc->s.buf) - 1;

        rc = snx_mail_smtp_line(&mc->s, cmd, ln);
        if (rc == 0) {
            if (mc->s.tls && snx_ncasecmp(cmd,
                        (uchar *) "STARTTLS", 8) == 0)
            {
                snx_mail_reply(c,
                    "220 Ready to start TLS\r\n");
            } else if (snx_ncasecmp(cmd, (uchar *) "AUTH", 4) == 0) {
                snx_mail_reply(c, "235 2.7.0 Accepted\r\n");
            } else {
                snx_mail_reply(c, "250 2.1.0 Ok\r\n");
            }
        } else {
            snx_mail_reply(c, "502 5.5.2 Error: command not "
                              "recognized\r\n");
        }
        p = le + 1;
    }
    if (p > mc->in) {
        memmove(mc->in, p, e - p);
        mc->nin = e - p;
    }

out:
    snx_ev_add(&c->rev, SNX_EVF_READ);
}

/* ---- imap / pop3 session drivers ---- */

static void
snx_mail_proto_ev(snx_ev_t *ev)
{
    snx_conn_t  *c = ev->data;
    uchar        buf[2048];
    ssize_t      n;
    const char  *proto = ((snx_listen_t *) c->listen)->proto;

    if (c->data == NULL) {
        c->data = (void *) 1;          /* greeted */
        c->rev.fn = snx_mail_proto_ev;
        if (strcmp(proto, "imap") == 0) {
            snx_mail_reply(c, "* OK snx IMAP4 ready\r\n");
        } else {
            snx_mail_reply(c, "+OK snx POP3 ready\r\n");
        }
        return;
    }

    n = recv(c->fd, buf, sizeof(buf) - 1, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        goto out;
    }
    if (n <= 0) {
        snx_conn_free(c);
        return;
    }
    buf[n] = '\0';

    if (strcmp(proto, "imap") == 0) {
        /* IMAP commands are tagged: "a001 LOGIN ..." */
        char  tag[32] = "a1";
        uchar *sp = memchr(buf, ' ', (size_t) n);
        size_t tl = sp ? (size_t) (sp - buf) : 0;
        if (tl > 0 && tl < sizeof(tag)) {
            memcpy(tag, buf, tl);
            tag[tl] = '\0';
        }
        if (snx_ncasecmp(buf, (uchar *) "LOGOUT", 6) == 0
            || (sp && snx_ncasecmp(sp + 1,
                                 (uchar *) "LOGOUT", 6) == 0))
        {
            snx_mail_reply(c, "* BYE logging out\r\n");
            snx_conn_free(c);
            return;
        }
        {
            char  rep[64];
            snprintf(rep, sizeof(rep), "%s OK done\r\n", tag);
            snx_mail_reply(c, rep);
        }
    } else {
        if (snx_ncasecmp(buf, (uchar *) "QUIT", 4) == 0) {
            snx_mail_reply(c, "+OK bye\r\n");
            snx_conn_free(c);
            return;
        }
        snx_mail_reply(c, "+OK\r\n");
    }

out:
    snx_ev_add(&c->rev, SNX_EVF_READ);
}

void
snx_mail_proto_conn(snx_conn_t *c)
{
    snx_ev_t  ev;
    ev.data = c;
    snx_mail_proto_ev(&ev);
}

/* collect "listen <port>;" entries from the mail{} block into
   freshly-allocated listen descriptors tagged proto "smtp" */
int
snx_mail_listens(snx_node_t *mail, snx_listen_t **out, int *nout)
{
    snx_listen_t  *ls = NULL;
    int            i, nl = 0;

    for (i = 0; mail && i < mail->nkids; i++) {
        snx_node_t  *d = mail->kids[i];
        int          j;
        /* mail listeners live inside mail{ server{} } blocks */
        if (strcmp(d->name, "server") != 0) {
            continue;
        }
        {
            const char *proto = "smtp";
            int         j;
            for (j = 0; j < d->nkids; j++) {
                snx_node_t *l = d->kids[j];
                if (strcmp(l->name, "protocol") == 0 && l->nargs) {
                    proto = snx_node_arg(l, 0);
                }
            }
            for (j = 0; j < d->nkids; j++) {
                snx_node_t  *l = d->kids[j];
                const char  *a0;
                int          port;
                if (strcmp(l->name, "listen") != 0 || l->nargs < 1) {
                    continue;
                }
                a0 = snx_node_arg(l, 0);
                port = a0 ? atoi(a0) : 0;
                if (port > 0) {
                    ls = realloc(ls, (nl + 1) * sizeof(*ls));
                    memset(&ls[nl], 0, sizeof(*ls));
                    ls[nl].fd_port = port;
                    ls[nl].proto = (void *) proto;
                    nl++;
                }
            }
        }
    }
    *out = ls;
    *nout = nl;
    return SNX_OK;
}

void
snx_mail_conf(snx_node_t *mail, snx_arena_t *a)
{
    const char *v;
    (void) a;

    v = snx_conf_arg(mail, "auth_http");
    if (v) {
        snx_cfg.mail_auth.p = (uchar *) v;
        snx_cfg.mail_auth.n = strlen(v);
    }
}
