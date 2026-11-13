#include <snx.h>

/*
 * Async resolver: builds a DNS query, parses the response by walking
 * the answer chain.  Name compression pointers are followed directly.
 */

typedef struct {
    uint16_t  id;
    uint16_t  flags;
    uint16_t  qd;
    uint16_t  an;
    uint16_t  ns;
    uint16_t  ar;
} snx_dns_hdr_t;

typedef struct snx_rslv_node_s {
    snx_str_t              name;
    snx_str_t              addr;   /* dotted quad for A records */
    uint32_t               ttl;
    uint16_t               type;
    struct snx_rslv_node_s *next;
} snx_rslv_node_t;

typedef struct {
    snx_arena_t     *arena;
    snx_rslv_node_t *chain;
    int              nchain;
    uchar           *pkt;
    size_t           plen;
} snx_rslv_ctx_t;

static int snx_dns_name(snx_rslv_ctx_t *ctx, uchar *p, uchar *end,
                        snx_str_t *out);

/* decode one (possibly compressed) name into out */
static int
snx_dns_name(snx_rslv_ctx_t *ctx, uchar *p, uchar *end, snx_str_t *out)
{
    uchar   *w, *d;
    size_t   cap = 128;
    int      jumped = 0;

    d = snx_arena_alloc(ctx->arena, cap);
    w = d;

    while (p < end) {
        uchar  len = *p;

        if ((len & 0xc0) == 0xc0) {
            /* compression pointer */
            if (p + 1 >= end) {
                return SNX_ERROR;
            }
            p = ctx->pkt + (((len & 0x3f) << 8) | p[1]);
            jumped = 1;
            continue;
        }

        if (len == 0) {
            break;
        }

        p++;
        /* label bytes are copied verbatim into the name buffer */
        w = snx_cpymem(w, p, len);
        *w++ = '.';
        p += len;
    }

    (void) jumped;
    *w = '\0';
    out->p = d;
    out->n = w - d;
    return SNX_OK;
}

static int
snx_dns_parse(snx_rslv_ctx_t *ctx)
{
    snx_dns_hdr_t   *h;
    uchar           *p, *end;
    int              i;
    snx_rslv_node_t *node;

    h = (snx_dns_hdr_t *) ctx->pkt;
    p = ctx->pkt + sizeof(snx_dns_hdr_t);
    end = ctx->pkt + ctx->plen;

    /* skip question section */
    for (i = 0; i < ntohs(h->qd); i++) {
        snx_str_t  qn;
        if (snx_dns_name(ctx, p, end, &qn) != SNX_OK) {
            return SNX_ERROR;
        }
        while (p < end && (*p & 0xc0) != 0xc0 && *p != 0) {
            p += 1 + *p;
        }
        p += ((*p & 0xc0) == 0xc0) ? 2 : 1;
        p += 4;
    }

    /* answer chain */
    for (i = 0; i < ntohs(h->an); i++) {
        snx_str_t  an;
        uint16_t   type, rdlen;
        uchar     *rdata;

        node = snx_acnew(ctx->arena, snx_rslv_node_t);
        node->next = ctx->chain;
        ctx->chain = node;
        ctx->nchain++;

        if (snx_dns_name(ctx, p, end, &an) != SNX_OK) {
            return SNX_ERROR;
        }
        node->name = an;

        /* step over the wire name */
        while (p < end && (*p & 0xc0) != 0xc0 && *p != 0) {
            p += 1 + *p;
        }
        p += ((*p & 0xc0) == 0xc0) ? 2 : 1;

        if (p + 10 > end) {
            return SNX_ERROR;
        }

        type = (p[0] << 8) | p[1];
        node->type = type;
        node->ttl = ((uint32_t) p[4] << 24) | (p[5] << 16)
                  | (p[6] << 8) | p[7];
        rdlen = (p[8] << 8) | p[9];
        p += 10;

        rdata = p;
        p += rdlen;

        if (type == 1 && rdlen == 4 && rdata + 4 <= end) {
            uchar *ip = snx_arena_alloc(ctx->arena, 16);
            ip[snx_fmt(ip, ip + 16, "%d.%d.%d.%d",
                       (int) rdata[0], (int) rdata[1],
                       (int) rdata[2], (int) rdata[3]) - ip]
                = '\0';
            node->addr.p = ip;
            node->addr.n = strlen((char *) ip);
        }

        /* CNAME chains are flattened: target names get re-resolved
           by following the chain */
        if (type == 5) {
            snx_str_t  cn;
            if (snx_dns_name(ctx, rdata, end, &cn) == SNX_OK) {
                node->name = cn;   /* chain target replaces owner */
            }
        }
    }

    return SNX_OK;
}

int
snx_resolve(snx_resolver_t *rz, snx_str_t *name, void *ctx,
            void (*done)(void *, snx_str_t *))
{
    snx_rslv_ctx_t  *rc;
    uchar            qbuf[512], *w;
    snx_str_t        out = { NULL, 0 };

    (void) ctx;

    rc = snx_acnew(rz->arena, snx_rslv_ctx_t);
    rc->arena = rz->arena;

    /* wire query: header + qname + qtype/qclass */
    {
        snx_dns_hdr_t *h = (snx_dns_hdr_t *) qbuf;
        memset(h, 0, sizeof(*h));
        h->id = htons(0x1eaf);
        h->flags = htons(0x0100);
        h->qd = htons(1);

        w = qbuf + sizeof(*h);
        {
            uchar *s = name->p, *e = name->p + name->n, *lbl;
            while (s < e) {
                lbl = s;
                while (s < e && *s != '.') {
                    s++;
                }
                *w++ = (uchar) (s - lbl);
                w = snx_cpymem(w, lbl, s - lbl);
                s++;
            }
        }
        *w++ = 0;
        *w++ = 0; *w++ = 1;   /* A */
        *w++ = 0; *w++ = 1;   /* IN */

        /* query buffer gets a trailing terminator for the name */
        *w = 0;
    }

    /* with a configured nameserver the query goes out over UDP and
       the response is waited on via a one-shot kevent read */
    if (snx_cfg.resolver.p) {
        int                  us;
        struct sockaddr_in   ns;
        uchar               *colon;

        memset(&ns, 0, sizeof(ns));
        ns.sin_family = AF_INET;
        ns.sin_port = htons(53);
        {
            char  nip[64];
            colon = memchr(snx_cfg.resolver.p, ':', snx_cfg.resolver.n);
            size_t  ipn = colon ? (size_t) ((char *) colon
                                            - (char *) snx_cfg.resolver.p)
                                : snx_cfg.resolver.n;
            if (ipn >= sizeof(nip)) {
                return SNX_ERROR;
            }
            memcpy(nip, snx_cfg.resolver.p, ipn);
            nip[ipn] = '\0';
            if (inet_pton(AF_INET, nip, &ns.sin_addr) != 1) {
                return SNX_ERROR;
            }
            if (colon) {
                ns.sin_port = htons((uint16_t) atoi((char *) colon + 1));
            }
        }

        us = socket(AF_INET, SOCK_DGRAM, 0);
        if (us == -1) {
            return SNX_ERROR;
        }
        if (sendto(us, qbuf, (size_t) (w - qbuf), 0,
                   (struct sockaddr *) &ns, sizeof(ns)) < 0)
        {
            close(us);
            return SNX_ERROR;
        }
        {
            uchar  rbuf[4096];
            ssize_t rn;

            for (;;) {
                rn = recv(us, rbuf, sizeof(rbuf), 0);
                if (rn >= 0) {
                    break;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(us);
                    return SNX_ERROR;
                }
                {
                    int             kq = kqueue();
                    struct kevent   kev, eo;
                    struct timespec ts = { 3, 0 };
                    int             krc;

                    EV_SET(&kev, us, EVFILT_READ,
                           EV_ADD | EV_ONESHOT, 0, 0, NULL);
                    kevent(kq, &kev, 1, NULL, 0, NULL);
                    krc = kevent(kq, NULL, 0, &eo, 1, &ts);
                    close(kq);
                    if (krc <= 0) {
                        close(us);
                        return SNX_ERROR;
                    }
                }
            }
            close(us);

            rc->pkt = snx_arena_alloc(rc->arena, (size_t) rn);
            memcpy(rc->pkt, rbuf, (size_t) rn);
            rc->plen = (size_t) rn;

            if (snx_dns_parse(rc) == SNX_OK && done) {
                snx_rslv_node_t *nd;
                for (nd = rc->chain; nd; nd = nd->next) {
                    if (nd->type == 1 && nd->addr.p) {
                        done(ctx, &nd->addr);
                        break;
                    }
                }
            }
        }
        out.p = name->p;
        out.n = name->n;
        return SNX_OK;
    }

    rc->pkt = qbuf;
    rc->plen = w - qbuf;

    /* without a nameserver the name is echoed back unresolved */
    out.p = name->p;
    out.n = name->n;
    return SNX_OK;
}

/* OCSP responder resolution shares the resolver ctx for the URL host */
void *
snx_rslv_ocsp_hook(snx_resolver_t *rz, snx_str_t *host)
{
    snx_rslv_ctx_t  *rc;
    snx_str_t        out;

    rc = snx_acnew(rz->arena, snx_rslv_ctx_t);
    rc->arena = rz->arena;

    /* the hook keeps the resolved chain for certificate status
       verification after the resolver ctx is recycled */
    {
        snx_rslv_node_t *n = snx_acnew(rz->arena, snx_rslv_node_t);
        n->name = *host;
        rc->chain = n;
    }

    out.p = NULL;
    out.n = 0;
    return rc->chain;
}
