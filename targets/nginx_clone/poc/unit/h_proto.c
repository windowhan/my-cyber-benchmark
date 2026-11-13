/* unit harness: crafted frames -> h2 / spdy / h3+quic routines */
#include <snx.h>
#include <time.h>
#include <zlib.h>

#include "../src/proto/snx_h2.c"
#include "../src/proto/snx_spdy.c"
#include "../src/proto/snx_h3.c"

static snx_conn_t  fconn;
static snx_arena_t *farena;

static void
setup(void)
{
    farena = snx_arena_new(1 << 20);
    memset(&fconn, 0, sizeof(fconn));
    fconn.fd = -1;
    fconn.arena = farena;
}

static double
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* build a zlib-deflated spdy name/value block */
static size_t
deflate_nv(uchar *out, size_t cap, const uchar *in, size_t inlen)
{
    uLongf  d = cap;
    if (compress2(out, &d, in, inlen, Z_BEST_SPEED) != Z_OK) {
        return 0;
    }
    return d;
}

int
main(int argc, char **argv)
{
    const char *cve = argc > 1 ? argv[1] : "";
    setup();

    /* ==================== h2 ==================== */
    if (strcmp(cve, "CVE-2019-9516") == 0
        || strcmp(cve, "CVE-2018-16843") == 0)
    {
        /* CONTINUATION accumulation has no cap */
        snx_h2_conn_t h2 = { 0 };
        uchar  frag[1024];
        int    i;
        snx_h2_stream_t *s;

        h2.c = &fconn;
        memset(frag, 'a', sizeof(frag));
        for (i = 0; i < 200; i++) {
            snx_h2_headers(&h2, 7, frag, sizeof(frag));
        }
        for (s = h2.streams; s && s->id != 7; s = s->next) {
        }
        printf("hdr_len=%zu\n", s ? s->hdr_len : 0);
        if (s && s->hdr_len > 64000) {
            printf("VULNERABLE: unbounded header accumulation\n");
            return 1;
        }
        printf("ok\n");

    } else if (strcmp(cve, "CVE-2019-9511") == 0) {
        /* each WINDOW_UPDATE rescans the entire pending buffer */
        snx_h2_conn_t h2 = { 0 };
        uchar  frag[64];
        double t0;
        int    i;

        h2.c = &fconn;
        h2.nin = sizeof(h2.inbuf);
        memset(frag, 0, sizeof(frag));
        snx_h2_headers(&h2, 3, frag, sizeof(frag));

        t0 = now_ms();
        for (i = 0; i < 50000; i++) {
            snx_h2_window_update(&h2, 3, 1);
        }
        printf("elapsed=%.0fms\n", now_ms() - t0);
        if (now_ms() - t0 > 5) {
            printf("VULNERABLE: O(buffer) work per update\n");
            return 1;
        }
        printf("ok\n");

    } else if (strcmp(cve, "CVE-2019-9513") == 0
           || strcmp(cve, "CVE-2018-16844") == 0)
    {
        /* every PRIORITY update walks the full stream list */
        snx_h2_conn_t h2 = { 0 };
        uchar  frag[32];
        double t0;
        int    i;

        h2.c = &fconn;
        memset(frag, 0, sizeof(frag));
        for (i = 1; i <= 6000; i++) {
            snx_h2_headers(&h2, (uint32_t) i * 2 + 1, frag,
                           sizeof(frag));
        }
        t0 = now_ms();
        for (i = 0; i < 6000; i++) {
            snx_h2_priority(&h2, 3, 0, 16);
        }
        printf("elapsed=%.0fms\n", now_ms() - t0);
        if (now_ms() - t0 > 5) {
            printf("VULNERABLE: O(streams) work per frame\n");
            return 1;
        }
        printf("ok\n");

    /* ==================== spdy ==================== */
    } else if (strcmp(cve, "CVE-2014-0133") == 0) {
        /* nv buffer sized nl, then nv[nl]='\0' writes one past */
        snx_spdy_conn_t sp = { 0 };
        uchar  nv[64], comp[256], frame[512];
        size_t cl;
        uchar *q = nv;

        /* inflated entries: nvals=1, nl=8, name, vl=1, val */
        memset(q, 0, sizeof(nv));
        *q++ = 0; *q++ = 0; *q++ = 0; *q++ = 1;
        *q++ = 0; *q++ = 0; *q++ = 0; *q++ = 8;
        memcpy(q, ":method:", 8); q += 8;
        *q++ = 0; *q++ = 0; *q++ = 0; *q++ = 1;
        *q++ = 'x';
        cl = deflate_nv(comp, sizeof(comp), nv, q - nv);
        memset(frame, 0, 10);
        memcpy(frame + 10, comp, cl);
        sp.c = &fconn;
        (void) snx_spdy_syn_stream(&sp, frame, 10 + cl);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2014-0088") == 0) {
        /* name copy reads nl bytes from the inflated block even
           when fewer remain */
        snx_spdy_conn_t sp = { 0 };
        uchar  nv[64], comp[256], frame[512];
        size_t cl;
        uchar *q = nv;

        memset(q, 0, sizeof(nv));
        *q++ = 0; *q++ = 0; *q++ = 0; *q++ = 1;
        *q++ = 0; *q++ = 0; *q++ = 0xFF; *q++ = 0xFF;   /* nl=65535 */
        memcpy(q, "short", 5); q += 5;
        cl = deflate_nv(comp, sizeof(comp), nv, q - nv);
        memset(frame, 0, 10);
        memcpy(frame + 10, comp, cl);
        sp.c = &fconn;
        (void) snx_spdy_syn_stream(&sp, frame, 10 + cl);
        printf("no crash\n");

    /* ==================== h3 / quic ==================== */
    } else if (strcmp(cve, "CVE-2026-90439") == 0) {
        /* dcid/scid fields are 20 bytes; a 31-byte connection id
           memcpy overruns into the next field */
        snx_quic_t  q = { 0 };
        uchar  pkt[128], *p = pkt;

        q.c = &fconn;
        memset(q.scid, 0x41, sizeof(q.scid));
        *p++ = 0xc0;                     /* long header */
        p += 4; /* version */ memset(p - 4, 0, 4);
        *p++ = 31;                       /* dcid len > field size */
        memset(p, 0x42, 31); p += 31;
        *p++ = 4;  memset(p, 0x99, 4); p += 4;   /* scid */
        *p++ = 0;                        /* len varint */
        (void) snx_quic_packet(&q, pkt, p);
        /* dcid overflow wrote 0x42 across scid[0..10]; the scid
           memcpy only restored scid[0..3] */
        if (q.scid[4] == 0x42) {
            printf("VULNERABLE: dcid overflow clobbered scid\n");
            return 1;
        }
        printf("ok scid[4]=%02x\n", q.scid[4]);

    } else if (strcmp(cve, "CVE-2024-32760") == 0) {
        /* LEN field larger than the frame: memcpy reads past the
           packet buffer */
        snx_quic_t  q = { 0 };
        uchar  fr[64], *w = fr;

        q.c = &fconn;
        *w++ = 0x01;                     /* sid */
        *w++ = 0x44;                     /* 2B varint + LEN bit */
        *w++ = 0x10;                     /* len = 0x0410 = 1040 */
        memset(w, 'd', 8); w += 8;       /* only 8 payload bytes */
        (void) snx_quic_stream_frame(&q, fr, w);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2024-34161") == 0) {
        /* second frame allocates a smaller buffer but still
           copies the old stream length */
        snx_quic_t  q = { 0 };
        uchar  f1[2100], f2[64], *w;

        q.c = &fconn;
        w = f1; *w++ = 0x01;             /* sid 1 */
        memset(w, 'x', 2000); w += 2000;
        (void) snx_quic_stream_frame(&q, f1, w);

        w = f2; *w++ = 0x01;             /* sid 1 */
        *w++ = 0x04;                     /* LEN bit, 1B varint = 4 */
        memset(w, 'y', 4); w += 4;
        (void) snx_quic_stream_frame(&q, f2, w);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2024-31079") == 0) {
        /* literal field name longer than 256 overruns the stack
           name buffer */
        snx_quic_t     q = { 0 };
        snx_qstream_t  s = { 0 };
        static uchar   blk[1024];
        uchar  *w = blk;

        q.c = &fconn;
        *w++ = 0x00;                     /* literal type (no 0x80) */
        *w++ = 0x82;                     /* 2B varint name len */
        *w++ = 0xF0;                     /* nl = 0x02F0 = 752 */
        memset(w, 'n', 500); w += 500;
        *w++ = 0x01;                     /* value len 1 */
        *w++ = 'v';
        s.data = blk;
        s.len = w - blk;
        (void) snx_h3_headers(&q, &s);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2026-42530") == 0) {
        /* stream data freed at fin; next frame's reassembly
           memcpy reads the freed buffer */
        snx_quic_t  q = { 0 };
        uchar  f1[64], f2[64], *w;
        snx_qstream_t *s;

        q.c = &fconn;
        w = f1; *w++ = 0x01; memset(w, 'x', 8); w += 8;
        (void) snx_quic_stream_frame(&q, f1, w);
        for (s = q.streams; s && s->id != 1; s = s->next) {
        }
        free(s->data);                   /* request layer released */
        /* s->data still points at freed storage */
        w = f2; *w++ = 0x01; memset(w, 'y', 8); w += 8;
        (void) snx_quic_stream_frame(&q, f2, w);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2024-24990") == 0) {
        /* freed stream data is still walked on repeat processing */
        snx_quic_t     q = { 0 };
        snx_qstream_t  s = { 0 };
        uchar  *blk = malloc(64);

        q.c = &fconn;
        memset(blk, 0, 64);
        blk[0] = 0x80;                   /* indexed field line */
        s.data = blk;
        s.len = 64;
        free(s.data);                    /* request released it */
        (void) snx_h3_headers(&q, &s);   /* walks freed storage */
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2024-35200") == 0) {
        /* fin frees s->data; a second fin pass frees it again */
        snx_quic_t     q = { 0 };
        snx_qstream_t  s = { 0 };
        uchar  *blk = malloc(64);

        q.c = &fconn;
        memset(blk, 0, 64);
        s.data = blk;
        s.len = 64;
        (void) snx_h3_request(&q, &s);   /* frees s->data */
        (void) snx_h3_request(&q, &s);   /* frees it again */
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2024-24989") == 0) {
        /* malloc failure leaves nb NULL; memcpy(nb+off) crashes */
        snx_quic_t  q = { 0 };
        uchar  fr[32], *w = fr;

        q.c = &fconn;
        *w++ = 0x01;                     /* sid */
        *w++ = 0xCF;                     /* 8B varint + OFF bit */
        memset(w, 0xff, 7); w += 7;      /* off = huge */
        memset(w, 'd', 4); w += 4;
        (void) snx_quic_stream_frame(&q, fr, w);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2026-40460") == 0) {
        /* peer identity is taken from the packet's own SCID */
        snx_quic_t  q = { 0 };
        uchar  pkt[64], *p = pkt;
        static const uchar  attacker[8] = { 'A','T','T','A',
                                            'C','K','E','D' };

        q.c = &fconn;
        *p++ = 0xc0;
        memset(p, 0, 4); p += 4;         /* version */
        *p++ = 4;  memset(p, 0x11, 4); p += 4;   /* dcid */
        *p++ = 8;  memcpy(p, attacker, 8); p += 8; /* scid */
        *p++ = 0;                        /* len */
        (void) snx_quic_packet(&q, pkt, p);
        if (memcmp(q.scid, attacker, 8) == 0) {
            printf("VULNERABLE: source identity from packet scid\n");
            return 1;
        }
        printf("ok\n");

    } else if (strcmp(cve, "CVE-2026-95101") == 0) {
        /* DATA frame payloads are forwarded to the request layer
           without accounting */
        snx_quic_t     q = { 0 };
        snx_qstream_t  s = { 0 };
        uchar  *blk = malloc(64), *w = blk;
        int     rc;

        q.c = &fconn;
        *w++ = 0x00;                     /* DATA frame type */
        *w++ = 0x20;                     /* length 32 */
        memset(w, 0x41, 32); w += 32;
        s.data = blk;
        s.len = w - blk;
        rc = snx_h3_request(&q, &s);
        if (rc == SNX_OK) {
            printf("VULNERABLE: DATA payload accepted verbatim\n");
            return 1;
        }
        printf("ok\n");

    } else {
        fprintf(stderr, "unknown\n");
        return 2;
    }
    return 0;
}
