/* libFuzzer entry for the snx parsers: http request/header lines,
   uri unescape, hpack block decode, auth_jwt header handling.
   Build:  clang -fsanitize=fuzzer,address,undefined -I src ... */
#include <snx.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* globals owned by snx_main.c, stubbed for the harness */
snx_cfg_t  snx_cfg;
int        snx_conns;
int        snx_conns_total;
int        snx_conns_handled;
int        snx_conns_reading;
int        snx_conns_writing;
int        snx_conns_waiting;

snx_str_t
snx_mime_type(snx_http_req_t *r)
{
    static snx_str_t mt = { (uchar *) "text/html", 9 };
    (void) r;
    return mt;
}

static snx_arena_t *fa;

static int
fz_hpack_cb(const uchar *nm, size_t nl, const uchar *vv, size_t vl,
            void *arg)
{
    volatile size_t sink = 0;
    size_t          i;

    for (i = 0; i < nl && i < 64; i++) {
        sink += nm[i];
    }
    for (i = 0; i < vl && i < 64; i++) {
        sink += vv[i];
    }
    (void) arg;
    return (int) (sink & 0);
}

static void
fz_http(const uint8_t *d, size_t n)
{
    snx_http_req_t *r;
    snx_iobuf_t     b;
    int             rc, i;

    r = snx_acnew(fa, snx_http_req_t);
    r->arena = fa;
    r->in.last = &r->in.list;
    r->state = 0;
    r->req_start = (uchar *) d;
    memset(&b, 0, sizeof(b));
    b.head = (uchar *) d;
    b.tail = (uchar *) d + n;

    rc = snx_http_parse_reqline(r, &b);
    if (rc == SNX_OK && r->uri.n) {
        r->unparsed = r->uri;
        (void) snx_http_unescape_uri(r);
        for (i = 0; i < 64; i++) {
            rc = snx_http_parse_hdline(r, &b);
            if (rc != SNX_OK) {
                break;
            }
        }
    }
}

static void
fz_hpack(const uint8_t *d, size_t n)
{
    snx_hpack_t  hp;

    snx_hpack_init(&hp, fa, 4096);
    (void) snx_hpack_decode(&hp, (uchar *) d, (uchar *) d + n,
                            fz_hpack_cb, NULL);
}

static void
fz_jwt(const uint8_t *d, size_t n)
{
    snx_http_req_t *r;
    snx_loc_t      *loc;
    snx_node_t     *conf, *dir;
    snx_str_t       auth;
    uchar          *tok;

    if (n < 4 || n > 4096) {
        return;
    }
    /* auth_jwt on; */
    conf = snx_acnew(fa, snx_node_t);
    dir = snx_acnew(fa, snx_node_t);
    dir->name = "auth_jwt";
    dir->nargs = 1;
    dir->args = snx_arena_alloc(fa, sizeof(uchar *));
    dir->args[0] = (uchar *) "on";
    conf->nkids = 1;
    conf->kids = snx_arena_alloc(fa, sizeof(snx_node_t *));
    conf->kids[0] = dir;

    loc = snx_acnew(fa, snx_loc_t);
    loc->conf = conf;

    tok = snx_arena_alloc(fa, n + 8);
    memcpy(tok, "Bearer ", 7);
    memcpy(tok + 7, d, n);
    auth.p = tok;
    auth.n = n + 7;

    r = snx_acnew(fa, snx_http_req_t);
    r->arena = fa;
    r->loc = loc;
    r->in.auth = &auth;
    (void) snx_mod_auth_jwt(r);
}

int
LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (fa == NULL) {
        fa = snx_arena_new(1 << 20);
    } else {
        snx_arena_reset(fa);
    }
    fz_http(d, n);
    fz_hpack(d, n);
    fz_jwt(d, n);
    return 0;
}
