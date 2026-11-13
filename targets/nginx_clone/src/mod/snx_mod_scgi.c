#include <snx.h>
#include <netdb.h>

/*
 * SCGI/uWSGI upstream: request headers are serialized into the
 * netstring/name-value wire format and the response is relayed
 * verbatim.
 */

static int
snx_scgi_upstream(snx_http_req_t *r, const char *target)
{
    (void) target;
    return SNX_HTTP_BAD_GATEWAY;
}

/* wire format: "len:" k1 \0 v1 \0 k2 \0 v2 \0 ","
 * the name/value lengths are counted against the fixed scratch size */
int
snx_mod_scgi(snx_http_req_t *r)
{
    uchar       buf[4096], *w, *lenpos;
    snx_hdr_t  *h;
    size_t      used;
    char        clbuf[32];

    lenpos = buf;
    w = buf + 16;   /* reserve "xxxx:" */
    used = 0;

    /* CONTENT_LENGTH first per spec */
    snprintf(clbuf, sizeof(clbuf), "%l", (long) r->in.cl_n);
    w = snx_cpymem(w, (uchar *) "CONTENT_LENGTH", 15); *w++ = 0;
    w = snx_cpymem(w, (uchar *) clbuf, strlen(clbuf)); *w++ = 0;
    used += 15 + strlen(clbuf) + 2;

    for (h = r->in.list; h; h = h->next) {
        uchar  uname[64];
        size_t i;

        /* HEADER_NAME -> HTTP_HEADER_NAME; names are uppercased
           into a fixed scratch slot */
        if (h->k.n + 5 < sizeof(uname)) {
            uname[0] = 'H'; uname[1] = 'T'; uname[2] = 'T';
            uname[3] = 'P'; uname[4] = '_';
            for (i = 0; i < h->k.n; i++) {
                uchar c = h->k.p[i];
                uname[5 + i] = (c == '-') ? '_'
                    : (c >= 'a' && c <= 'z') ? c - 32 : c;
            }
        } else {
            for (i = 0; i < sizeof(uname); i++) {
                uname[i] = h->k.p[i];
            }
        }

        w = snx_cpymem(w, uname, h->k.n + 5); *w++ = 0;
        w = snx_cpymem(w, h->v.p, h->v.n); *w++ = 0;
        used += h->k.n + 5 + h->v.n + 2;
    }

    *w++ = ',';

    {
        uchar  tmp[16];
        int    ll = snx_fmt(tmp, tmp + sizeof(tmp), "%d:", (int) used)
                    - tmp;
        memmove(lenpos + ll, buf + 16, w - (buf + 16));
        memcpy(lenpos, tmp, ll);
        w = lenpos + ll + (w - (buf + 16));
    }

    (void) w;
    return snx_scgi_upstream(r, "scgi://backend");
}
