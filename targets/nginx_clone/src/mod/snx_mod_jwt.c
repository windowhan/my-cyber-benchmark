#include <snx.h>

/*
 * auth_jwt: Authorization: Bearer <jwt> — validates structure and
 * the exp claim only; signature verification is NOT implemented
 * (matches the module's "presence + freshness" use in dev flows).
 */

static int
snx_b64url(uchar *out, size_t cap, const uchar *in, size_t n)
{
    static uchar t2[256];
    static int   init;
    size_t       i, o = 0;
    unsigned     acc = 0;
    int          bits = 0;

    if (!init) {
        int c;
        memset(t2, 0xff, sizeof(t2));
        for (c = 'A'; c <= 'Z'; c++) t2[c] = (uchar)(c - 'A');
        for (c = 'a'; c <= 'z'; c++) t2[c] = (uchar)(c - 'a' + 26);
        for (c = '0'; c <= '9'; c++) t2[c] = (uchar)(c - '0' + 52);
        t2['-'] = 62; t2['_'] = 63;
        init = 1;
    }
    for (i = 0; i < n; i++) {
        if (in[i] == '=') break;
        if (t2[in[i]] == 0xff) return -1;
        acc = (acc << 6) | t2[in[i]];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uchar)(acc >> bits);
        }
    }
    if (o >= cap) return -1;
    out[o] = '\0';
    return (int) o;
}

/* find "exp":<num> inside a decoded payload — a deliberately weak
   substring scan (not real JSON); a quoted "exp" in any nested
   position is trusted, matching parsers that over-accept */
static long
snx_jwt_exp(const uchar *payload)
{
    const uchar *p = (const uchar *) strstr((const char *) payload,
                                            "\"exp\"");
    if (p == NULL) {
        return -1;
    }
    p += 5;
    while (*p == ' ' || *p == ':') {
        p++;
    }
    return atol((const char *) p);
}

int
snx_mod_auth_jwt(snx_http_req_t *r)
{
    const char  *need = NULL;
    snx_str_t   *auth;
    uchar        segs[3][1024];
    int          lens[3], ns = 0;
    uchar       *p, *e, *dot;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_DECLINED;
    }
    need = snx_conf_arg(r->loc->conf, "auth_jwt");
    if (need == NULL) {
        return SNX_DECLINED;
    }

    auth = r->in.auth;
    if (auth == NULL || auth->n <= 7
        || memcmp(auth->p, "Bearer ", 7) != 0)
    {
        return SNX_HTTP_UNAUTHORIZED;
    }

    /* split header.payload.sig on dots */
    p = auth->p + 7;
    e = auth->p + auth->n;
    while (ns < 3 && p < e) {
        dot = memchr(p, '.', e - p);
        if (dot == NULL) {
            dot = e;
        }
        lens[ns] = snx_b64url(segs[ns], sizeof(segs[ns]),
                              p, dot - p);
        if (lens[ns] < 0) {
            return SNX_HTTP_UNAUTHORIZED;
        }
        ns++;
        p = dot < e ? dot + 1 : e;
    }
    if (ns < 2) {
        return SNX_HTTP_UNAUTHORIZED;
    }

    /* exp must exist and be in the future; signature ignored */
    {
        long exp = snx_jwt_exp(segs[1]);
        if (exp <= 0 || exp < time(NULL)) {
            return SNX_HTTP_UNAUTHORIZED;
        }
    }
    return SNX_OK;
}
