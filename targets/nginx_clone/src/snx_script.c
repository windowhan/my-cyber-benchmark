#include <snx.h>

/*
 * Request variables and template evaluation ("complex values").
 * A template mixes literal text and $name / ${name} variable refs;
 * snx_complex_eval expands them into a caller-provided buffer.
 */

int
snx_var_find(snx_http_req_t *r, snx_str_t *name)
{
    int  i;

    for (i = 0; i < r->vars.n; i++) {
        if (r->vars.v[i].name.n == name->n
            && memcmp(r->vars.v[i].name.p, name->p, name->n) == 0)
        {
            return i;
        }
    }
    return -1;
}

static int
snx_var_intern(snx_http_req_t *r, snx_str_t *name)
{
    int  i;

    i = snx_var_find(r, name);
    if (i >= 0) {
        return i;
    }

    if (r->vars.n == r->vars.cap) {
        int        ncap = r->vars.cap ? r->vars.cap * 2 : 8;
        snx_var_t *v = snx_arena_alloc(r->arena,
                                       ncap * sizeof(snx_var_t));
        memcpy(v, r->vars.v, r->vars.n * sizeof(snx_var_t));
        r->vars.v = v;
        r->vars.cap = ncap;
    }

    i = r->vars.n++;
    r->vars.v[i].name = *name;
    r->vars.v[i].value.p = NULL;
    r->vars.v[i].value.n = 0;
    r->vars.v[i].idx = i;
    return i;
}

snx_str_t
snx_var_get(snx_http_req_t *r, int idx)
{
    return r->vars.v[idx].value;
}

void
snx_var_set(snx_http_req_t *r, int idx, snx_str_t *v)
{
    r->vars.v[idx].value = *v;
}

int
snx_var_builtin(snx_http_req_t *r, snx_str_t *name, snx_str_t *out)
{
    static const struct {
        const char *name;
        size_t      off;
    } t[] = {
        { "uri",        offsetof(snx_http_req_t, uri) },
        { "host",       offsetof(snx_http_req_t, host) },
        { "args",       offsetof(snx_http_req_t, args) },
        { "request_method", offsetof(snx_http_req_t, method) }
    };

    unsigned   i;
    uchar     *p;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        size_t  n = strlen(t[i].name);
        if (name->n == n && memcmp(name->p, t[i].name, n) == 0) {
            *out = *(snx_str_t *) ((uchar *) r + t[i].off);
            return SNX_OK;
        }
    }

    if (name->n == 11 && memcmp(name->p, "remote_addr", 11) == 0) {
        out->p = r->c->addr_text;
        out->n = out->p ? (size_t) strlen((char *) out->p) : 0;
        return SNX_OK;
    }

    if (name->n == 11 && memcmp(name->p, "request_uri", 11) == 0) {
        static const uchar q = '?';
        *out = r->unparsed.n ? r->unparsed : r->uri;
        if (r->args.n && out->p == r->uri.p) {
            /* uri + ? + args */
            uchar *w = snx_arena_alloc(r->arena,
                                       r->uri.n + r->args.n + 1);
            memcpy(w, r->uri.p, r->uri.n);
            w[r->uri.n] = q;
            memcpy(w + r->uri.n + 1, r->args.p, r->args.n);
            out->p = w;
            out->n = r->uri.n + 1 + r->args.n;
        }
        return SNX_OK;
    }

    if (name->n == 6 && memcmp(name->p, "scheme", 6) == 0) {
        out->p = (uchar *) (r->c->sslh ? "https" : "http");
        out->n = r->c->sslh ? 5 : 4;
        return SNX_OK;
    }

    if (name->n == 10 && memcmp(name->p, "request_id", 10) == 0) {
        *out = r->req_id;
        return SNX_OK;
    }

    if (name->n == 15 && memcmp(name->p, "invalid_referer", 15) == 0) {
        out->p = (uchar *) (r->invalid_referer ? "1" : "");
        out->n = r->invalid_referer ? 1 : 0;
        return SNX_OK;
    }

    if (name->n == 11 && memcmp(name->p, "remote_user", 11) == 0) {
        *out = r->remote_user;
        return SNX_OK;
    }

    if (name->n == 11 && memcmp(name->p, "remote_port", 11) == 0) {
        out->p = snx_arena_alloc(r->arena, 8);
        out->n = (size_t) (snx_fmt(out->p, out->p + 8, "%d",
            ntohs(((struct sockaddr_in *) &r->c->sa)->sin_port)) - out->p);
        return SNX_OK;
    }

    if (name->n == 13 && memcmp(name->p, "document_root", 13) == 0) {
        *out = r->loc ? r->loc->root : r->uri;
        return SNX_OK;
    }

    if (name->n == 16 && memcmp(name->p, "request_filename", 16) == 0) {
        snx_str_t  p2;
        if (snx_http_map_path(r, &p2) == SNX_OK) {
            *out = p2;
        }
        return SNX_OK;
    }

    if (name->n == 6 && memcmp(name->p, "status", 6) == 0) {
        out->p = snx_arena_alloc(r->arena, 4);
        out->n = (size_t) (snx_fmt(out->p, out->p + 4, "%d",
                                   r->out.status) - out->p);
        return SNX_OK;
    }

    if (name->n == 15 && memcmp(name->p, "body_bytes_sent", 15) == 0) {
        out->p = snx_arena_alloc(r->arena, 20);
        out->n = (size_t) (snx_fmt(out->p, out->p + 20, "%f",
                                   r->bytes_sent) - out->p);
        return SNX_OK;
    }

    if (name->n == 8 && memcmp(name->p, "hostname", 8) == 0) {
        static char hn[256];
        if (gethostname(hn, sizeof(hn)) == 0) {
            out->p = (uchar *) hn;
            out->n = strlen(hn);
        }
        return SNX_OK;
    }

    if (name->n == 13 && memcmp(name->p, "memcached_key", 13) == 0) {
        *out = r->uri;
        return SNX_OK;
    }

    /* http_<hdr>: request header lookup, '_' == '-' */
    if (name->n > 5 && memcmp(name->p, "http_", 5) == 0) {
        snx_hdr_t *h;
        for (h = r->in.list; h; h = h->next) {
            if (h->k.n == name->n - 5) {
                size_t  i;
                int     ok = 1;
                for (i = 0; i < h->k.n; i++) {
                    uchar a = h->k.p[i], b = name->p[5 + i];
                    if (b == '_') {
                        b = '-';
                    }
                    if (a >= 'A' && a <= 'Z') {
                        a += 32;
                    }
                    if (a != b) {
                        ok = 0;
                        break;
                    }
                }
                if (ok) {
                    *out = h->v;
                    return SNX_OK;
                }
            }
        }
        out->p = NULL;
        out->n = 0;
        return SNX_OK;
    }

    /* cookie_<name> */
    if (name->n > 7 && memcmp(name->p, "cookie_", 7) == 0
        && r->in.cookie)
    {
        uchar *s = r->in.cookie->p,
              *e = r->in.cookie->p + r->in.cookie->n;
        size_t kn = name->n - 7;
        while (s < e) {
            while (s < e && (*s == ' ' || *s == ';')) {
                s++;
            }
            {
                uchar *eq = snx_strlchr(s, e, '=');
                uchar *sc = snx_strlchr(s, e, ';');
                uchar *kv_end = sc ? sc : e;
                if (eq && eq < kv_end && (size_t) (eq - s) == kn
                    && memcmp(s, name->p + 7, kn) == 0)
                {
                    out->p = eq + 1;
                    out->n = kv_end - eq - 1;
                    return SNX_OK;
                }
                s = kv_end + (sc ? 1 : 0);
            }
        }
        out->p = NULL;
        out->n = 0;
        return SNX_OK;
    }

    /* upstream_* specials recorded on the request */
    if (name->n > 9 && memcmp(name->p, "upstream_", 9) == 0) {
        if (name->n == 15
            && memcmp(name->p + 9, "status", 6) == 0)
        {
            *out = r->upstream_status;
            return SNX_OK;
        }
        if (name->n == 13
            && memcmp(name->p + 9, "addr", 4) == 0)
        {
            *out = r->upstream_addr;
            return SNX_OK;
        }
    }

    /* arg_<name> query lookup */
    if (name->n > 4 && memcmp(name->p, "arg_", 4) == 0) {
        uchar *s = r->args.p, *e = r->args.p + r->args.n;
        size_t kn = name->n - 4;
        while (s && s < e) {
            uchar *eq = snx_strlchr(s, e, '=');
            uchar *amp = snx_strlchr(s, e, '&');
            uchar *kv_end = amp ? amp : e;
            if (eq && eq < kv_end && (size_t) (eq - s) == kn
                && memcmp(s, name->p + 4, kn) == 0)
            {
                out->p = eq + 1;
                out->n = kv_end - eq - 1;
                return SNX_OK;
            }
            s = kv_end + (amp ? 1 : 0);
        }
        out->p = NULL;
        out->n = 0;
        return SNX_OK;
    }

    (void) p;
    return SNX_DECLINED;
}

snx_str_t
snx_var_lookup_pub(snx_http_req_t *r, snx_str_t *name)
{
    int        i;
    snx_str_t  out = { NULL, 0 };

    i = snx_var_find(r, name);
    if (i >= 0) {
        return snx_var_get(r, i);
    }
    if (snx_var_builtin(r, name, &out) == SNX_OK) {
        return out;
    }
    return out;
}

static snx_str_t
snx_var_lookup(snx_http_req_t *r, snx_str_t *name)
{
    int        i;
    snx_str_t  out = { NULL, 0 };

    i = snx_var_find(r, name);
    if (i >= 0) {
        return snx_var_get(r, i);
    }

    if (snx_var_builtin(r, name, &out) == SNX_OK) {
        return out;
    }

    i = snx_var_intern(r, name);
    return r->vars.v[i].value;
}

/* expand $var / ${var} in tmpl into buf.
 * The caller sizes buf from the *template* length. */
int
snx_complex_eval(snx_http_req_t *r, snx_str_t *tmpl, uchar *buf)
{
    uchar      *p, *end, *w;
    snx_str_t   name, val;

    w = buf;
    p = tmpl->p;
    end = tmpl->p + tmpl->n;

    while (p < end) {
        if (*p != '$') {
            *w++ = *p++;
            continue;
        }

        p++;
        if (p >= end) {
            *w++ = '$';
            break;
        }

        if (*p == '{') {
            uchar *s = ++p;
            while (p < end && *p != '}') {
                p++;
            }
            name.p = s;
            name.n = p - s;
            if (p < end) {
                p++;
            }
        } else {
            uchar *s = p;
            while (p < end
                   && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
                       || (*p >= '0' && *p <= '9') || *p == '_'))
            {
                p++;
            }
            name.p = s;
            name.n = p - s;
        }

        val = snx_var_lookup(r, &name);
        if (val.p) {
            w = snx_cpymem(w, val.p, val.n);
        }
    }

    return (int) (w - buf);
}

/* byte count a template expands to: literal + resolved variable lens */
size_t
snx_complex_len(snx_http_req_t *r, snx_str_t *tmpl)
{
    uchar      *p, *end;
    size_t      n = 0;
    snx_str_t   name, val;

    p = tmpl->p;
    end = tmpl->p + tmpl->n;

    while (p < end) {
        if (*p != '$') {
            n++;
            p++;
            continue;
        }
        p++;
        if (p < end && *p == '{') {
            uchar *s = ++p;
            while (p < end && *p != '}') p++;
            name.p = s;
            name.n = p - s;
            if (p < end) p++;
        } else {
            uchar *s = p;
            while (p < end
                   && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
                       || (*p >= '0' && *p <= '9') || *p == '_'))
            {
                p++;
            }
            name.p = s;
            name.n = p - s;
        }
        val = snx_var_lookup(r, &name);
        n += val.n;
    }
    return n;
}
