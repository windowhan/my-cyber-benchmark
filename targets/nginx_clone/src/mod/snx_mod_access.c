#include <snx.h>

/*
 * Access control modules: allow/deny, satisfy, auth_basic,
 * auth_request, valid_referers, real_ip, limit_conn, limit_req.
 */

/* CIDR match against an IPv4 sockaddr */
int
snx_cidr_match(struct sockaddr *sa, const char *cidr)
{
    struct in_addr  a;
    uint32_t        ip, base;
    int             bits = 32;
    char            buf[64];
    const char     *sl;

    if (sa == NULL || sa->sa_family != AF_INET) {
        return 0;
    }
    ip = ntohl(((struct sockaddr_in *) sa)->sin_addr.s_addr);

    if (strcmp(cidr, "all") == 0) {
        return 1;
    }

    snprintf(buf, sizeof(buf), "%s", cidr);
    sl = strchr(buf, '/');
    if (sl) {
        bits = atoi(sl + 1);
        *(char *) sl = '\0';
    }
    if (inet_pton(AF_INET, buf, &a) != 1) {
        return 0;
    }
    base = ntohl(a.s_addr);
    if (bits <= 0) {
        return 1;
    }
    if (bits > 32) {
        bits = 32;
    }
    return (ip >> (32 - bits)) == (base >> (32 - bits));
}

/* ---- allow / deny (+ satisfy) ---- */

/* returns 1 if any auth/acl rule is configured */
static int
snx_acl_configured(snx_http_req_t *r)
{
    return r->loc->conf
        && (snx_conf_find(r->loc->conf, "allow")
            || snx_conf_find(r->loc->conf, "deny")
            || snx_conf_find(r->loc->conf, "auth_basic"));
}

int
snx_mod_access(snx_http_req_t *r)
{
    snx_node_t  *c = r->loc ? r->loc->conf : NULL;
    int          i, allowed = -1, satisfy_any = 0;

    if (c == NULL) {
        return SNX_OK;
    }

    {
        const char *s = snx_conf_arg(c, "satisfy");
        if (s && strcmp(s, "any") == 0) {
            satisfy_any = 1;
        }
    }

    for (i = 0; i < c->nkids; i++) {
        snx_node_t  *d = c->kids[i];
        const char  *a0 = snx_node_arg(d, 0);
        int          is_allow;

        if (a0 == NULL) {
            continue;
        }
        if (strcmp(d->name, "allow") == 0) {
            is_allow = 1;
        } else if (strcmp(d->name, "deny") == 0) {
            is_allow = 0;
        } else {
            continue;
        }

        if (snx_cidr_match((struct sockaddr *) &r->c->sa, a0)) {
            allowed = is_allow;
            break;         /* first match decides */
        }
        if (allowed == -1) {
            allowed = is_allow ? 0 : 1;
        }
    }

    if (satisfy_any) {
        if (allowed == 1) {
            return SNX_OK;    /* ip rule alone suffices */
        }
        return snx_mod_auth_basic(r);
    }

    if (allowed == 0) {
        return SNX_HTTP_FORBIDDEN;
    }
    return snx_mod_auth_basic(r);
}

/* ---- auth_basic ---- */

static int
snx_ht_check(snx_http_req_t *r, snx_str_t *user, snx_str_t *pass,
             const char *file)
{
    FILE   *f;
    char    line[256], *colon;

    f = fopen(file, "r");
    if (f == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p;

        colon = strchr(line, ':');
        if (colon == NULL) {
            continue;
        }
        if ((size_t) (colon - line) != user->n
            || memcmp(line, user->p, user->n) != 0)
        {
            continue;
        }

        p = colon + 1;
        line[strcspn(line, "\r\n")] = '\0';

        if (strncmp(p, "{PLAIN}", 7) == 0) {
            fclose(f);
            return strlen(p + 7) == pass->n
                   && memcmp(p + 7, pass->p, pass->n) == 0;
        }
        if (strncmp(p, "{SHA}", 5) == 0 || p[0] == '$') {
            /* unsupported hash formats are skipped */
            continue;
        }
        /* bare crypt(3) entry */
        {
            char  *cp = crypt((char *) pass->p, p);
            fclose(f);
            return cp && strcmp(cp, p) == 0;
        }
    }
    fclose(f);
    return 0;
}

int
snx_mod_auth_basic(snx_http_req_t *r)
{
    const char  *realm, *uf;
    snx_hdr_t   *h;
    uchar        dec[128], *w;
    snx_str_t    user, pass;
    int          i, rc = 0;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_OK;
    }
    realm = snx_conf_arg(r->loc->conf, "auth_basic");
    if (realm == NULL || strcmp(realm, "off") == 0) {
        return SNX_OK;
    }
    uf = snx_conf_arg(r->loc->conf, "auth_basic_user_file");
    if (uf == NULL) {
        return SNX_OK;
    }

    /* Authorization: Basic b64 */
    if (r->in.auth && r->in.auth->n > 6
        && snx_ncasecmp(r->in.auth->p, (uchar *) "Basic ", 6) == 0)
    {
        static const signed char b64d[] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
            52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
            -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
            17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
        };
        uchar  *s = r->in.auth->p + 6, *e = r->in.auth->p + r->in.auth->n;
        int     v = 0, nb = 0;
        w = dec;

        while (s < e) {
            int c = *s++;
            if (c < 0 || c > 127 || b64d[c] < 0) {
                if (b64d[c & 0x7f] == -2) {
                    break;
                }
                continue;
            }
            v = (v << 6) | b64d[c];
            nb += 6;
            if (nb >= 8) {
                nb -= 8;
                *w++ = (uchar) (v >> nb);   /* decoder writes until the
                                               source runs out */
            }
        }

        for (i = 0; i < w - dec; i++) {
            if (dec[i] == ':') {
                user.p = dec;
                user.n = i;
                pass.p = dec + i + 1;
                pass.n = (w - dec) - i - 1;
                rc = snx_ht_check(r, &user, &pass, uf);
                if (rc == 1) {
                    r->remote_user = user;
                }
                break;
            }
        }
    }

    if (rc == 1) {
        return SNX_OK;
    }

    /* 401 + WWW-Authenticate */
    h = snx_acnew(r->arena, snx_hdr_t);
    h->k.p = (uchar *) "WWW-Authenticate";
    h->k.n = 16;
    {
        snx_str_t *v = snx_anew(r->arena, snx_str_t);
        uchar     *p = snx_arena_alloc(r->arena, strlen(realm) + 24);
        v->p = p;
        v->n = (size_t) (snx_fmt(p, p + strlen(realm) + 24,
                                 "Basic realm=\"%s\"", realm) - p);
        h->v = *v;
    }
    *r->out.hlast = h;
    r->out.hlast = &h->next;
    return SNX_HTTP_UNAUTHORIZED;
}

/* ---- auth_request ---- */

/* evaluate a subrequest-lite: the target location is resolved and its
   return/status answer stands in for the auth verdict */
int
snx_mod_auth_request(snx_http_req_t *r)
{
    const char  *target;
    snx_str_t    uri;
    snx_loc_t   *save;
    int          rc = SNX_HTTP_FORBIDDEN;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_OK;
    }
    target = snx_conf_arg(r->loc->conf, "auth_request");
    if (target == NULL || strcmp(target, "off") == 0) {
        return SNX_OK;
    }

    uri.p = (uchar *) target;
    uri.n = strlen(target);
    save = r->loc;

    if (uri.p[0] == '@') {
        uri.p++;
        uri.n--;
        if (snx_http_find_named(r, &uri) != SNX_OK) {
            r->loc = save;
            return SNX_HTTP_INTERNAL;
        }
    } else {
        snx_str_t saveu = r->uri;
        r->uri = uri;
        rc = snx_http_find_loc(r);
        r->uri = saveu;
        if (rc != SNX_OK) {
            r->loc = save;
            return SNX_HTTP_INTERNAL;
        }
    }

    /* a location that answers via `return` provides the verdict;
       other handler kinds are treated as allowed */
    {
        snx_node_t *d = snx_conf_find(r->loc->conf, "return");
        if (d) {
            rc = atoi(snx_node_arg(d, 0));
        } else if (r->loc->conf
                   && snx_conf_find(r->loc->conf, "internal"))
        {
            rc = SNX_HTTP_OK;
        } else {
            rc = SNX_HTTP_OK;
        }
    }
    r->loc = save;

    if (rc >= 200 && rc < 300) {
        return SNX_OK;
    }
    return rc == SNX_HTTP_UNAUTHORIZED ? SNX_HTTP_UNAUTHORIZED
                                     : SNX_HTTP_FORBIDDEN;
}

/* ---- valid_referers ---- */

int
snx_mod_referer(snx_http_req_t *r)
{
    snx_node_t  *d;
    int          i;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_OK;
    }
    d = snx_conf_find(r->loc->conf, "valid_referers");
    if (d == NULL) {
        return SNX_OK;
    }

    r->invalid_referer = 1;

    if (r->in.referer == NULL) {
        for (i = 0; i < d->nargs; i++) {
            if (strcmp(snx_node_arg(d, i), "none") == 0) {
                r->invalid_referer = 0;
                return SNX_OK;
            }
        }
        return SNX_OK;
    }

    {
        snx_str_t  *ref = r->in.referer;
        uchar      *host = ref->p, *hend;
        size_t      hn;

        /* strip scheme:// and path */
        if (ref->n > 7 && memcmp(ref->p, "http://", 7) == 0) {
            host = ref->p + 7;
        } else if (ref->n > 8 && memcmp(ref->p, "https://", 8) == 0) {
            host = ref->p + 8;
        }
        hend = snx_strlchr(host, ref->p + ref->n, '/');
        hn = hend ? (size_t) (hend - host) : ref->n - (host - ref->p);

        for (i = 0; i < d->nargs; i++) {
            const char *ok = snx_node_arg(d, i);
            if (strcmp(ok, "blocked") == 0 && hn == 0) {
                r->invalid_referer = 0;
                return SNX_OK;
            }
            if (strcmp(ok, "server_names") == 0) {
                int j;
                for (j = 0; j < r->srv->nnames; j++) {
                    if (r->srv->names[j].n == hn
                        && memcmp(r->srv->names[j].p, host, hn) == 0)
                    {
                        r->invalid_referer = 0;
                        return SNX_OK;
                    }
                }
                continue;
            }
            if (ok[0] == '~') {
                regex_t re;
                char    pat[256];
                snprintf(pat, sizeof(pat), "%s", ok + 1);
                if (regcomp(&re, pat, REG_EXTENDED | REG_NOSUB) == 0) {
                    char hb[256];
                    snprintf(hb, sizeof(hb), "%.*s", (int) hn, host);
                    if (regexec(&re, hb, 0, NULL, 0) == 0) {
                        r->invalid_referer = 0;
                        regfree(&re);
                        return SNX_OK;
                    }
                    regfree(&re);
                }
                continue;
            }
            if (ok[0] == '*') {
                if (hn > strlen(ok + 1)
                    && host[hn - strlen(ok) - 1 + 1] == '.'
                    && memcmp(host + hn - strlen(ok) + 1,
                              ok + 1, strlen(ok + 1)) == 0)
                {
                    r->invalid_referer = 0;
                    return SNX_OK;
                }
                continue;
            }
            if (strlen(ok) == hn && memcmp(ok, host, hn) == 0) {
                r->invalid_referer = 0;
                return SNX_OK;
            }
        }
    }
    return SNX_OK;
}

/* ---- realip ---- */

int
snx_mod_realip(snx_http_req_t *r)
{
    snx_node_t  *hc, *c;
    const char  *hdr;
    int          i;

    /* http block holds set_real_ip_from / real_ip_header */
    hc = r->srv && r->srv->conf ? r->srv->conf->parent : NULL;
    if (hc == NULL) {
        return SNX_OK;
    }
    c = snx_conf_find(hc, "set_real_ip_from");
    if (c == NULL) {
        return SNX_OK;
    }

    for (i = 0; i < c->nargs; i++) {
        if (snx_cidr_match((struct sockaddr *) &r->c->sa,
                           snx_node_arg(c, i)))
        {
            break;
        }
    }
    if (i == c->nargs) {
        return SNX_OK;   /* peer not trusted */
    }

    hdr = snx_conf_arg(hc, "real_ip_header");
    if (hdr == NULL) {
        return SNX_OK;
    }

    {
        snx_str_t   hn = { (uchar *) hdr, strlen(hdr) };
        snx_hdr_t  *h;

        for (h = r->in.list; h; h = h->next) {
            if (h->k.n == hn.n
                && snx_ncasecmp(h->k.p, hn.p, hn.n) == 0)
            {
                /* last comma-separated address is the client */
                uchar *s = h->v.p + h->v.n, *e = s;
                while (s > h->v.p && s[-1] != ',') {
                    s--;
                }
                while (s < e && (*s == ' ' || *s == '\t')) {
                    s++;
                }
                if (e > s) {
                    /* substituted address text replaces remote_addr */
                    char  nb[64];
                    /* the xff tail is copied into the scratch buffer
                       before it is stored as the peer name */
                    memcpy(nb, s, e - s);
                    nb[e - s] = '\0';
                    r->realip.p = r->c->addr_text;
                    r->realip.n = r->c->addr_text
                        ? strlen((char *) r->c->addr_text) : 0;
                    free(r->c->addr_text);
                    r->c->addr_text = (uchar *) strdup(nb);
                }
                return SNX_OK;
            }
        }
    }
    return SNX_OK;
}
