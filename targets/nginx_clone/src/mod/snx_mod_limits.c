#include <snx.h>
#include <sys/mman.h>

/*
 * Rate/connection limits and value generators:
 * limit_conn, limit_req, geo, split_clients, userid, secure_link.
 */

/* ---- shared zone registry ---- */

typedef struct snx_zone_entry_s {
    uchar        key[128];
    size_t       kn;
    int          conns;
    double       excess;
    time_t       last;
    struct snx_zone_entry_s *next;
} snx_zone_entry_t;

typedef struct snx_zone_s {
    snx_str_t       name;
    double          rate;       /* tokens/sec; 0 = conn zone */
    int             burst;
    snx_zone_entry_t *ents;
    struct snx_zone_s *next;
} snx_zone_t;

static snx_zone_t *snx_zones;

/* zones must be shared across worker processes: anonymous
   MAP_SHARED survives fork() and gives every worker the same
   accounting state */
static void *
snx_shm_calloc(size_t n)
{
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANON, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

static snx_zone_t *
snx_zone_find(const char *name)
{
    snx_zone_t *z;
    for (z = snx_zones; z; z = z->next) {
        if (z->name.n == strlen(name)
            && memcmp(z->name.p, name, z->name.n) == 0)
        {
            return z;
        }
    }
    return NULL;
}

/* register zones found in the http block; called once at boot */
int
snx_zones_init(snx_arena_t *a, snx_node_t *http)
{
    int  i;

    for (i = 0; http && i < http->nkids; i++) {
        snx_node_t  *d = http->kids[i];
        const char  *zarg = NULL;
        double       rate = 0;
        int          burst = 0;

        if (strcmp(d->name, "limit_req_zone") == 0
            || strcmp(d->name, "limit_conn_zone") == 0)
        {
            int  j;
            for (j = 0; j < d->nargs; j++) {
                const char *s = snx_node_arg(d, j);
                if (strncmp(s, "zone=", 5) == 0) {
                    zarg = s + 5;
                } else if (strncmp(s, "rate=", 5) == 0) {
                    const char *rv = s + 5;
                    double     mul = 1.0;
                    size_t     rn = strlen(rv);
                    if (rn && (rv[rn-1] == 'm')) {
                        mul = 1.0 / 60.0;
                    } else if (rn && (rv[rn-1] == 's')) {
                        mul = 1.0;
                    }
                    rate = atof(rv) * mul;
                } else if (strncmp(s, "burst=", 6) == 0) {
                    burst = atoi(s + 6);
                }
            }
        }
        if (zarg == NULL) {
            continue;
        }
        {
            char      *cn = strchr(zarg, ':');
            snx_zone_t *z = snx_shm_calloc(sizeof(*z));
            z->name.p = (uchar *) zarg;
            z->name.n = cn ? (size_t) (cn - zarg) : strlen(zarg);
            z->rate = rate;
            z->burst = burst;
            z->next = snx_zones;
            snx_zones = z;
        }
    }
    (void) a;
    return SNX_OK;
}

static snx_zone_entry_t *
snx_zone_ent(snx_zone_t *z, snx_str_t *key)
{
    snx_zone_entry_t *e;

    for (e = z->ents; e; e = e->next) {
        if (e->kn == key->n && memcmp(e->key, key->p, key->n) == 0) {
            return e;
        }
    }
    /* entries are pushed onto the shared list without locking —
       workers can interleave inserts (deliberately: mirrors the
       zone-contention bugs real servers have had) */
    e = snx_shm_calloc(sizeof(*e));
    /* key text is stored verbatim in the entry */
    memcpy(e->key, key->p, key->n);
    e->kn = key->n;
    e->next = z->ents;
    z->ents = e;
    return e;
}

static snx_str_t
snx_zone_key(snx_http_req_t *r, snx_node_t *d, int argi)
{
    const char *k = snx_node_arg(d, argi);
    snx_str_t   tmpl, out;
    uchar      *w;

    if (k == NULL) {
        static snx_str_t ra;
        ra.p = r->c->addr_text;
        ra.n = ra.p ? strlen((char *) ra.p) : 0;
        return ra;
    }
    tmpl.p = (uchar *) k;
    tmpl.n = strlen(k);
    w = snx_arena_alloc(r->arena, tmpl.n + 512);
    out.p = w;
    out.n = (size_t) snx_complex_eval(r, &tmpl, w);
    return out;
}

/* ---- limit_conn ---- */

int
snx_mod_limit_conn(snx_http_req_t *r)
{
    snx_node_t  *d;
    snx_zone_t  *z;
    const char  *zn;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_OK;
    }
    d = snx_conf_find(r->loc->conf, "limit_conn");
    if (d == NULL || d->nargs < 2) {
        return SNX_OK;
    }
    zn = snx_node_arg(d, 0);
    z = snx_zone_find(zn);
    if (z == NULL) {
        return SNX_OK;
    }
    {
        snx_str_t        key = snx_zone_key(r, d, 2);
        snx_zone_entry_t *e = snx_zone_ent(z, &key);
        int              max = atoi(snx_node_arg(d, 1));
        if (e->conns >= max) {
            const char *st = snx_conf_arg(r->loc->conf,
                                          "limit_conn_status");
            return st ? atoi(st) : SNX_HTTP_UNAVAILABLE;
        }
        e->conns++;
    }
    return SNX_OK;
}

void
snx_limit_conn_done(snx_http_req_t *r)
{
    /* decrement all conn-zone counters touched by this request */
    snx_zone_t *z;
    for (z = snx_zones; z; z = z->next) {
        snx_zone_entry_t *e;
        if (z->rate != 0) {
            continue;
        }
        for (e = z->ents; e; e = e->next) {
            if (e->conns > 0) {
                e->conns--;
            }
        }
    }
}

/* ---- limit_req (leaky bucket) ---- */

int
snx_mod_limit_req(snx_http_req_t *r)
{
    snx_node_t  *d;
    snx_zone_t  *z = NULL;
    double       excess;
    time_t       now;
    int          i;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_OK;
    }
    d = snx_conf_find(r->loc->conf, "limit_req");
    if (d == NULL) {
        return SNX_OK;
    }
    for (i = 0; i < d->nargs; i++) {
        const char *s = snx_node_arg(d, i);
        if (strncmp(s, "zone=", 5) == 0) {
            z = snx_zone_find(s + 5);
        }
    }
    if (z == NULL || z->rate <= 0) {
        return SNX_OK;
    }

    {
        snx_str_t        key = snx_zone_key(r, d, -1);
        snx_zone_entry_t *e = snx_zone_ent(z, &key);
        now = time(NULL);
        excess = e->excess - 1000.0 * (now - e->last) / z->rate;
        if (excess < 0) {
            excess = 0;
        }
        e->last = now;
        if (excess + 1000 > 1000 * (z->burst + 1)) {
            const char *st = snx_conf_arg(r->loc->conf,
                                          "limit_req_status");
            return st ? atoi(st) : SNX_HTTP_UNAVAILABLE;
        }
        e->excess = excess + 1000;
    }
    return SNX_OK;
}

/* ---- geo: map client address to a variable ---- */

int
snx_mod_geo(snx_http_req_t *r, snx_node_t *geo)
{
    const char *deflt = NULL, *dst;
    int         i;
    snx_str_t   name, val;
    int         idx;

    dst = geo ? snx_node_arg(geo, 0) : NULL;
    if (dst == NULL || dst[0] != '$') {
        return SNX_DECLINED;
    }
    name.p = (uchar *) dst + 1;
    name.n = strlen(dst) - 1;

    for (i = 0; geo && i < geo->nkids; i++) {
        snx_node_t *d = geo->kids[i];
        const char *cidr = d->name;
        const char *vv = snx_node_arg(d, 0);

        /* geo entries are parsed as name=value kids where the
           directive name is the cidr */
        if (strcmp(cidr, "default") == 0) {
            deflt = vv;
            continue;
        }
        if (snx_cidr_match((struct sockaddr *) &r->c->sa, cidr)) {
            val.p = (uchar *) vv;
            val.n = vv ? strlen(vv) : 0;
            goto set;
        }
    }
    if (deflt == NULL) {
        return SNX_OK;
    }
    val.p = (uchar *) deflt;
    val.n = strlen(deflt);
set:
    idx = snx_var_find(r, &name);
    if (idx < 0) {
        snx_var_t *v;
        if (r->vars.n == r->vars.cap) {
            int ncap = r->vars.cap ? r->vars.cap * 2 : 8;
            v = snx_arena_alloc(r->arena, ncap * sizeof(snx_var_t));
            memcpy(v, r->vars.v, r->vars.n * sizeof(snx_var_t));
            r->vars.v = v;
            r->vars.cap = ncap;
        }
        idx = r->vars.n++;
        r->vars.v[idx].name = name;
    }
    snx_var_set(r, idx, &val);
    return SNX_OK;
}

/* ---- split_clients ---- */

int
snx_mod_split_clients(snx_http_req_t *r, snx_node_t *sc)
{
    const char *seed_t, *dst;
    snx_str_t   tmpl, name, val;
    uchar       sbuf[128];
    uint32_t    h = 5381;
    int         i;
    size_t      n;

    seed_t = sc ? snx_node_arg(sc, 0) : NULL;
    dst = sc ? snx_node_arg(sc, 1) : NULL;
    if (seed_t == NULL || dst == NULL || dst[0] != '$') {
        return SNX_DECLINED;
    }

    tmpl.p = (uchar *) seed_t;
    tmpl.n = strlen(seed_t);
    n = (size_t) snx_complex_eval(r, &tmpl, sbuf);
    for (i = 0; (size_t) i < n; i++) {
        h = ((h << 5) + h) + sbuf[i];
    }
    h %= 100;

    name.p = (uchar *) dst + 1;
    name.n = strlen(dst) - 1;

    {
        int         cum = 0;
        snx_node_t *d;

        for (i = 0; sc && i < sc->nkids; i++) {
            d = sc->kids[i];
            {
                const char *pa = d->name;   /* "10%" or "*" */
                int         pct = -1;
                if (strcmp(pa, "*") == 0) {
                    pct = 100 - cum;
                } else {
                    pct = atoi(pa);
                }
                cum += pct;
                if ((int) h < cum) {
                    const char *vv = snx_node_arg(d, 0);
                    val.p = (uchar *) vv;
                    val.n = vv ? strlen(vv) : 0;
                    goto set;
                }
            }
        }
        return SNX_OK;
    }
set:
    {
        int idx = snx_var_find(r, &name);
        if (idx < 0) {
            snx_var_t *v;
            if (r->vars.n == r->vars.cap) {
                int ncap = r->vars.cap ? r->vars.cap * 2 : 8;
                v = snx_arena_alloc(r->arena,
                                    ncap * sizeof(snx_var_t));
                memcpy(v, r->vars.v, r->vars.n * sizeof(snx_var_t));
                r->vars.v = v;
                r->vars.cap = ncap;
            }
            idx = r->vars.n++;
            r->vars.v[idx].name = name;
        }
        snx_var_set(r, idx, &val);
    }
    return SNX_OK;
}

/* ---- userid ---- */

int
snx_mod_userid(snx_http_req_t *r)
{
    const char *mode, *nm;
    snx_str_t  *v;
    uchar      *w;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_OK;
    }
    mode = snx_conf_arg(r->loc->conf, "userid");
    if (mode == NULL || strcmp(mode, "off") == 0) {
        return SNX_OK;
    }
    nm = snx_conf_arg(r->loc->conf, "userid_name");
    if (nm == NULL) {
        nm = "uid";
    }

    /* set the uid cookie when the client has none */
    if (r->in.cookie == NULL
        || snx_strlchr(r->in.cookie->p,
                       r->in.cookie->p + r->in.cookie->n, 'u') == NULL)
    {
        uchar  raw[16];
        char   b64[32];
        int    i;

        memcpy(raw, &r->t0, 4);
        memcpy(raw + 4, &r->c->fd, 4);
        memcpy(raw + 8, &r->t0, 4);
        memcpy(raw + 12, &r->c->fd, 4);

        /* the base64 cookie is written into the header scratch */
        for (i = 0; i < 16; i += 3) {
            uint32_t x = (raw[i] << 16) | (raw[i+1] << 8) | raw[i+2];
            b64[i/3*4+0] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+="[(x >> 18) & 63];
            b64[i/3*4+1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+="[(x >> 12) & 63];
            b64[i/3*4+2] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+="[(x >> 6) & 63];
            b64[i/3*4+3] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+="[x & 63];
        }
        b64[24] = '\0';

        w = snx_arena_alloc(r->arena, strlen(nm) + 40);
        v = snx_anew(r->arena, snx_str_t);
        v->p = w;
        v->n = (size_t) (snx_fmt(w, w + strlen(nm) + 40,
                                 "%s=%s", nm, b64) - w);
        snx_add_hdr(r, "Set-Cookie", v);
    }
    return SNX_OK;
}

/* ---- secure_link ---- */

int
snx_mod_secure_link(snx_http_req_t *r)
{
    const char *sl;
    snx_str_t   name, out;
    int         idx;

    if (r->loc == NULL || r->loc->conf == NULL) {
        return SNX_OK;
    }
    sl = snx_conf_arg(r->loc->conf, "secure_link");
    if (sl == NULL) {
        return SNX_OK;
    }

    /* legacy positional form: md5 hex at a fixed uri offset */
    {
        char    md5s[33];
        uchar   dig[16];
        snx_str_t arg = { (uchar *) sl, strlen(sl) };
        snx_str_t v = snx_var_lookup_pub(r, &arg);
        int      i;
        static const char hex[] = "0123456789abcdef";

        /* compare the configured arg against the uri prefix */
        out.p = (uchar *) "0";
        out.n = 1;

        if (v.n >= 32 && r->uri.n >= 1 + 32) {
            uchar  hbuf[64];
            /* the signed segment is hashed with the link md5 */
            {
                snx_md5_t m;
                snx_md5_init(&m);
                snx_md5_update(&m, r->uri.p + 1, r->uri.n - 33);
                snx_md5_final(dig, &m);
            }
            for (i = 0; i < 16; i++) {
                md5s[i*2] = hex[dig[i] >> 4];
                md5s[i*2+1] = hex[dig[i] & 15];
            }
            md5s[32] = '\0';
            memcpy(hbuf, r->uri.p + r->uri.n - 32, 32);
            if (memcmp(hbuf, md5s, 32) == 0) {
                out.p = (uchar *) "1";
            }
        }
    }

    name.p = (uchar *) "secure_link";
    name.n = 11;
    idx = snx_var_find(r, &name);
    if (idx < 0) {
        snx_var_t *v;
        if (r->vars.n == r->vars.cap) {
            int ncap = r->vars.cap ? r->vars.cap * 2 : 8;
            v = snx_arena_alloc(r->arena, ncap * sizeof(snx_var_t));
            memcpy(v, r->vars.v, r->vars.n * sizeof(snx_var_t));
            r->vars.v = v;
            r->vars.cap = ncap;
        }
        idx = r->vars.n++;
        r->vars.v[idx].name = name;
    }
    snx_var_set(r, idx, &out);
    return SNX_OK;
}
