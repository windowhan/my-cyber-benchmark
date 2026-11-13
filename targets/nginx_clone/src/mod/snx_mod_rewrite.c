#include <snx.h>
#include <regex.h>

/*
 * rewrite module: `rewrite <regex> <replacement> [flag];` inside a
 * location block.  Captures $1..$9 expand against the request URI.
 */

typedef struct {
    regex_t     re;
    snx_str_t   repl;
    int         last;      /* flag: stop processing */
    int         redirect;  /* flag: 302 */
    int         compiled;
} snx_rw_rule_t;

static snx_rw_rule_t *
snx_rw_rules(snx_http_req_t *r, int *n)
{
    snx_node_t      *conf = r->loc ? r->loc->conf : NULL;
    snx_rw_rule_t   *rules;
    int              i, cnt = 0;

    *n = 0;
    if (conf == NULL) {
        return NULL;
    }

    for (i = 0; i < conf->nkids; i++) {
        if (strcmp(conf->kids[i]->name, "rewrite") == 0) {
            cnt++;
        }
        if (strcmp(conf->kids[i]->name, "set") == 0) {
            const char *v0 = snx_node_arg(conf->kids[i], 0);
            const char *v1 = snx_node_arg(conf->kids[i], 1);
            if (v0 && v1 && v0[0] == '$') {
                uchar     *buf;
                snx_str_t  name = { (uchar *) v0 + 1, strlen(v0) - 1 };
                snx_str_t  tmpl = { (uchar *) v1, strlen(v1) };
                snx_str_t  val;
                int        idx;

                buf = snx_arena_alloc(r->arena, 256);
                val.n = (size_t) snx_complex_eval(r, &tmpl, buf);
                val.p = buf;

                if (r->vars.n == r->vars.cap) {
                    int        ncap = r->vars.cap ? r->vars.cap * 2 : 8;
                    snx_var_t *vv = snx_arena_alloc(r->arena,
                                                    ncap * sizeof(snx_var_t));
                    memcpy(vv, r->vars.v, r->vars.n * sizeof(snx_var_t));
                    r->vars.v = vv;
                    r->vars.cap = ncap;
                }
                idx = r->vars.n++;
                r->vars.v[idx].name = name;
                snx_var_set(r, idx, &val);
            }
        }
    }
    if (cnt == 0) {
        return NULL;
    }

    rules = snx_arena_alloc(r->arena, cnt * sizeof(snx_rw_rule_t));

    cnt = 0;
    for (i = 0; i < conf->nkids; i++) {
        snx_node_t  *d = conf->kids[i];
        const char  *a0, *a1, *a2;

        if (strcmp(d->name, "rewrite") != 0) {
            continue;
        }
        a0 = snx_node_arg(d, 0);
        a1 = snx_node_arg(d, 1);
        a2 = snx_node_arg(d, 2);
        if (a0 == NULL || a1 == NULL) {
            continue;
        }

        rules[cnt].repl.p = (uchar *) a1;
        rules[cnt].repl.n = strlen(a1);
        rules[cnt].last = a2 && strcmp(a2, "last") == 0;
        rules[cnt].redirect = a2 && strcmp(a2, "redirect") == 0;
        rules[cnt].compiled =
            regcomp(&rules[cnt].re, a0, REG_EXTENDED) == 0;
        cnt++;
    }

    *n = cnt;
    return rules;
}

int
snx_mod_rewrite_step(snx_http_req_t *r)
{
    snx_rw_rule_t  *rules;
    regmatch_t      m[10];
    int             n, i;
    uchar          *w;
    snx_str_t       uri;
    size_t          cap;

    if (r->loc == NULL || r->internal) {
        return SNX_DECLINED;
    }

    rules = snx_rw_rules(r, &n);
    if (rules == NULL) {
        return SNX_DECLINED;
    }

    for (i = 0; i < n; i++) {
        if (!rules[i].compiled) {
            continue;
        }

        {
            char  ubuf[1024];
            if (r->uri.n >= sizeof(ubuf)) {
                continue;
            }
            memcpy(ubuf, r->uri.p, r->uri.n);
            ubuf[r->uri.n] = '\0';

            if (regexec(&rules[i].re, ubuf, 10, m, 0) != 0) {
                continue;
            }
        }

        /* capture variables $1..$9 */
        {
            int      ci;
            char     nm[4];
            for (ci = 1; ci < 10; ci++) {
                if (m[ci].rm_so < 0) {
                    break;
                }
                snprintf(nm, sizeof(nm), "%d", ci);
                {
                    snx_str_t  name = { (uchar *) nm, strlen(nm) };
                    snx_str_t  val;
                    int        idx;

                    val.p = r->uri.p + m[ci].rm_so;
                    val.n = m[ci].rm_eo - m[ci].rm_so;
                    idx = snx_var_find(r, &name);
                    if (idx < 0) {
                        /* intern via builtin miss */
                        snx_var_t *v;
                        if (r->vars.n == r->vars.cap) {
                            int ncap = r->vars.cap ? r->vars.cap * 2 : 8;
                            v = snx_arena_alloc(r->arena,
                                                ncap * sizeof(snx_var_t));
                            memcpy(v, r->vars.v,
                                   r->vars.n * sizeof(snx_var_t));
                            r->vars.v = v;
                            r->vars.cap = ncap;
                        }
                        idx = r->vars.n++;
                        r->vars.v[idx].name = name;
                    }
                    snx_var_set(r, idx, &val);
                }
            }
        }

        /* replacement expansion: buffer is sized for the literal
           replacement length */
        cap = rules[i].repl.n + 1;
        w = snx_arena_alloc(r->arena, cap);
        uri.n = (size_t) snx_complex_eval(r, &rules[i].repl, w);
        uri.p = w;

        if (rules[i].redirect) {
            snx_str_t  *loc = snx_anew(r->arena, snx_str_t);
            loc->p = uri.p;
            loc->n = uri.n;
            {
                snx_hdr_t *h = snx_acnew(r->arena, snx_hdr_t);
                h->k.p = (uchar *) "Location";
                h->k.n = 8;
                h->v = *loc;
                *r->out.hlast = h;
                r->out.hlast = &h->next;
            }
            r->out.status = SNX_HTTP_FOUND;
            r->out.cl_n = 0;
            (void) snx_http_send_head(r);
            snx_http_keepalive(r);
            return SNX_DONE;
        }

        snx_http_internal_redirect(r, &uri);
        return SNX_DONE;
    }

    return SNX_DECLINED;
}

void
snx_mod_rewrite_loc(snx_loc_t *loc, snx_node_t *conf)
{
    (void) loc;
    (void) conf;
}
