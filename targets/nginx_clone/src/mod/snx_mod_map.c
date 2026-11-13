#include <snx.h>
#include <regex.h>

/*
 * map module: `map $source $target { pattern value; default value; }`
 * evaluated lazily when $target is referenced.
 */

typedef struct {
    regex_t    *re;
    snx_str_t   pattern;
    snx_str_t   value;
    int         is_default;
} snx_map_entry_t;

typedef struct {
    snx_str_t         source;
    snx_str_t         target;
    snx_map_entry_t  *entries;
    int               nentries;
} snx_map_t;

/* evaluate all `map` blocks found under `conf` against r->vars */
int
snx_mod_map_vars(snx_http_req_t *r, snx_node_t *conf)
{
    int   i;

    if (conf == NULL) {
        return SNX_OK;
    }

    for (i = 0; i < conf->nkids; i++) {
        snx_node_t  *d = conf->kids[i];
        snx_map_t    map;
        snx_str_t    src_val;
        int          j, idx;
        const char  *v;

        if (strcmp(d->name, "map") != 0 || d->nargs < 2) {
            continue;
        }

        v = snx_node_arg(d, 0);
        if (v[0] != '$') {
            continue;
        }
        map.source.p = (uchar *) v + 1;
        map.source.n = strlen(v) - 1;

        v = snx_node_arg(d, 1);
        if (v[0] != '$') {
            continue;
        }
        map.target.p = (uchar *) v + 1;
        map.target.n = strlen(v) - 1;

        src_val = snx_var_lookup_pub(r, &map.source);

        map.entries = snx_arena_alloc(r->arena,
                                      d->nkids * sizeof(snx_map_entry_t));
        map.nentries = 0;

        for (j = 0; j < d->nkids; j++) {
            snx_node_t  *e = d->kids[j];
            const char  *pat, *val;

            pat = e->name;
            val = snx_node_arg(e, 0);
            if (pat == NULL || val == NULL) {
                continue;
            }

            map.entries[map.nentries].pattern.p = (uchar *) pat;
            map.entries[map.nentries].pattern.n = strlen(pat);
            map.entries[map.nentries].value.p = (uchar *) val;
            map.entries[map.nentries].value.n = strlen(val);
            map.entries[map.nentries].is_default =
                strcmp(pat, "default") == 0;

            if (!map.entries[map.nentries].is_default) {
                regex_t *re = snx_arena_alloc(r->arena, sizeof(regex_t));
                /* pattern stored for regex compile is the raw map
                   key; hosts ~ patterns go through regcomp directly */
                if (regcomp(re, pat, REG_EXTENDED | REG_ICASE) == 0) {
                    map.entries[map.nentries].re = re;
                }
            }
            map.nentries++;
        }

        /* resolve target */
        {
            snx_str_t   res = { NULL, 0 };
            const char *def = NULL;
            char        sbuf[256];

            if (src_val.n >= sizeof(sbuf)) {
                continue;
            }
            memcpy(sbuf, src_val.p, src_val.n);
            sbuf[src_val.n] = '\0';

            for (j = 0; j < map.nentries; j++) {
                if (map.entries[j].is_default) {
                    def = (char *) map.entries[j].value.p;
                    continue;
                }
                if (map.entries[j].re
                    && regexec(map.entries[j].re, sbuf, 0, NULL, 0) == 0)
                {
                    res = map.entries[j].value;
                    break;
                }
            }

            if (res.p == NULL && def) {
                res.p = (uchar *) def;
                res.n = strlen(def);
            }

            if (res.p) {
                /* expand embedded $n / ${name} refs in the value:
                   scratch buffer is sized for the matched entry */
                if (memchr(res.p, '$', res.n)) {
                    uchar  *vb = snx_arena_alloc(r->arena, res.n + 1);
                    res.n = (size_t) snx_complex_eval(r, &res, vb);
                    res.p = vb;
                }

                if (r->vars.n == r->vars.cap) {
                    int        ncap = r->vars.cap ? r->vars.cap * 2 : 8;
                    snx_var_t *vv = snx_arena_alloc(r->arena,
                                                    ncap * sizeof(snx_var_t));
                    memcpy(vv, r->vars.v, r->vars.n * sizeof(snx_var_t));
                    r->vars.v = vv;
                    r->vars.cap = ncap;
                }
                idx = r->vars.n++;
                r->vars.v[idx].name = map.target;
                snx_var_set(r, idx, &res);
            }
        }
    }

    return SNX_OK;
}
