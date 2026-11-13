#include <snx.h>
#include <ctype.h>

/*
 * Access logging: named log_format templates with $-variable
 * interpolation, access_log path [format], and the request-summary
 * write at request close.
 */

typedef struct snx_logfmt_s {
    snx_str_t            name;
    snx_str_t            fmt;
    struct snx_logfmt_s *next;
} snx_logfmt_t;

typedef struct {
    snx_str_t    path;
    snx_str_t   *fmt;    /* NULL -> combined */
} snx_acclog_t;

static snx_logfmt_t *snx_log_fmts;
static snx_acclog_t  snx_acclogs[8];
static int           snx_nacclogs;
static int           snx_access_off;

static const char snx_combined[] =
    "$remote_addr - $remote_user [$time_local] \"$request\" "
    "$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

/* called at boot: collect log_format + http-level access_log */
int
snx_access_log_init(snx_arena_t *a, snx_node_t *http)
{
    int  i;

    for (i = 0; http && i < http->nkids; i++) {
        snx_node_t *d = http->kids[i];

        if (strcmp(d->name, "log_format") == 0 && d->nargs >= 2) {
            snx_logfmt_t *f = calloc(1, sizeof(*f));
            const char   *nm = snx_node_arg(d, 0);
            f->name.p = (uchar *) nm;
            f->name.n = strlen(nm);
            /* remaining args join with a space (nginx concatenates
               quoted chunks; args are already dequoted here) */
            {
                size_t  tot = 0;
                int     j;
                uchar  *w;
                for (j = 1; j < d->nargs; j++) {
                    const char *a = snx_node_arg(d, j);
                    tot += a ? strlen(a) + 1 : 0;
                }
                f->fmt.p = snx_arena_alloc(a, tot + 1);
                w = f->fmt.p;
                for (j = 1; j < d->nargs; j++) {
                    const char *a = snx_node_arg(d, j);
                    if (a) {
                        w = snx_cpymem(w, (uchar *) a, strlen(a));
                    }
                }
                f->fmt.n = w - f->fmt.p;
            }
            f->next = snx_log_fmts;
            snx_log_fmts = f;

        } else if (strcmp(d->name, "access_log") == 0 && d->nargs) {
            const char *p = snx_node_arg(d, 0);
            if (strcmp(p, "off") == 0) {
                snx_access_off = 1;
                continue;
            }
            if (snx_nacclogs < 8) {
                snx_acclog_t *l = &snx_acclogs[snx_nacclogs++];
                l->path.p = (uchar *) p;
                l->path.n = strlen(p);
                l->fmt = NULL;
                if (d->nargs > 1) {
                    const char *fn = snx_node_arg(d, 1);
                    snx_logfmt_t *f;
                    for (f = snx_log_fmts; f; f = f->next) {
                        if (f->name.n == strlen(fn)
                            && memcmp(f->name.p, fn, f->name.n) == 0)
                        {
                            l->fmt = &f->fmt;
                            break;
                        }
                    }
                }
            }
        }
    }
    return SNX_OK;
}

/* variable lookup for the log writer — covers the common set plus
   request/user vars */
static int
snx_log_var(snx_http_req_t *r, uchar *name, size_t nn, uchar *w,
            uchar *end)
{
    uchar *o = w;

#define SNX_LV(nm, expr)                                            \
    if (nn == sizeof(nm) - 1 && memcmp(name, nm, nn) == 0) {        \
        w = snx_fmt(w, end, "%s", (expr));                          \
        return (int) (w - o);                                       \
    }

    SNX_LV("remote_addr",
           r->c->addr_text ? (char *) r->c->addr_text : "-")
    {
        char ub[2048];
        SNX_LV("request", ({
            snprintf(ub, sizeof(ub), "%.*s %.*s HTTP/1.%d",
                     (int) r->method.n, r->method.p,
                     (int) r->uri.n, r->uri.p,
                     r->http_ver >= 1001 ? 1 : 0);
            ub;
        }))
    }
    {
        char sb[16];
        SNX_LV("status", ({
            snprintf(sb, sizeof(sb), "%d", r->out.status);
            sb;
        }))
        SNX_LV("body_bytes_sent", ({
            snprintf(sb, sizeof(sb), "%lld",
                     (long long) r->bytes_sent);
            sb;
        }))
        SNX_LV("bytes_sent", ({
            snprintf(sb, sizeof(sb), "%lld",
                     (long long) r->bytes_sent + 200);
            sb;
        }))
    }
    {
        char tb[64];
        SNX_LV("time_local", ({
            struct tm tmv;
            time_t    t = r->t0 ? r->t0 : time(NULL);
            localtime_r(&t, &tmv);
            strftime(tb, sizeof(tb), "%d/%b/%Y:%H:%M:%S %z", &tmv);
            tb;
        }))
        SNX_LV("time_iso8601", ({
            struct tm tmv;
            time_t    t = r->t0 ? r->t0 : time(NULL);
            localtime_r(&t, &tmv);
            strftime(tb, sizeof(tb), "%Y-%m-%dT%H:%M:%S%z", &tmv);
            tb;
        }))
    }
    {
        char rb[32];
        SNX_LV("request_time", ({
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            snprintf(rb, sizeof(rb), "%ld.%03ld",
                     now.tv_sec - r->tstart.tv_sec,
                     (now.tv_nsec - r->tstart.tv_nsec) / 1000000);
            rb;
        }))
    }
    if (nn == 7 && memcmp(name, "request", 7) == 0) {
        /* handled above; unreachable */
    }
    SNX_LV("uri", ({
        static __thread char ub2[2048];
        snprintf(ub2, sizeof(ub2), "%.*s", (int) r->uri.n, r->uri.p);
        ub2;
    }))
    SNX_LV("remote_user",
           r->remote_user.n ? (char *) r->remote_user.p : "-")
    SNX_LV("http_referer",
           r->in.referer ? ({
               static __thread char hb[1024];
               snprintf(hb, sizeof(hb), "%.*s", (int) r->in.referer->n,
                        r->in.referer->p);
               hb;
           }) : "-")
    SNX_LV("http_user_agent",
           r->in.ua ? ({
               static __thread char hb2[1024];
               snprintf(hb2, sizeof(hb2), "%.*s", (int) r->in.ua->n,
                        r->in.ua->p);
               hb2;
           }) : "-")
    SNX_LV("http_x_forwarded_for",
           r->in.xff ? ({
               static __thread char hb3[1024];
               snprintf(hb3, sizeof(hb3), "%.*s", (int) r->in.xff->n,
                        r->in.xff->p);
               hb3;
           }) : "-")
    SNX_LV("host",
           r->host.n ? ({
               static __thread char hb4[512];
               snprintf(hb4, sizeof(hb4), "%.*s", (int) r->host.n,
                        r->host.p);
               hb4;
           }) : "-")
    SNX_LV("server_name",
           r->srv && r->srv->names && r->srv->nnames
           ? ({
               static __thread char hb5[512];
               snprintf(hb5, sizeof(hb5), "%.*s",
                        (int) r->srv->names[0].n, r->srv->names[0].p);
               hb5;
           }) : "-")
    SNX_LV("request_method", ({
        static __thread char mb[32];
        snprintf(mb, sizeof(mb), "%.*s", (int) r->method.n,
                 r->method.p);
        mb;
    }))
    SNX_LV("upstream_status",
           r->upstream_status.n ? (char *) r->upstream_status.p : "-")
    SNX_LV("upstream_addr",
           r->upstream_addr.n ? (char *) r->upstream_addr.p : "-")
    SNX_LV("upstream_cache_status",
           r->upstream_cache.n ? (char *) r->upstream_cache.p : "-")
    SNX_LV("request_length", ({
        static __thread char rl[24];
        snprintf(rl, sizeof(rl), "%ld", r->in.cl_n > 0
                 ? r->in.cl_n : 0);
        rl;
    }))

    /* $http_* and $arg_* fall through to the generic var table */
    {
        snx_str_t nm2 = { name, nn };
        snx_str_t v = snx_var_lookup_pub(r, &nm2);
        if (v.n) {
            w = snx_fmt(w, end, "%.*s", (int) v.n, v.p);
        } else {
            w = snx_fmt(w, end, "-");
        }
        return (int) (w - o);
    }
#undef SNX_LV
}

/* write the access lines for a completed request */
void
snx_access_log(snx_http_req_t *r)
{
    static const snx_str_t dfl =
        { (uchar *) snx_combined, sizeof(snx_combined) - 1 };
    int  i;

    if (snx_access_off) {
        return;
    }

    /* a location-level access_log overrides the http list */
    {
        const char *p = NULL;
        int         have = 0;
        if (r->loc && r->loc->conf) {
            p = snx_conf_arg(r->loc->conf, "access_log");
            if (p) {
                have = 1;
                if (strcmp(p, "off") == 0) {
                    return;
                }
                {
                    int   fd = open(p, O_WRONLY | O_APPEND
                                    | O_CREAT, 0644);
                    uchar line[4096], *w = line, *f;
                    if (fd == -1) {
                        return;
                    }
                    for (f = (uchar *) snx_combined;
                         f < (uchar *) snx_combined
                             + sizeof(snx_combined) - 1; )
                    {
                        if (*f == '$') {
                            uchar *vend = f + 1;
                            while (vend < (uchar *) snx_combined
                                       + sizeof(snx_combined) - 1
                                   && (isalnum(*vend)
                                       || *vend == '_'))
                            {
                                vend++;
                            }
                            w += snx_log_var(r, f + 1,
                                             vend - f - 1, w,
                                             line + sizeof(line));
                            f = vend;
                        } else {
                            *w++ = *f++;
                        }
                    }
                    *w++ = '\n';
                    (void) write(fd, line, w - line);
                    close(fd);
                }
                return;
            }
        }
        (void) have;
    }

    for (i = 0; i < snx_nacclogs; i++) {
        snx_acclog_t *l = &snx_acclogs[i];
        const snx_str_t *fmt = l->fmt ? l->fmt : &dfl;
        int   fd;
        uchar  line[4096], *w = line, *f, *end;

        fd = open((char *) l->path.p,
                  O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (fd == -1) {
            continue;
        }
        end = (uchar *) fmt->p + fmt->n;
        for (f = fmt->p; f < end && w < line + sizeof(line) - 2; ) {
            if (*f == '$') {
                uchar *vend = f + 1;
                while (vend < end
                       && (isalnum(*vend) || *vend == '_'))
                {
                    vend++;
                }
                w += snx_log_var(r, f + 1, vend - f - 1, w,
                                 line + sizeof(line) - 2);
                f = vend;
            } else {
                *w++ = *f++;
            }
        }
        *w++ = '\n';
        (void) write(fd, line, w - line);
        close(fd);
    }
}
