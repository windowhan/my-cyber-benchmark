#include <snx.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pwd.h>

/*
 * snx entry point: parse config, build listeners, run event loop.
 */

snx_cfg_t snx_cfg = {
    .keepalive_timeout     = 75,
    .client_header_timeout = 60,
    .client_body_timeout   = 60,
    .send_timeout          = 60,
    .keepalive_requests    = 1000,
    .worker_connections    = 1024,
    .client_max_body_size  = 1048576,
    .large_client_header   = 8192,
    .server_tokens         = 1,
    .etag                  = 1,
    .merge_slashes         = 1,
    .underscores_in_headers= 0,
    .ignore_invalid_headers= 1,
    .sendfile              = 0,
    .tcp_nodelay           = 1,
    .tcp_nopush            = 0,
    .max_ranges            = 0,
    .limit_rate            = 0,
    .chunked_te            = 1,
    .absolute_redirect     = 1,
    .lingering_close       = 1,
    .server_name_in_redirect = 0,
    .port_in_redirect      = 1,
    .log_not_found         = 0,
    .recursive_error_pages = 0,
    .gzip                  = 0,
    .gzip_min_len          = 20,
    .gzip_level            = 6,
    .gzip_vary             = 0,
    .gzip_static           = 0,
    .file_cache_max        = 0,
    .file_cache_inactive   = 60,
    .worker_processes      = 1,
    .accept_mutex          = 0,
    .multi_accept          = 0,
};

int snx_conns;
int snx_conns_total;
int snx_conns_handled;
int snx_conns_reading;
int snx_conns_writing;
int snx_conns_waiting;

/* master shutdown: workers share the process group */
static void
snx_master_term(int sig)
{
    (void) sig;
    kill(0, SIGTERM);
    _exit(0);
}

static int      snx_daemon_on = 1;
static int      snx_test_only = 0;
static snx_log_t snx_file_log = { SNX_LOG_NOTICE, -1 };

static void snx_usage(void);
static int  snx_boot_http(snx_arena_t *a, snx_node_t *http,
                          snx_listen_t **out, int *nout);

static void
snx_usage(void)
{
    fprintf(stderr, "usage: snx [-t] [-g] [-c file] [-p prefix]\n");
}

int
main(int argc, char **argv)
{
    const char   *conf_path = "conf/snx.conf";
    const char   *prefix = ".";
    snx_arena_t  *a;
    snx_node_t   *root, *http, *n;
    snx_listen_t *listens = NULL;
    int           nlisten = 0, i;
    char          cwd[256];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0) {
            snx_test_only = 1;
        } else if (strcmp(argv[i], "-g") == 0) {
            snx_daemon_on = 0;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            conf_path = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            prefix = argv[++i];
        } else {
            snx_usage();
            return 1;
        }
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, ".");
    }
    if (chdir(prefix) == -1) {
        fprintf(stderr, "chdir %s failed\n", prefix);
        return 1;
    }

    a = snx_arena_new(16384);
    if (a == NULL) {
        return 1;
    }

    root = snx_conf_parse(conf_path, a);
    if (root == NULL) {
        return 1;
    }

    n = snx_node_find(root, "daemon");
    if (n && snx_node_arg(n, 0) && strcmp(snx_node_arg(n, 0), "off") == 0) {
        snx_daemon_on = 0;
    }

    n = snx_node_find(root, "error_log");
    if (n && snx_node_arg(n, 0)) {
        int fd = open(snx_node_arg(n, 0),
                      O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd != -1) {
            snx_file_log.fd = fd;
        }
    }

    http = snx_node_find(root, "http");
    if (http == NULL) {
        snx_log(&snx_stderr_log, SNX_LOG_ERR, "no http block");
        return 1;
    }

    /* main-context directives */
    {
        const char *v;
        if ((v = snx_conf_arg(root, "worker_processes"))) {
            snx_cfg.worker_processes =
                strcmp(v, "auto") == 0 ? 2 : atoi(v);
        }
        if ((v = snx_conf_arg(root, "pid"))) {
            snprintf(snx_cfg.pid_path, sizeof(snx_cfg.pid_path),
                     "%s", v);
        }
        if ((v = snx_conf_arg(root, "user"))) {
            snprintf(snx_cfg.user_name, sizeof(snx_cfg.user_name),
                     "%s", v);
        }
        if ((v = snx_conf_arg(root, "worker_rlimit_nofile"))) {
            snx_cfg.rlimit_nofile = atoi(v);
        }
        {
            snx_node_t *ev = snx_node_find(root, "events");
            if (ev) {
                if ((v = snx_conf_arg(ev, "worker_connections"))) {
                    snx_cfg.worker_connections = atoi(v);
                }
                if ((v = snx_conf_arg(ev, "accept_mutex"))) {
                    snx_cfg.accept_mutex = strcmp(v, "on") == 0;
                }
                if ((v = snx_conf_arg(ev, "multi_accept"))) {
                    snx_cfg.multi_accept = strcmp(v, "on") == 0;
                }
            }
        }
    }

    if (snx_boot_http(a, http, &listens, &nlisten) != SNX_OK) {
        return 1;
    }

    if (snx_test_only) {
        printf("snx: configuration file %s test is successful\n",
               conf_path);
        return 0;
    }

    /* optional subsystems — their listeners merge into the shared
       table before sockets are bound */
    {
        snx_node_t *mail = snx_node_find(root, "mail");
        if (mail) {
            snx_listen_t *mls = NULL;
            int           nml = 0;
            snx_mail_listens(mail, &mls, &nml);
            if (nml > 0) {
                listens = realloc(listens,
                                  (nlisten + nml) * sizeof(*listens));
                memcpy(listens + nlisten, mls, nml * sizeof(*mls));
                nlisten += nml;
                free(mls);
            }
            snx_mail_conf(mail, a);
        }
        snx_node_t *stream = snx_node_find(root, "stream");
        if (stream) {
            snx_listen_t *sls = NULL;
            int           nsl = 0;
            snx_stream_listens(stream, &sls, &nsl);
            if (nsl > 0) {
                listens = realloc(listens,
                                  (nlisten + nsl) * sizeof(*listens));
                memcpy(listens + nlisten, sls, nsl * sizeof(*sls));
                nlisten += nsl;
                free(sls);
            }
            (void) snx_stream_conf(stream, a);
        }
    }

    /* listeners are created before forking so every worker inherits
       the same bound sockets */
    for (i = 0; i < nlisten; i++) {
        int  rc = (listens[i].proto
                   && (strcmp((char *) listens[i].proto, "quic") == 0
                       || (strcmp((char *) listens[i].proto,
                                  "stream") == 0
                           && listens[i].udp_on)))
                  ? snx_listen_start_udp(&listens[i], INADDR_ANY,
                                         listens[i].fd_port)
                  : snx_listen_start(&listens[i], INADDR_ANY,
                                     listens[i].fd_port);
        if (rc != SNX_OK) {
            snx_log(&snx_stderr_log, SNX_LOG_ERR,
                    "listen failed: %d", errno);
            return 1;
        }
        snx_log(&snx_stderr_log, SNX_LOG_NOTICE,
                "listen on 0.0.0.0:%d", listens[i].fd_port);
    }

    if (snx_cfg.pid_path[0]) {
        FILE *pf = fopen(snx_cfg.pid_path, "w");
        if (pf) {
            fprintf(pf, "%d\n", (int) getpid());
            fclose(pf);
        }
    }

    if (snx_cfg.rlimit_nofile > 0) {
        struct rlimit rl = { snx_cfg.rlimit_nofile,
                             snx_cfg.rlimit_nofile };
        (void) setrlimit(RLIMIT_NOFILE, &rl);
    }

    if (snx_cfg.user_name[0] && geteuid() == 0) {
        struct passwd *pw = getpwnam(snx_cfg.user_name);
        if (pw) {
            setgid(pw->pw_gid);
            setuid(pw->pw_uid);
        }
    }

    if (snx_daemon_on) {
        if (daemon(0, 0) == -1) {
            return 1;
        }
    }

    /* workers: each child gets its own kqueue on the shared listeners;
       the master supervises (simple respawn) */
    if (snx_cfg.worker_processes > 1) {
        int   w;
        pid_t kids[64];
        int   nkids = 0;

        for (w = 0; w < snx_cfg.worker_processes && nkids < 64; w++) {
            pid_t pid = fork();
            if (pid == 0) {
                goto worker;
            }
            kids[nkids++] = pid;
        }
        /* master: wait for children, respawn on exit; TERM/INT is
           fanned out to the whole worker set */
        signal(SIGTERM, snx_master_term);
        signal(SIGINT, snx_master_term);
        for ( ;; ) {
            int   st;
            pid_t pid = wait(&st);
            if (pid < 0) {
                break;
            }
            {
                int i2;
                for (i2 = 0; i2 < nkids; i2++) {
                    if (kids[i2] == pid) {
                        kids[i2] = fork();
                        if (kids[i2] == 0) {
                            goto worker;
                        }
                        break;
                    }
                }
            }
        }
        return 0;
    }

worker:
    if (snx_ev_init() != SNX_OK) {
        return 1;
    }

    for (i = 0; i < nlisten; i++) {
        if (snx_ev_add(&listens[i].ev, SNX_EVF_READ) != SNX_OK) {
            return 1;
        }
    }

    snx_log(&snx_stderr_log, SNX_LOG_NOTICE, "%s ready (pid %d)",
            SNX_VER, (int) getpid());

    return snx_ev_run();
}

/* ================= http block boot ================= */

static int
snx_loc_fill(snx_arena_t *a, snx_srv_t *srv, snx_loc_t *loc,
             snx_node_t *ln)
{
    int  i;

    for (i = 0; i < ln->nkids; i++) {
        snx_node_t  *d = ln->kids[i];
        const char  *a0 = snx_node_arg(d, 0);

        if (strcmp(d->name, "root") == 0 && a0) {
            loc->root.p = (uchar *) a0;
            loc->root.n = strlen(a0);
        } else if (strcmp(d->name, "alias") == 0 && a0) {
            loc->alias.p = (uchar *) a0;
            loc->alias.n = strlen(a0);
        } else if (strcmp(d->name, "charset") == 0 && a0) {
            loc->charset.p = (uchar *) a0;
            loc->charset.n = strlen(a0);
        } else if (strcmp(d->name, "source_charset") == 0 && a0) {
            loc->src_charset.p = (uchar *) a0;
            loc->src_charset.n = strlen(a0);
        } else if (strcmp(d->name, "ssi") == 0 && a0) {
            loc->ssi_on = strcmp(a0, "on") == 0;
        } else if (strcmp(d->name, "ssi_types") == 0 && a0) {
            loc->ssi_types.p = (uchar *) a0;
            loc->ssi_types.n = strlen(a0);
        } else if (strcmp(d->name, "internal") == 0) {
            loc->internal_only = 1;
        } else if (strcmp(d->name, "index") == 0) {
            /* kept on conf node; first arg cached */
            loc->index.p = (uchar *) a0;
            loc->index.n = a0 ? strlen(a0) : 0;
        } else if (strcmp(d->name, "autoindex") == 0 && a0) {
            loc->autoindex = strcmp(a0, "on") == 0;
        } else if (strcmp(d->name, "sendfile") == 0 && a0) {
            loc->sendfile_on = strcmp(a0, "on") == 0;
        } else if (strcmp(d->name, "etag") == 0 && a0) {
            loc->etag_off = strcmp(a0, "off") == 0;
        } else if (strcmp(d->name, "limit_rate") == 0 && a0) {
            loc->limit_rate = snx_parse_size(a0);
        } else if (strcmp(d->name, "empty_gif") == 0) {
            loc->handler = snx_mod_empty_gif;
        } else if (strcmp(d->name, "stub_status") == 0
                   && a0 && strcmp(a0, "on") == 0)
        {
            loc->handler = snx_mod_stub_status;
        } else if (strcmp(d->name, "dav_methods") == 0) {
            int  j;
            loc->dav_on = 1;
            for (j = 0; j < d->nargs; j++) {
                const char *m = snx_node_arg(d, j);
                static const struct { const char *n; int id; } mt[] = {
                    {"PUT",SNX_M_PUT},{"DELETE",SNX_M_DELETE},
                    {"MKCOL",SNX_M_MKCOL},{"COPY",SNX_M_COPY},
                    {"MOVE",SNX_M_MOVE}
                };
                unsigned k;
                for (k = 0; k < sizeof(mt)/sizeof(mt[0]); k++) {
                    if (strcasecmp(m, mt[k].n) == 0) {
                        loc->flags |= (1u << mt[k].id);
                    }
                }
            }
            if (loc->flags == 0) {
                loc->flags |= (1u << SNX_M_PUT);
            }
        } else if (strcmp(d->name, "limit_except") == 0) {
            int  j;
            for (j = 0; j < d->nargs; j++) {
                const char *m = snx_node_arg(d, j);
                snx_str_t   ms = { (uchar *) m,
                                   m ? strlen(m) : 0 };
                int         id = snx_method_id(&ms);
                if (id) {
                    loc->le_mask |= (1u << id);
                }
            }
        } else if (strcmp(d->name, "proxy_cache_use_stale") == 0) {
            int  j;
            for (j = 0; j < d->nargs; j++) {
                const char *m = snx_node_arg(d, j);
                if (strcmp(m, "error") == 0)     loc->cache_stale |= 1;
                if (strcmp(m, "timeout") == 0)   loc->cache_stale |= 2;
                if (strcmp(m, "updating") == 0)  loc->cache_stale |= 4;
                if (strcmp(m, "off") == 0)       loc->cache_stale = 0;
            }
        } else if (strcmp(d->name, "dav_ext") == 0 && a0) {
            loc->dav_ext.p = (uchar *) a0;
            loc->dav_ext.n = strlen(a0);
        } else if (strcmp(d->name, "slice") == 0 && a0) {
            loc->slice_size = snx_atooff((uchar *) a0, strlen(a0));
        } else if (strcmp(d->name, "aio") == 0 && a0) {
            loc->aio_on = strcmp(a0, "on") == 0;
        } else if (strcmp(d->name, "mp4") == 0) {
            loc->mp4_on = 1;
        } else if (strcmp(d->name, "mp4_buffer_size") == 0 && a0) {
            loc->mp4_buf.p = (uchar *) a0;
            loc->mp4_buf.n = strlen(a0);
        } else if (strcmp(d->name, "proxy_pass") == 0 && a0) {
            loc->handler = snx_mod_proxy;
        } else if (strcmp(d->name, "scgi_pass") == 0 && a0) {
            loc->handler = snx_mod_scgi;
        } else if (strcmp(d->name, "grpc_pass") == 0 && a0) {
            loc->handler = snx_mod_grpc;
        } else if (strcmp(d->name, "fastcgi_pass") == 0 && a0) {
            loc->handler = snx_mod_fastcgi;
        } else if (strcmp(d->name, "uwsgi_pass") == 0 && a0) {
            loc->handler = snx_mod_uwsgi;
        } else if (strcmp(d->name, "memcached_pass") == 0 && a0) {
            loc->handler = snx_mod_memcached;
        }
    }

    /* location-local rewrite/table directives are resolved per-request */
    loc->conf = ln;
    (void) srv;
    return SNX_OK;
}

static int
snx_srv_fill(snx_arena_t *a, snx_srv_t *srv, snx_node_t *sn)
{
    int  i;

    for (i = 0; i < sn->nkids; i++) {
        snx_node_t  *d = sn->kids[i];
        const char  *a0 = snx_node_arg(d, 0);

        if (strcmp(d->name, "server_name") == 0) {
            int  j;
            for (j = 0; j < d->nargs; j++) {
                const char *nm = snx_node_arg(d, j);
                snx_str_t  *nn;
                if (nm == NULL) {
                    continue;
                }
                nn = snx_arena_alloc(a,
                       (srv->nnames + 1) * sizeof(snx_str_t));
                memcpy(nn, srv->names,
                       srv->nnames * sizeof(snx_str_t));
                nn[srv->nnames].p = (uchar *) nm;
                nn[srv->nnames].n = strlen(nm);
                srv->names = nn;
                srv->nnames++;
            }
            if (srv->name.p == NULL && a0) {
                srv->name.p = (uchar *) a0;
                srv->name.n = strlen(a0);
            }
        } else if (strcmp(d->name, "root") == 0 && a0) {
            srv->root.p = (uchar *) a0;
            srv->root.n = strlen(a0);
        } else if (strcmp(d->name, "charset") == 0 && a0) {
            srv->charset.p = (uchar *) a0;
            srv->charset.n = strlen(a0);
        } else if (strcmp(d->name, "default_type") == 0 && a0) {
            srv->dfl_type.p = (uchar *) a0;
            srv->dfl_type.n = strlen(a0);
        } else if (strcmp(d->name, "location") == 0) {
            snx_loc_t  *loc = snx_acnew(a, snx_loc_t);
            const char *mod = NULL;
            const char *uri = a0;

            /* modifier arg: = ^~ ~ ~* or @name prefixing the uri */
            if (d->nargs >= 2) {
                mod = a0;
                uri = snx_node_arg(d, 1);
            }

            if (mod && strcmp(mod, "=") == 0) {
                loc->kind = SNX_LOC_EXACT;
            } else if (mod && strcmp(mod, "^~") == 0) {
                loc->kind = SNX_LOC_NOSTOP;
            } else if (mod && strcmp(mod, "~") == 0) {
                loc->kind = SNX_LOC_REGEX;
            } else if (mod && strcmp(mod, "~*") == 0) {
                loc->kind = SNX_LOC_REGEX_NC;
            } else if (a0 && a0[0] == '@') {
                loc->kind = SNX_LOC_NAMED;
                uri = a0 + 1;
            } else {
                loc->kind = SNX_LOC_PREFIX;
            }

            loc->uri.p = (uchar *) uri;
            loc->uri.n = uri ? strlen(uri) : 0;

            if (loc->kind == SNX_LOC_REGEX
                || loc->kind == SNX_LOC_REGEX_NC)
            {
                char  pat[512];
                if (loc->uri.n < sizeof(pat)) {
                    memcpy(pat, loc->uri.p, loc->uri.n);
                    pat[loc->uri.n] = '\0';
                    loc->re = malloc(sizeof(regex_t));
                    if (regcomp(loc->re, pat,
                        REG_EXTENDED | REG_NOSUB
                        | (loc->kind == SNX_LOC_REGEX_NC
                           ? REG_ICASE : 0)) != 0)
                    {
                        free(loc->re);
                        loc->re = NULL;
                    }
                }
            }

            if (loc->root.p == NULL && srv->root.p) {
                loc->root = srv->root;
            }

            loc->next = srv->locs;
            srv->locs = loc;
            snx_loc_fill(a, srv, loc, d);
        }
    }
    srv->conf = sn;
    return SNX_OK;
}

/* ---- mime types ---- */

typedef struct {
    snx_str_t   type;
    snx_str_t   ext;
} snx_mime_t;

static snx_mime_t  snx_mime[512];
static int         snx_nmime;

static void
snx_mime_add(const char *type, const char *ext)
{
    if (snx_nmime >= 512) {
        return;
    }
    snx_mime[snx_nmime].type.p = (uchar *) type;
    snx_mime[snx_nmime].type.n = strlen(type);
    snx_mime[snx_nmime].ext.p = (uchar *) ext;
    snx_mime[snx_nmime].ext.n = strlen(ext);
    snx_nmime++;
}

int
snx_mime_init(snx_arena_t *a, snx_node_t *http)
{
    int  i, j;

    /* built-in table mirrors the common mime.types entries */
    snx_mime_add("text/html", "html");
    snx_mime_add("text/html", "htm");
    snx_mime_add("text/html", "shtml");
    snx_mime_add("text/css", "css");
    snx_mime_add("text/plain", "txt");
    snx_mime_add("text/xml", "xml");
    snx_mime_add("image/gif", "gif");
    snx_mime_add("image/jpeg", "jpg");
    snx_mime_add("image/jpeg", "jpeg");
    snx_mime_add("image/png", "png");
    snx_mime_add("image/svg+xml", "svg");
    snx_mime_add("image/webp", "webp");
    snx_mime_add("image/x-icon", "ico");
    snx_mime_add("application/javascript", "js");
    snx_mime_add("application/json", "json");
    snx_mime_add("application/pdf", "pdf");
    snx_mime_add("application/zip", "zip");
    snx_mime_add("application/gzip", "gz");
    snx_mime_add("video/mp4", "mp4");
    snx_mime_add("video/x-flv", "flv");
    snx_mime_add("audio/mpeg", "mp3");
    snx_mime_add("application/octet-stream", "bin");
    snx_mime_add("application/octet-stream", "exe");
    snx_mime_add("font/woff", "woff");
    snx_mime_add("font/woff2", "woff2");
    snx_mime_add("application/wasm", "wasm");

    /* types { type ext...; } blocks extend or override */
    for (i = 0; http && i < http->nkids; i++) {
        snx_node_t *d = http->kids[i];
        if (strcmp(d->name, "types") == 0) {
            for (j = 0; j < d->nkids; j++) {
                snx_node_t *t = d->kids[j];
                int         k;
                for (k = 0; k < t->nargs; k++) {
                    const char *e = snx_node_arg(t, k);
                    if (e) {
                        snx_mime_add(t->name, e);
                    }
                }
            }
        }
        if (strcmp(d->name, "server") == 0) {
            for (j = 0; j < d->nkids; j++) {
                if (strcmp(d->kids[j]->name, "types") == 0) {
                    snx_node_t *tb = d->kids[j];
                    int         k, l;
                    for (k = 0; k < tb->nkids; k++) {
                        snx_node_t *t = tb->kids[k];
                        for (l = 0; l < t->nargs; l++) {
                            const char *e = snx_node_arg(t, l);
                            if (e) {
                                snx_mime_add(t->name, e);
                            }
                        }
                    }
                }
            }
        }
    }
    (void) a;
    return SNX_OK;
}

snx_str_t
snx_mime_type(snx_http_req_t *r)
{
    snx_str_t    out = { NULL, 0 };
    const char  *dfl = "application/octet-stream";
    int          i;

    if (r->ext.p && r->ext.n > 1) {
        for (i = snx_nmime - 1; i >= 0; i--) {
            if (snx_mime[i].ext.n == r->ext.n - 1
                && snx_ncasecmp(snx_mime[i].ext.p, r->ext.p + 1,
                                r->ext.n - 1) == 0)
            {
                return snx_mime[i].type;
            }
        }
    }

    /* location default_type > server default_type > global default */
    if (r->loc && r->loc->conf) {
        const char *v = snx_conf_arg(r->loc->conf, "default_type");
        if (v) {
            out.p = (uchar *) v;
            out.n = strlen(v);
            return out;
        }
    }
    if (r->srv && r->srv->dfl_type.p) {
        return r->srv->dfl_type;
    }
    out.p = (uchar *) dfl;
    out.n = strlen(dfl);
    return out;
}

static int
snx_boot_http(snx_arena_t *a, snx_node_t *http,
              snx_listen_t **out, int *nout)
{
    int            i, j, nl = 0, cap = 8;
    snx_listen_t  *ls;
    const char    *v;

    ls = calloc(cap, sizeof(snx_listen_t));

    /* http-level globals */
    if ((v = snx_conf_arg(http, "keepalive_timeout"))) {
        snx_cfg.keepalive_timeout = (int) snx_parse_time(v);
    }
    if ((v = snx_conf_arg(http, "client_header_timeout"))) {
        snx_cfg.client_header_timeout = (int) snx_parse_time(v);
    }
    if ((v = snx_conf_arg(http, "client_body_timeout"))) {
        snx_cfg.client_body_timeout = (int) snx_parse_time(v);
    }
    if ((v = snx_conf_arg(http, "send_timeout"))) {
        snx_cfg.send_timeout = (int) snx_parse_time(v);
    }
    if ((v = snx_conf_arg(http, "keepalive_requests"))) {
        snx_cfg.keepalive_requests = atoi(v);
    }
    if ((v = snx_conf_arg(http, "resolver"))) {
        snx_cfg.resolver.p = (uchar *) v;
        snx_cfg.resolver.n = strlen(v);
    }
    if ((v = snx_conf_arg(http, "client_max_body_size"))) {
        snx_cfg.client_max_body_size = snx_parse_size(v);
    }
    if ((v = snx_conf_arg(http, "server_tokens"))) {
        snx_cfg.server_tokens = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "etag"))) {
        snx_cfg.etag = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "merge_slashes"))) {
        snx_cfg.merge_slashes = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "underscores_in_headers"))) {
        snx_cfg.underscores_in_headers = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "ignore_invalid_headers"))) {
        snx_cfg.ignore_invalid_headers = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "sendfile"))) {
        snx_cfg.sendfile = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "tcp_nodelay"))) {
        snx_cfg.tcp_nodelay = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "tcp_nopush"))) {
        snx_cfg.tcp_nopush = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "max_ranges"))) {
        snx_cfg.max_ranges = snx_parse_size(v);
    }
    if ((v = snx_conf_arg(http, "limit_rate"))) {
        snx_cfg.limit_rate = snx_parse_size(v);
    }
    if ((v = snx_conf_arg(http, "chunked_transfer_encoding"))) {
        snx_cfg.chunked_te = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "absolute_redirect"))) {
        snx_cfg.absolute_redirect = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "server_name_in_redirect"))) {
        snx_cfg.server_name_in_redirect = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "port_in_redirect"))) {
        snx_cfg.port_in_redirect = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "gzip"))) {
        snx_cfg.gzip = strcmp(v, "on") == 0;
    }
    if ((v = snx_conf_arg(http, "gzip_min_length"))) {
        snx_cfg.gzip_min_len = snx_parse_size(v);
    }
    if ((v = snx_conf_arg(http, "gzip_comp_level"))) {
        snx_cfg.gzip_level = atoi(v);
    }
    if ((v = snx_conf_arg(http, "gzip_vary"))) {
        snx_cfg.gzip_vary = strcmp(v, "on") == 0;
    }
    if (snx_conf_find(http, "gzip_types")) {
        snx_node_t *n = snx_conf_find(http, "gzip_types");
        size_t      tot = 1;
        int         k;
        for (k = 0; k < n->nargs; k++) {
            const char *a = snx_node_arg(n, k);
            if (a) {
                tot += strlen(a) + 1;
            }
        }
        {
            uchar *s = malloc(tot), *w = s;
            for (k = 0; k < n->nargs; k++) {
                const char *a = snx_node_arg(n, k);
                if (a) {
                    w = snx_cpymem(w, (uchar *) a, strlen(a));
                    *w++ = ' ';
                }
            }
            snx_cfg.gzip_types.p = s;
            snx_cfg.gzip_types.n = w - s;
        }
    }
    if ((v = snx_conf_arg(http, "gzip_static"))) {
        snx_cfg.gzip_static = strcmp(v, "always") == 0 ? 2
                              : strcmp(v, "off") != 0;
    }
    if ((v = snx_conf_arg(http, "open_file_cache"))) {
        /* "max=N [inactive=T]" */
        snx_node_t *n = snx_conf_find(http, "open_file_cache");
        int         k;
        for (k = 0; n && k < n->nargs; k++) {
            const char *s = snx_node_arg(n, k);
            if (strncmp(s, "max=", 4) == 0) {
                snx_cfg.file_cache_max = snx_parse_size(s + 4);
            } else if (strncmp(s, "inactive=", 9) == 0) {
                snx_cfg.file_cache_inactive =
                    (int) snx_parse_time(s + 9);
            }
        }
    }
    if ((v = snx_conf_arg(http, "lingering_close"))) {
        snx_cfg.lingering_close = strcmp(v, "off") != 0;
    }

    /* http-level registries */
    (void) snx_mime_init(a, http);
    (void) snx_upstreams_init(a, http);
    (void) snx_zones_init(a, http);
    (void) snx_cache_init(a, http);
    (void) snx_access_log_init(a, http);

    for (i = 0; i < http->nkids; i++) {
        snx_node_t  *sn = http->kids[i];
        int          port = 0;
        const char  *proto = NULL;
        int          ssl = 0, deflt = 0;

        if (strcmp(sn->name, "server") != 0) {
            continue;
        }

        /* each listen directive attaches the server to its own
           (port,ssl,proto) entry — a server may listen many times */
        {
            int saw_listen = 0;
            for (j = 0; j < sn->nkids; j++) {
                snx_node_t  *d = sn->kids[j];
                if (strcmp(d->name, "listen") != 0 || !d->nargs) {
                    continue;
                }
                {
                    const char *la = snx_node_arg(d, 0);
                    const char *colon = strrchr(la, ':');
                    int         k;
                    port = atoi(colon ? colon + 1 : la);
                    proto = NULL;
                    ssl = 0;
                    deflt = 0;
                    saw_listen = 1;
                    for (k = 1; k < d->nargs; k++) {
                        const char *opt = snx_node_arg(d, k);
                        if (strcmp(opt, "ssl") == 0) {
                            ssl = 1;
                        } else if (strcmp(opt, "default_server") == 0) {
                            deflt = 1;
                        } else if (strcmp(opt, "http2") == 0) {
                            proto = "http2";
                        } else if (strcmp(opt, "spdy") == 0) {
                            proto = "spdy";
                        } else if (strcmp(opt, "quic") == 0) {
                            proto = "quic";
                        }
                    }
                }

                if (port == 0) {
                    port = 8080;
                }

                /* attach server to the matching listen entry */
                {
                    int k, found = -1;
                    for (k = 0; k < nl; k++) {
                        if (ls[k].fd_port == port && ls[k].ssl_on == ssl
                            && ((ls[k].proto == NULL && proto == NULL)
                                || (ls[k].proto && proto
                                    && strcmp(ls[k].proto,
                                              proto) == 0)))
                        {
                            found = k;
                            break;
                        }
                    }
                    if (found == -1) {
                        found = nl++;
                        if (nl > cap) {
                            cap *= 2;
                            ls = realloc(ls,
                                         cap * sizeof(snx_listen_t));
                            memset(&ls[found], 0,
                                   (cap - found)
                                   * sizeof(snx_listen_t));
                        }
                        memset(&ls[found], 0, sizeof(snx_listen_t));
                        ls[found].fd_port = port;
                        ls[found].ssl_on = ssl;
                        ls[found].proto =
                            proto ? (void *) proto : NULL;
                    }
                    if (deflt) {
                        ls[found].default_idx = ls[found].nservers;
                    }

                    {
                        snx_srv_t  *srv = snx_acnew(a, snx_srv_t);
                        int         idx = ls[found].nservers;

                        srv->default_srv = deflt;
                        ls[found].servers =
                            realloc(ls[found].servers,
                                    (idx + 1) * sizeof(void *));
                        ls[found].servers[idx] = srv;
                        ls[found].nservers++;
                        snx_srv_fill(a, srv, sn);
                        if (ssl) {
                            srv->ssl_ctx = snx_tls_setup(sn);
                        }
                    }
                }
            }
            if (!saw_listen) {
                port = 8080;
            }
        }
    }

    *out = ls;
    *nout = nl;

    if (nl == 0) {
        /* implicit default listener */
        nl = 1;
        ls[0].fd_port = 8080;
        {
            snx_srv_t *srv = snx_acnew(a, snx_srv_t);
            ls[0].servers = malloc(sizeof(void *));
            ls[0].servers[0] = srv;
            ls[0].nservers = 1;
        }
        *out = ls;
        *nout = nl;
    }

    return SNX_OK;
}
