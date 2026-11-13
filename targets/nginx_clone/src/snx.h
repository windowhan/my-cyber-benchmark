#ifndef SNX_H
#define SNX_H

/*
 * snx — a small event-driven HTTP server.
 * Master header: shared types, utilities, and module interfaces.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include <regex.h>
#include <zlib.h>

#define SNX_VER        "snx/1.0.0"
#define SNX_OK          0
#define SNX_ERROR      -1
#define SNX_AGAIN      -2
#define SNX_DONE       -3
#define SNX_DECLINED   -4
#define SNX_ABORT      -5

#define SNX_CR          '\r'
#define SNX_LF          '\n'
#define SNX_CRLF        "\r\n"

typedef unsigned char              uchar;
typedef int64_t                    soff_t;

/* ---------- status codes ---------- */
#define SNX_HTTP_OK                 200
#define SNX_HTTP_CREATED            201
#define SNX_HTTP_NO_CONTENT         204
#define SNX_HTTP_PARTIAL            206
#define SNX_HTTP_MOVED              301
#define SNX_HTTP_FOUND              302
#define SNX_HTTP_SEE_OTHER          303
#define SNX_HTTP_NOT_MODIFIED       304
#define SNX_HTTP_BAD_REQUEST        400
#define SNX_HTTP_UNAUTHORIZED       401
#define SNX_HTTP_FORBIDDEN          403
#define SNX_HTTP_NOT_FOUND          404
#define SNX_HTTP_NOT_ALLOWED        405
#define SNX_HTTP_CONFLICT           409
#define SNX_HTTP_LENGTH_REQUIRED    411
#define SNX_HTTP_TOO_LARGE          413
#define SNX_HTTP_URI_TOO_LONG       414
#define SNX_HTTP_RANGE_BAD          416
#define SNX_HTTP_INTERNAL           500
#define SNX_HTTP_NOT_IMPLEMENTED    501
#define SNX_HTTP_BAD_GATEWAY        502
#define SNX_HTTP_UNAVAILABLE        503

/* methods */
#define SNX_M_GET       1
#define SNX_M_HEAD      2
#define SNX_M_POST      3
#define SNX_M_PUT       4
#define SNX_M_DELETE    5
#define SNX_M_MKCOL     6
#define SNX_M_COPY      7
#define SNX_M_MOVE      8
#define SNX_M_OPTIONS   9
#define SNX_M_PROPFIND  10
#define SNX_M_PROPPATCH 11
#define SNX_M_LOCK      12
#define SNX_M_UNLOCK    13
#define SNX_M_TRACE     14

/* location match kinds */
#define SNX_LOC_PREFIX    0
#define SNX_LOC_NOSTOP    1   /* ^~  prefix match; regexes are skipped */
#define SNX_LOC_EXACT     2   /* =   exact match */
#define SNX_LOC_REGEX     3   /* ~   case-sensitive regex */
#define SNX_LOC_REGEX_NC  4   /* ~*  case-insensitive regex */
#define SNX_LOC_NAMED     5   /* @x  internal-only named location */

/* upstream selection methods */
#define SNX_UP_RR         0   /* weighted round robin */
#define SNX_UP_LEAST_CONN 1
#define SNX_UP_IPHASH     2
#define SNX_UP_HASH       3
#define SNX_UP_LEAST_TIME 4

/* ---------- string ---------- */
typedef struct {
    uchar   *p;
    size_t   n;
} snx_str_t;

#define snx_str_lit(s)      { (uchar *) (s), sizeof(s) - 1 }
#define snx_str_null        { NULL, 0 }
#define snx_str_set(s, v)   do { (s)->p = (uchar *) (v); (s)->n = sizeof(v) - 1; } while (0)

/* ---------- arena allocator ---------- */
/* region allocator: allocate-only, freed all at once at request end */

typedef struct snx_chunk_s {
    struct snx_chunk_s  *next;
    uchar               *last;
    uchar               *end;
} snx_chunk_t;

typedef struct snx_arena_s {
    snx_chunk_t   *cur;
    snx_chunk_t   *large;
    size_t         max;
} snx_arena_t;

snx_arena_t  *snx_arena_new(size_t size);
void          snx_arena_free(snx_arena_t *a);
void          snx_arena_reset(snx_arena_t *a);
void         *snx_arena_alloc(snx_arena_t *a, size_t size);
void         *snx_arena_calloc(snx_arena_t *a, size_t size);
#define snx_anew(a, T)     ((T *) snx_arena_alloc((a), sizeof(T)))
#define snx_acnew(a, T)    ((T *) snx_arena_calloc((a), sizeof(T)))

/* ---------- io buffer ---------- */

#define SNX_IOB_MEM    0x01
#define SNX_IOB_FILE   0x02
#define SNX_IOB_LAST   0x04
#define SNX_IOB_FLUSH  0x08
#define SNX_IOB_TMP    0x10

typedef struct snx_iobuf_s {
    uchar                *base;    /* allocation base */
    uchar                *head;    /* first data byte */
    uchar                *tail;    /* one past last data byte */
    size_t                cap;
    unsigned              flags;
    int                   fd;      /* for SNX_IOB_FILE */
    soff_t                fpos;    /* file read offset */
    soff_t                flen;    /* file bytes to send */
    struct snx_iobuf_s   *next;
} snx_iobuf_t;

#define snx_iob_len(b)    ((size_t) ((b)->tail - (b)->head))

snx_iobuf_t  *snx_iob_new(snx_arena_t *a, size_t cap);
snx_iobuf_t  *snx_iob_file(snx_arena_t *a, int fd, soff_t pos, soff_t len);
void          snx_iob_append(snx_iobuf_t **head, snx_iobuf_t **tail,
                             snx_iobuf_t *b);

/* ---------- string utils ---------- */
long      snx_atoi(uchar *p, size_t n);
soff_t    snx_atooff(uchar *p, size_t n);
uchar    *snx_cpymem(uchar *dst, const uchar *src, size_t n);
uchar    *snx_strlchr(uchar *s, uchar *last, uchar c);
int       snx_ncmp(uchar *a, uchar *b, size_t n);
int       snx_ncasecmp(uchar *a, uchar *b, size_t n);
int       snx_str_eq(snx_str_t *a, const char *b);
snx_str_t snx_str_dup(snx_arena_t *a, snx_str_t *s);

typedef enum {
    SNX_UNESC_STD = 0,
    SNX_UNESC_URI,
    SNX_UNESC_REDIR,
    SNX_UNESC_ARGS,
    SNX_UNESC_COMP
} snx_unesc_t;

void      snx_unescape(uchar **dst, uchar **src, size_t n, int type);

/* ---------- formatter ---------- */
uchar    *snx_fmt(uchar *buf, uchar *last, const char *fmt, ...);
uchar    *snx_vfmt(uchar *buf, uchar *last, const char *fmt, va_list ap);

/* ---------- log ---------- */
#define SNX_LOG_ERR      1
#define SNX_LOG_WARN     2
#define SNX_LOG_NOTICE   3
#define SNX_LOG_INFO     4
#define SNX_LOG_DEBUG    5

typedef struct snx_log_s {
    int    level;
    int    fd;
} snx_log_t;

extern snx_log_t  snx_stderr_log;

void snx_log_write(snx_log_t *log, int level, const char *fmt, ...);
void snx_log_err(snx_log_t *log, const char *fmt, ...);

#define snx_log(l, lv, ...)  snx_log_write((l), (lv), __VA_ARGS__)

/* ---------- md5 ---------- */
typedef struct {
    uint64_t   bytes;
    uint32_t   a, b, c, d;
    uchar      buf[64];
} snx_md5_t;

void snx_md5_init(snx_md5_t *ctx);
void snx_md5_update(snx_md5_t *ctx, const void *data, size_t n);
void snx_md5_final(uchar out[16], snx_md5_t *ctx);

/* ---------- config tree ---------- */

typedef struct snx_node_s {
    char                *name;
    uchar              **args;
    int                  nargs;
    struct snx_node_s   *parent;
    struct snx_node_s  **kids;
    int                  nkids;
} snx_node_t;

snx_node_t  *snx_conf_parse(const char *path, snx_arena_t *a);
snx_node_t  *snx_node_find(snx_node_t *parent, const char *name);
snx_node_t **snx_node_find_all(snx_node_t *parent, const char *name, int *count);
const char  *snx_node_arg(snx_node_t *n, int i);

/* ---------- events ---------- */

typedef struct snx_ev_s {
    void              *data;
    void             (*fn)(struct snx_ev_s *ev);
    int                fd;
    unsigned           flags;
    int                timer_ms;
} snx_ev_t;

#define SNX_EVF_READ     0x01
#define SNX_EVF_WRITE    0x02
#define SNX_EVF_ONESHOT  0x04
#define SNX_EVF_TIMER    0x08

typedef struct snx_conn_s {
    int                fd;
    snx_ev_t           rev;
    snx_ev_t           wev;
    snx_ev_t           tev;      /* deadline timer */
    snx_arena_t       *arena;
    void              *data;
    int               (*on_read)(struct snx_conn_s *);
    int                listen_fd;
    uchar             *addr_text;
    struct sockaddr_storage sa;
    socklen_t          sa_len;
    void              *proto;
    void              *listen;
    int                nreqs;    /* requests served on this conn */
    void              *sslh;     /* SSL object when TLS is enabled */
    int                ssl_ready;
    unsigned           writing:1;
} snx_conn_t;

typedef struct snx_listen_s {
    int          fd;
    int          fd_port;
    snx_ev_t     ev;
    struct snx_srv_s **servers;
    int          nservers;
    int          default_idx;
    void        *proto;      /* "http2", "spdy", "quic" */
    void        *proto_arg;  /* stream proxy target, etc */
    void        *udp;        /* persistent conn for quic listeners */
    int          ssl_on;
    int          pp;         /* proxy_protocol on listen */
    void        *ssl;
    int          preread;
    void        *preread_routes;
    int          n_preread_routes;
    int          udp_on;     /* stream datagram listener */
} snx_listen_t;

int   snx_ev_init(void);
int   snx_ev_add(snx_ev_t *ev, int what);
int   snx_ev_del(snx_ev_t *ev, int what);
int   snx_ev_run(void);
void  snx_ev_later(snx_ev_t *ev);
int   snx_ev_timer(snx_ev_t *ev, int ms);
void  snx_ev_timer_off(snx_ev_t *ev);

/* conn io indirection (plain socket or TLS) */
ssize_t snx_conn_recv(snx_conn_t *c, void *buf, size_t n);
ssize_t snx_conn_send(snx_conn_t *c, const void *buf, size_t n);
void    snx_conn_timer(snx_conn_t *c, int ms);

snx_conn_t *snx_conn_new(int fd, snx_log_t *log);
void        snx_conn_free(snx_conn_t *c);
int         snx_listen_start(snx_listen_t *ls, in_addr_t addr, int port);
int         snx_listen_start_udp(snx_listen_t *ls, in_addr_t addr, int port);

/* ---------- http ---------- */

typedef struct snx_hdr_s {
    snx_str_t          k;
    snx_str_t          v;
    struct snx_hdr_s  *next;
} snx_hdr_t;

typedef struct {
    snx_hdr_t   *list;
    snx_hdr_t  **last;
    snx_str_t   *host;
    snx_str_t   *conn;
    snx_str_t   *cl;
    snx_str_t   *te;
    snx_str_t   *range;
    snx_str_t   *ua;
    snx_str_t   *ctype;
    snx_str_t   *expect;
    snx_str_t   *cookie;
    snx_str_t   *auth;
    snx_str_t   *xff;
    snx_str_t   *te_head;
    snx_str_t   *referer;
    snx_str_t   *ims;       /* if-modified-since */
    snx_str_t   *inm;       /* if-none-match */
    snx_str_t   *ifr;       /* if-range */
    snx_str_t   *ae;        /* accept-encoding */
    snx_str_t   *cc;        /* cache-control */
    snx_str_t   *dest;      /* Destination (dav) */
    snx_str_t   *depth;
    int          chunked;
    long         cl_n;
} snx_in_t;

typedef struct {
    int          status;
    soff_t       cl_n;
    snx_str_t   *ctype;
    snx_str_t   *crange;
    snx_hdr_t   *hdrs;
    snx_hdr_t  **hlast;
    int          header_sent;
} snx_out_t;

typedef struct snx_http_req_s snx_http_req_t;
typedef int (*snx_step_t)(snx_http_req_t *r);
typedef snx_iobuf_t *(*snx_bodyf_t)(snx_http_req_t *r, snx_iobuf_t *in);
typedef int (*snx_headf_t)(snx_http_req_t *r);

typedef struct snx_loc_s {
    snx_str_t     uri;
    int           kind;           /* SNX_LOC_* */
    regex_t      *re;             /* compiled for REGEX kinds */
    int           internal_only;  /* internal; */
    snx_str_t     root;
    snx_str_t     alias;
    snx_str_t     charset;
    snx_str_t     src_charset;
    snx_str_t     ssi_types;
    snx_str_t     dav_ext;
    snx_str_t     mp4_buf;
    snx_str_t     index;          /* index file list */
    unsigned      flags;          /* bit i = method i allowed (dav) */
    int           ssi_on;
    int           dav_on;
    unsigned      le_mask;        /* limit_except allowed-method bits */
    int           cache_stale;    /* proxy_cache_use_stale mask */
    soff_t        slice_size;
    int           mp4_on;
    int           aio_on;
    int           autoindex;
    int           sendfile_on;
    int           etag_off;
    soff_t        limit_rate;
    snx_step_t    handler;
    snx_node_t   *conf;           /* location block node */
    struct snx_loc_s *next;
} snx_loc_t;

typedef struct snx_srv_s {
    snx_str_t     name;
    snx_str_t    *names;
    int           nnames;
    int           default_srv;
    snx_str_t     root;
    snx_str_t     charset;
    snx_str_t     dfl_type;       /* default_type */
    snx_loc_t    *locs;
    snx_node_t   *conf;
    void         *ssl_ctx;
} snx_srv_t;

typedef struct snx_var_s {
    snx_str_t   name;
    snx_str_t   value;
    int         idx;
} snx_var_t;

typedef struct {
    snx_var_t  *v;
    int         n;
    int         cap;
} snx_vars_t;

struct snx_http_req_s {
    snx_conn_t     *c;
    snx_arena_t    *arena;
    snx_iobuf_t    *inbuf;
    snx_iobuf_t    *saved;

    /* parser state */
    int             state;
    uchar          *req_start;
    uchar          *req_end;
    uchar          *uri_s;
    uchar          *uri_e;
    uchar          *args_s;
    uchar          *host_s;
    uchar          *hname_s;
    uchar          *hname_e;
    uchar          *hval_s;
    uchar          *hval_e;

    snx_str_t       method;
    snx_str_t       uri;
    snx_str_t       req_id;  /* $request_id */
    snx_str_t       args;
    snx_str_t       host;
    snx_str_t       unparsed;
    snx_str_t       path;
    snx_str_t       ext;
    int             method_id;
    int             http_ver;
    int             keepalive;
    int             header_only;
    int             discard_body;
    int             err_status;
    int             lingering;
    int             internal;    /* rewritten/internal redirect */
    int             chunked_out; /* body len invalidated -> chunked TE */
    int             invalid_referer;
    soff_t          bytes_sent;
    struct timespec tstart;

    snx_str_t       remote_user;
    snx_str_t       realip;      /* pre-realip remote addr text */
    snx_str_t       etag;
    time_t          mtime;

    snx_in_t        in;
    snx_out_t       out;
    snx_srv_t      *srv;
    snx_loc_t      *loc;
    snx_vars_t      vars;
    void           *range_ctx;
    void           *ssi_vars;
    void           *mp4_ctx;
    void           *body_tf;     /* snx_tmpfile_t */
    void           *fctx;        /* per-request filter chain ctx */
    void           *sub_ctx;     /* sub_filter state */
    void           *gz_ctx;      /* gzip state */
    void           *gunzip_ctx;  /* gunzip state */
    snx_str_t       upstream_status;
    snx_str_t       upstream_cache;
    snx_str_t       upstream_addr;
    void           *up_peer;     /* active upstream peer */
    void           *up_group;    /* upstream{} block it came from */
    int             image_on;    /* image_filter active */
    int             xslt_on;     /* xslt_stylesheet active */

    snx_log_t      *log;
    time_t          t0;
};

typedef struct {
    snx_headf_t   head;
    snx_bodyf_t   body;
} snx_stage_t;

/* global http-level settings (http {} block) */
typedef struct {
    int      keepalive_timeout;
    int      client_header_timeout;
    int      client_body_timeout;
    int      send_timeout;
    int      keepalive_requests;
    int      worker_connections;
    soff_t   client_max_body_size;
    soff_t   large_client_header;
    int      server_tokens;
    int      etag;
    int      merge_slashes;
    int      underscores_in_headers;
    int      ignore_invalid_headers;
    int      sendfile;
    int      tcp_nodelay;
    int      tcp_nopush;
    int      reset_timedout;
    soff_t   max_ranges;
    soff_t   limit_rate;
    int      msie_padding;
    int      chunked_te;
    int      absolute_redirect;
    int      server_name_in_redirect;
    int      port_in_redirect;
    int      log_not_found;
    int      recursive_error_pages;
    soff_t   sub_once_off;
    int      gzip;
    soff_t   gzip_min_len;
    int      gzip_level;
    int      gzip_vary;
    snx_str_t gzip_types;
    int      gzip_static;
    int      aio_write;
    soff_t   file_cache_max;
    int      file_cache_inactive;
    int      lingering_close;
    snx_str_t resolver;             /* nameserver addr (ip[:port]) */
    snx_str_t mail_auth;            /* mail auth_http endpoint */
    char     pid_path[256];
    char     user_name[64];
    int      rlimit_nofile;
    int      worker_processes;
    int      accept_mutex;
    int      multi_accept;
} snx_cfg_t;

extern snx_cfg_t snx_cfg;
extern int       snx_conns;         /* live connection count */
extern int       snx_conns_total;   /* accepted total */
extern int       snx_conns_handled; /* completed requests */
extern int       snx_conns_reading; /* reading state */
extern int       snx_conns_writing; /* writing state */
extern int       snx_conns_waiting; /* keepalive idle */

/* conf helper: first arg of named directive in a node */
const char *snx_conf_arg(snx_node_t *n, const char *name);
snx_node_t *snx_conf_find(snx_node_t *n, const char *name);
soff_t      snx_parse_size(const char *s);
int         snx_method_id(snx_str_t *m);
long        snx_parse_time(const char *s);

/* http core */
void   snx_http_init(snx_conn_t *c);
void   snx_http_req_reset(snx_conn_t *c);
void   snx_http_req_read(snx_ev_t *ev);
void   snx_http_drain(snx_ev_t *ev);
void   snx_http_finish(snx_http_req_t *r, int rc);
void   snx_http_run(snx_http_req_t *r);
int    snx_http_parse_reqline(snx_http_req_t *r, snx_iobuf_t *b);
int    snx_http_parse_hdline(snx_http_req_t *r, snx_iobuf_t *b);
void   snx_http_note_hdr(snx_http_req_t *r, snx_str_t *k, snx_str_t *v);
int    snx_http_headers_done(snx_http_req_t *r);
int    snx_http_find_loc(snx_http_req_t *r);
int    snx_http_find_named(snx_http_req_t *r, snx_str_t *name);
int    snx_http_map_path(snx_http_req_t *r, snx_str_t *path);
int    snx_http_unescape_uri(snx_http_req_t *r);
int    snx_http_static(snx_http_req_t *r);
void   snx_http_error_page(snx_http_req_t *r, int status);
int    snx_http_send_head(snx_http_req_t *r);
int    snx_http_write(snx_http_req_t *r, snx_iobuf_t *in);
int    snx_http_body_stage(snx_http_req_t *r, snx_iobuf_t *in);
int    snx_http_read_body(snx_http_req_t *r, snx_step_t cont);
void   snx_http_body_handler(snx_ev_t *ev);
void   snx_http_discard_body(snx_http_req_t *r);
int    snx_http_keepalive(snx_http_req_t *r);
void   snx_http_internal_redirect(snx_http_req_t *r, snx_str_t *uri);

snx_srv_t *snx_srv_match(snx_http_req_t *r, snx_str_t *host);
int   snx_name_match(snx_str_t *name, uchar *host, size_t hlen);
int        snx_http_init_conf(snx_arena_t *a, snx_node_t *http);

/* script/vars */
int       snx_var_find(snx_http_req_t *r, snx_str_t *name);
snx_str_t snx_var_get(snx_http_req_t *r, int idx);
void      snx_var_set(snx_http_req_t *r, int idx, snx_str_t *v);
int       snx_var_builtin(snx_http_req_t *r, snx_str_t *name, snx_str_t *out);
int       snx_complex_eval(snx_http_req_t *r, snx_str_t *tmpl, uchar *buf);
size_t    snx_complex_len(snx_http_req_t *r, snx_str_t *tmpl);
snx_str_t snx_var_lookup_pub(snx_http_req_t *r, snx_str_t *name);

/* filters (stages) */
int           snx_f_charset_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_charset_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_ssi_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_ssi_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_slice_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_slice_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_range_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_range_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_send_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_send_body(snx_http_req_t *r, snx_iobuf_t *in);

/* modules */
int  snx_mod_rewrite_step(snx_http_req_t *r);
void snx_mod_rewrite_loc(snx_loc_t *loc, snx_node_t *conf);
int  snx_mod_map_vars(snx_http_req_t *r, snx_node_t *conf);
int  snx_mod_dav(snx_http_req_t *r);
int  snx_mod_mp4(snx_http_req_t *r);
int  snx_mod_proxy(snx_http_req_t *r);
int  snx_mod_scgi(snx_http_req_t *r);
int  snx_mod_grpc(snx_http_req_t *r);
int  snx_mod_aio_sendfile(snx_http_req_t *r, snx_iobuf_t *b);
int  snx_grpc_pack(snx_http_req_t *r, snx_iobuf_t *in);

/* content handlers (mod_index) */
int  snx_mod_empty_gif(snx_http_req_t *r);
int  snx_mod_stub_status(snx_http_req_t *r);
int  snx_mod_autoindex(snx_http_req_t *r, snx_str_t *path);
int  snx_mod_flv(snx_http_req_t *r, snx_str_t *path, int fd,
                 struct stat *st);
int  snx_mod_random_index(snx_http_req_t *r, snx_str_t *path);
int  snx_mod_return(snx_http_req_t *r);
int  snx_mod_return_node(snx_http_req_t *r, snx_node_t *d);
int  snx_http_redirect(snx_http_req_t *r, snx_str_t *loc, int status);
int  snx_try_files(snx_http_req_t *r);
int  snx_try_index(snx_http_req_t *r);

/* access modules */
int  snx_mod_access(snx_http_req_t *r);      /* allow/deny + satisfy */
int  snx_mod_auth_basic(snx_http_req_t *r);  /* auth_basic */
int  snx_mod_auth_request(snx_http_req_t *r);/* auth_request */
int  snx_mod_referer(snx_http_req_t *r);     /* valid_referers */
int  snx_mod_realip(snx_http_req_t *r);      /* real_ip_from */
int  snx_mod_limit_conn(snx_http_req_t *r);
int  snx_mod_limit_req(snx_http_req_t *r);
void snx_limit_conn_done(snx_http_req_t *r);

/* filters */
int           snx_f_sub_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_sub_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_gzip_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_gzip_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_gunzip_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_gunzip_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_image_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_image_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_f_xslt_head(snx_http_req_t *r);
snx_iobuf_t  *snx_f_xslt_body(snx_http_req_t *r, snx_iobuf_t *in);
int           snx_gzip_static_ok(snx_http_req_t *r);
int           snx_body_needs_mem(snx_http_req_t *r);

/* upstreams */
typedef struct snx_peer_s {
    snx_str_t   addr;      /* host[:port] */
    int         port;
    int         weight;
    int         down;
    int         backup;
    int         max_fails;
    int         fails;
    int         conns;
    int         eff_w;
    long        rt;        /* cumulative first-byte ms */
    int         rt_n;
} snx_peer_t;

typedef struct snx_upstream_s {
    snx_str_t   name;
    int         method;    /* SNX_UP_* */
    snx_str_t   hash_var;
    snx_peer_t *peers;
    int         npeers;
    int         rr;
    int         keepalive; /* idle conn cache size */
    int         queue_max; /* per-peer busy limit before queueing */
    long        queue_ms;  /* max wait in queue */
    snx_str_t   sticky;    /* sticky cookie name, empty=off */
    struct snx_upstream_s *next;
} snx_upstream_t;

snx_upstream_t *snx_upstream_find(snx_str_t *name);
snx_peer_t     *snx_upstream_pick(snx_http_req_t *r, snx_upstream_t *u);
void            snx_upstream_done(snx_http_req_t *r, snx_peer_t *p, int ok);
int  snx_upstreams_init(snx_arena_t *a, snx_node_t *http);
int  snx_zones_init(snx_arena_t *a, snx_node_t *http);
int  snx_mod_fastcgi(snx_http_req_t *r);
int  snx_mod_uwsgi(snx_http_req_t *r);
int  snx_mod_memcached(snx_http_req_t *r);
int  snx_proxy_fetch(snx_http_req_t *r, const char *host, int port,
                     snx_str_t *out);
int  snx_mod_mirror(snx_http_req_t *r);      /* mirror replay hook */

/* proxy_cache */
int  snx_cache_init(snx_arena_t *a, snx_node_t *http);
int  snx_mod_cache_lookup(snx_http_req_t *r);   /* called before proxy */
int  snx_mod_cache_stale(snx_http_req_t *r);    /* serve stale on error */
int  snx_mod_auth_jwt(snx_http_req_t *r);       /* auth_jwt check */
int  snx_mod_cache_store(snx_http_req_t *r);    /* called after upstream */
int  snx_cache_save(snx_http_req_t *r, int status, snx_str_t *ctype,
                    uchar *body, size_t blen);

/* log formats / access log */
int  snx_access_log_init(snx_arena_t *a, snx_node_t *http);
void snx_access_log(snx_http_req_t *r);
int  snx_mod_geo(snx_http_req_t *r, snx_node_t *http);
int  snx_mod_split_clients(snx_http_req_t *r, snx_node_t *http);
int  snx_mod_userid(snx_http_req_t *r);
int  snx_mod_secure_link(snx_http_req_t *r);

/* misc vars */
int  snx_cidr_match(struct sockaddr *sa, const char *cidr);
int  snx_mime_init(snx_arena_t *a, snx_node_t *http);
snx_str_t snx_mime_type(snx_http_req_t *r);
void snx_add_hdr(snx_http_req_t *r, const char *k, snx_str_t *v);

/* resolver */
typedef struct snx_resolver_s {
    snx_arena_t   *arena;
    void          *evt;
} snx_resolver_t;

int snx_resolve(snx_resolver_t *rz, snx_str_t *name, void *ctx,
                void (*done)(void *, snx_str_t *));

/* mail / stream / proto / tls — compile-gated entry points */
void snx_mail_conf(snx_node_t *mail, snx_arena_t *a);
int  snx_stream_conf(snx_node_t *stream, snx_arena_t *a);
void snx_h2_conn(snx_conn_t *c);
void snx_spdy_conn(snx_conn_t *c);
void snx_h3_conn(snx_conn_t *c);

/* HPACK (RFC 7541) */
typedef struct snx_hpack_ent_s {
    uchar                    *name, *value;
    size_t                    name_len, value_len, size;
    struct snx_hpack_ent_s   *next;
} snx_hpack_ent_t;
typedef struct {
    snx_hpack_ent_t *dyntab;
    size_t           dyn_size, dyn_cap;
    snx_arena_t     *arena;
} snx_hpack_t;
void snx_hpack_init(snx_hpack_t *hp, snx_arena_t *a, size_t cap);
int  snx_hpack_decode(snx_hpack_t *hp, uchar *p, uchar *end,
                      int (*cb)(const uchar *nm, size_t nl,
                                const uchar *vv, size_t vl, void *arg),
                      void *arg);
void snx_mail_conn(snx_conn_t *c);
void snx_mail_proto_conn(snx_conn_t *c);
void snx_stream_conn(snx_conn_t *c);
void snx_stream_udp_conn(snx_conn_t *c);
int  snx_mail_listens(snx_node_t *mail, snx_listen_t **out, int *nout);
int  snx_stream_listens(snx_node_t *st, snx_listen_t **out, int *nout);
void *snx_tls_setup(snx_node_t *conf);
void *snx_tls_ssl_ctx(void *ctx);
int  snx_tls_accept(snx_conn_t *c);
void snx_tls_conn_start(snx_conn_t *c);
int  snx_tls_read(snx_conn_t *c, void *buf, int n);
int  snx_tls_write(snx_conn_t *c, const void *buf, int n);
void snx_tls_conn_free(snx_conn_t *c);

#endif /* SNX_H */
