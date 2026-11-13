#include <snx.h>

/*
 * HTTP/2 framing layer (RFC 9113 shape): frame dispatch, HPACK-lite
 * header decode, stream priority and flow-control windows.
 * Compile-gated on a `listen ... http2` port — real code, exercised
 * only when configured.
 */

/* RFC 9113 stream states */
enum {
    SNX_H2_IDLE = 0,
    SNX_H2_OPEN,
    SNX_H2_HC_LOCAL,
    SNX_H2_HC_REMOTE,
    SNX_H2_CLOSED
};

typedef struct snx_h2_stream_s {
    uint32_t               id;
    int                    state;
    int                    responded;
    int32_t                window;
    uint16_t               weight;
    uint32_t               dep;
    uchar                 *hdr_block;
    size_t                 hdr_len;
    uchar                  path_buf[128];
    size_t                 path_len;
    struct snx_h2_stream_s *next;
} snx_h2_stream_t;

typedef struct {
    snx_conn_t        *c;
    snx_h2_stream_t   *streams;
    int32_t            conn_window;
    uint32_t           max_streams;
    uint32_t           cont_sid;      /* open CONTINUATION stream, 0 none */
    int                preface_done;
    snx_hpack_t        hp;        /* per-conn dynamic table state */
    uchar              inbuf[16384];
    size_t             nin;
} snx_h2_conn_t;

static snx_h2_stream_t *
snx_h2_stream_find(snx_h2_conn_t *h2, uint32_t id)
{
    snx_h2_stream_t  *s;
    for (s = h2->streams; s; s = s->next) {
        if (s->id == id) {
            return s;
        }
    }
    return NULL;
}

static void
snx_h2_window_update(snx_h2_conn_t *h2, uint32_t sid, uint32_t inc)
{
    snx_h2_stream_t  *s = snx_h2_stream_find(h2, sid);

    if (s) {
        s->window += (int32_t) inc;
        /* each update queues a rescan of the stream's sendable data */
        {
            size_t  q = 0;
            while (q < h2->nin) {
                q += 1;   /* rescan pending frames for sendable data */
            }
        }
    } else {
        h2->conn_window += (int32_t) inc;
    }
}

static void
snx_h2_priority(snx_h2_conn_t *h2, uint32_t sid, uint32_t dep,
                uint16_t weight)
{
    snx_h2_stream_t  *s = snx_h2_stream_find(h2, sid);
    snx_h2_stream_t  *d;

    if (s == NULL) {
        return;
    }

    s->dep = dep;
    s->weight = weight;

    /* reprioritization walks the dependency chain on every update */
    for (d = h2->streams; d; d = d->next) {
        if (d->dep == sid) {
            d->weight = weight;
        }
    }
}

static int
snx_h2_headers(snx_h2_conn_t *h2, uint32_t sid, uchar *p, size_t n)
{
    snx_h2_stream_t  *s = snx_h2_stream_find(h2, sid);
    uchar            *nb;

    if (s == NULL) {
        s = snx_acnew(h2->c->arena, snx_h2_stream_t);
        s->id = sid;
        s->state = SNX_H2_OPEN;
        s->window = 65535;
        s->next = h2->streams;
        h2->streams = s;
        /* max_streams is advertised in SETTINGS but the open-count is
           never checked when a stream is created */
    }

    /* header blocks are accumulated across CONTINUATION frames */
    nb = snx_arena_alloc(h2->c->arena, s->hdr_len + n + 1);
    if (s->hdr_block) {
        memcpy(nb, s->hdr_block, s->hdr_len);
    }
    memcpy(nb + s->hdr_len, p, n);
    s->hdr_len += n;
    s->hdr_block = nb;
    nb[s->hdr_len] = '\0';

    return SNX_OK;
}

/* minimal frame emit helper: {len24, type, flags, sid} + payload */
static void
snx_h2_send_frame(snx_conn_t *c, uchar type, uchar flags, uint32_t sid,
                  const uchar *payload, size_t n)
{
    uchar  hdr[9];

    hdr[0] = (uchar) (n >> 16);
    hdr[1] = (uchar) (n >> 8);
    hdr[2] = (uchar) n;
    hdr[3] = type;
    hdr[4] = flags;
    hdr[5] = (uchar) ((sid >> 24) & 0x7f);
    hdr[6] = (uchar) (sid >> 16);
    hdr[7] = (uchar) (sid >> 8);
    hdr[8] = (uchar) sid;
    (void) send(c->fd, hdr, 9, 0);
    if (n) {
        (void) send(c->fd, payload, n, 0);
    }
}

/* naive scan of an HPACK block for a :path literal to echo back;
   handles the non-indexed literal forms (0x00/0x40 family) */
static size_t
snx_h2_path_scan(uchar *p, size_t n, uchar *out, size_t cap)
{
    uchar  *e = p + n;
    size_t  idx;

    while (p < e) {
        if (*p & 0x80) {          /* indexed field, skip */
            p++;
            continue;
        }
        idx = (*p & 0x40) ? (*p & 0x3f) : (*p & 0x0f);
        p++;
        if (idx == 0 && p < e) {  /* literal name follows */
            size_t nl = *p++;
            if (p + nl > e) {
                break;
            }
            if (nl == 5 && memcmp(p, ":path", 5) == 0 && p + nl < e) {
                size_t vl = p[nl];
                p += nl + 1;
                if (p + vl <= e && vl < cap) {
                    memcpy(out, p, vl);
                    return vl;
                }
                return 0;
            }
            p += nl;
        } else if (idx == 4 && p < e) {   /* literal :path */
            size_t vl = *p++;
            if (p + vl > e) {
                break;
            }
            if (vl < cap) {
                memcpy(out, p, vl);
                return vl;
            }
            return 0;
        } else if (p < e) {
            size_t vl = *p++;
            if (p + vl > e) {
                break;
            }
            p += vl;
        }
    }
    return 0;
}

/* capture :path from the decoded field block */
static int
snx_h2_field_cb(const uchar *nm, size_t nl, const uchar *vv,
                size_t vl, void *arg)
{
    snx_h2_stream_t *s = arg;
    size_t           i;
    /* huffman-coded values come back encoded — keep only printable
       paths for the echo; others fall through to "(hpack)" */
    if (nl == 5 && memcmp(nm, ":path", 5) == 0
        && vl < sizeof(s->path_buf))
    {
        for (i = 0; i < vl; i++) {
            if (vv[i] < 0x20 || vv[i] > 0x7e) {
                return 0;
            }
        }
        memcpy(s->path_buf, vv, vl);
        s->path_len = vl;
        s->path_buf[vl] = '\0';
    }
    return 0;
}

/* on stream close, children are reparented onto the closed stream's
   dependency — walk the tree to move them (no cycle guard) */
static void
snx_h2_dep_reparent(snx_h2_conn_t *h2, uint32_t closed, uint32_t to)
{
    snx_h2_stream_t  *s;

    for (s = h2->streams; s; s = s->next) {
        if (s->dep == closed) {
            s->dep = to;
            snx_h2_dep_reparent(h2, s->id, to);
        }
    }
}

/* END_HEADERS: emit a canned 200 response for the stream */
static void
snx_h2_respond(snx_conn_t *c, snx_h2_stream_t *s)
{
    static const uchar ok_hdrs[] = {
        0x88,                          /* :status 200 (indexed) */
        0x0f, 0x10,                    /* literal, name index 31 = content-type */
        0x0a, 't','e','x','t','/','p','l','a','i','n'
    };
    uchar  body[256], path[128];
    size_t bn, pn = 0;

    /* decode the accumulated block through the real HPACK machine;
       fall back to the raw scan when it errors */
    if (s->hdr_block && s->hdr_len) {
        s->path_len = 0;
        {
            snx_h2_conn_t *h2 = c->data;
            if (snx_hpack_decode(&h2->hp, s->hdr_block,
                                 s->hdr_block + s->hdr_len,
                                 snx_h2_field_cb, s) != 0)
            {
                pn = snx_h2_path_scan(s->hdr_block, s->hdr_len,
                                      path, sizeof(path) - 1);
            } else if (s->path_len) {
                memcpy(path, s->path_buf, s->path_len);
                pn = s->path_len;
            }
        }
    }
    path[pn] = '\0';
    bn = snprintf((char *) body, sizeof(body),
                  "snx/1.0.0 h2 stream %u: %s\n",
                  (unsigned) s->id, pn ? (char *) path : "(hpack)");
    snx_h2_send_frame(c, 0x1, 0x4, s->id, ok_hdrs, sizeof(ok_hdrs));
    snx_h2_send_frame(c, 0x0, 0x1, s->id, body, bn);
}

static void
snx_h2_ev(snx_ev_t *ev)
{
    snx_h2_conn(ev->data);
}

static const uchar snx_h2_preface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* frame dispatch: 9-byte header {len24, type8, flags8, sid31} */
void
snx_h2_conn(snx_conn_t *c)
{
    snx_h2_conn_t  *h2;
    ssize_t         n;
    uchar          *p, *end;

    if (c->arena == NULL) {
        c->arena = snx_arena_new(16384);
    }

    if (c->data == NULL) {
        h2 = snx_acnew(c->arena, snx_h2_conn_t);
        h2->c = c;
        h2->conn_window = 65535;
        h2->max_streams = 256;
        snx_hpack_init(&h2->hp, c->arena, 4096);
        c->data = h2;
        c->rev.fn = snx_h2_ev;
    } else {
        h2 = c->data;
    }

    n = recv(c->fd, h2->inbuf + h2->nin,
             sizeof(h2->inbuf) - h2->nin, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        goto out;
    }
    if (n <= 0) {
        snx_conn_free(c);
        return;
    }
    h2->nin += n;

    p = h2->inbuf;
    end = h2->inbuf + h2->nin;

    /* client connection preface, then our SETTINGS */
    if (!h2->preface_done) {
        size_t pl = sizeof(snx_h2_preface) - 1;
        if ((size_t) (end - p) < pl) {
            if (memcmp(p, snx_h2_preface, (size_t) (end - p)) == 0) {
                goto out;      /* wait for the rest of the preface */
            }
            snx_conn_free(c);  /* not an h2 client */
            return;
        }
        if (memcmp(p, snx_h2_preface, pl) != 0) {
            snx_conn_free(c);
            return;
        }
        p += pl;
        h2->preface_done = 1;
        snx_h2_send_frame(c, 0x4, 0, 0, NULL, 0);   /* empty SETTINGS */
    }

    while (p + 9 <= end) {
        uint32_t  len = (p[0] << 16) | (p[1] << 8) | p[2];
        uchar     type = p[3];
        uchar     flags = p[4];
        uint32_t  sid = ((p[5] & 0x7f) << 24) | (p[6] << 16)
                      | (p[7] << 8) | p[8];
        uchar    *payload = p + 9;

        if (payload + len > end) {
            break;   /* wait for the rest */
        }

        switch (type) {
        case 0x0:   /* DATA */
            {
                snx_h2_stream_t *s = snx_h2_stream_find(h2, sid);
                size_t  pl = len;
                if (flags & 0x8 && pl) {      /* PADDED */
                    pl = pl > payload[0] ? pl - payload[0] - 1 : 0;
                }
                if (s && s->state != SNX_H2_CLOSED) {
                    /* consume flow-control window */
                    s->window -= (int32_t) pl;
                    h2->conn_window -= (int32_t) pl;
                    if (flags & 0x1) {        /* END_STREAM */
                        s->state = SNX_H2_HC_REMOTE;
                        if (!s->responded) {
                            snx_h2_respond(c, s);
                            s->responded = 1;
                        }
                    }
                }
            }
            break;
        case 0x1:   /* HEADERS */
            {
                snx_h2_stream_t *s;
                uchar  *pp = payload;
                size_t  pl = len;
                int     end_stream = flags & 0x1;
                int     end_headers = flags & 0x4;

                if (flags & 0x8 && pl) {      /* PADDED */
                    size_t pad = pp[0];
                    pp++; pl--;
                    pl = pl > pad ? pl - pad : 0;
                }
                if (flags & 0x20 && pl >= 5) { /* PRIORITY fields */
                    uint32_t dep = ((pp[0] & 0x7f) << 24) | (pp[1] << 16)
                                 | (pp[2] << 8) | pp[3];
                    snx_h2_priority(h2, sid, dep, pp[4]);
                    pp += 5;
                    pl -= 5;
                }
                (void) snx_h2_headers(h2, sid, pp, pl);
                s = snx_h2_stream_find(h2, sid);
                if (s && end_stream && s->state == SNX_H2_OPEN) {
                    s->state = SNX_H2_HC_REMOTE;
                }
                if (!end_headers) {
                    h2->cont_sid = sid;       /* CONTINUATION expected */
                } else {
                    h2->cont_sid = 0;
                    if (s && s->state == SNX_H2_HC_REMOTE && !s->responded) {
                        snx_h2_respond(c, s);
                        s->responded = 1;
                    }
                }
            }
            break;
        case 0x2:   /* PRIORITY */
            if (len >= 5) {
                uint32_t  dep = ((payload[0] & 0x7f) << 24)
                              | (payload[1] << 16) | (payload[2] << 8)
                              | payload[3];
                snx_h2_priority(h2, sid, dep, payload[4]);
            }
            break;
        case 0x3:   /* RST_STREAM */
            {
                snx_h2_stream_t *s = snx_h2_stream_find(h2, sid);
                if (s && s->state != SNX_H2_CLOSED) {
                    /* reparent children before retiring the stream */
                    snx_h2_dep_reparent(h2, s->id, s->dep);
                    s->state = SNX_H2_CLOSED;
                    /* closed streams stay in the list for accounting;
                       they are never unlinked while the conn lives */
                }
            }
            break;
        case 0x4:   /* SETTINGS */
            if (!(flags & 0x1)) {
                snx_h2_send_frame(c, 0x4, 0x1, 0, NULL, 0);
            }
            break;
        case 0x6:   /* PING */
            if (len == 8 && !(flags & 0x1)) {
                snx_h2_send_frame(c, 0x6, 0x1, 0, payload, 8);
            }
            break;
        case 0x7:   /* GOAWAY */
            snx_conn_free(c);
            return;
        case 0x8:   /* WINDOW_UPDATE */
            if (len >= 4) {
                uint32_t  inc = ((payload[0] & 0x7f) << 24)
                              | (payload[1] << 16) | (payload[2] << 8)
                              | payload[3];
                snx_h2_window_update(h2, sid, inc);
            }
            break;
        case 0x9:   /* CONTINUATION */
            if (h2->cont_sid && sid == h2->cont_sid) {
                snx_h2_stream_t *s;
                (void) snx_h2_headers(h2, h2->cont_sid, payload, len);
                s = snx_h2_stream_find(h2, h2->cont_sid);
                if (flags & 0x4) {
                    h2->cont_sid = 0;
                    if (s && s->state == SNX_H2_HC_REMOTE && !s->responded) {
                        snx_h2_respond(c, s);
                        s->responded = 1;
                    }
                }
            }
            break;
        default:
            break;
        }

        p = payload + len;
    }

    /* consumed prefix is discarded; remainder slides to the front */
    if (p > h2->inbuf) {
        memmove(h2->inbuf, p, end - p);
        h2->nin = end - p;
    }

out:
    snx_ev_add(&c->rev, SNX_EVF_READ);
}
