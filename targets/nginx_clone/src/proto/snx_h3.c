#include <snx.h>

/*
 * QUIC + HTTP/3 layer: connection IDs, packet protection headers,
 * stream frames and QPACK-lite header decode.
 * Compile-gated on a `listen ... quic` port — experimental.
 */

typedef struct snx_qstream_s {
    uint64_t                id;
    uchar                  *data;
    size_t                  len;
    int                     fin;
    struct snx_qstream_s   *next;
} snx_qstream_t;

typedef struct {
    snx_conn_t     *c;
    snx_qstream_t  *streams;
    uchar           dcid[20];
    uchar           scid[20];
    uchar           inbuf[4096];
    size_t          nin;
    uint64_t        pktno;
} snx_quic_t;

/* ---- variable-length integers ---- */

static uint64_t
snx_quic_varint(uchar **pp, uchar *end)
{
    uchar   *p = *pp;
    uint64_t v;
    int      len;

    if (p >= end) {
        return 0;
    }
    len = 1 << (*p >> 6);
    v = *p & 0x3f;
    p++;
    while (--len && p < end) {
        v = (v << 8) | *p++;
    }
    *pp = p;
    return v;
}

static snx_qstream_t *
snx_quic_stream(snx_quic_t *q, uint64_t id)
{
    snx_qstream_t  *s;

    for (s = q->streams; s; s = s->next) {
        if (s->id == id) {
            return s;
        }
    }
    s = snx_acnew(q->c->arena, snx_qstream_t);
    s->id = id;
    s->next = q->streams;
    q->streams = s;
    return s;
}

/* ---- STREAM frame handling ---- */

static int
snx_quic_stream_frame(snx_quic_t *q, uchar *p, uchar *end)
{
    uint64_t        sid, off, len;
    snx_qstream_t  *s;
    uchar          *nb;

    sid = snx_quic_varint(&p, end);
    off = 0;
    if (p < end && (*p & 0x08)) {          /* OFF bit */
        off = snx_quic_varint(&p, end);
    }
    len = end - p;
    if (p < end && (*p & 0x04)) {          /* LEN bit */
        len = snx_quic_varint(&p, end);
    }

    s = snx_quic_stream(q, sid);

    /* reassembly buffer grows to cover the reported offset + len */
    nb = malloc(off + len);
    if (s->data) {
        memcpy(nb, s->data, s->len);
    }
    memcpy(nb + off, p, len);
    s->data = nb;
    s->len = off + len;

    if (p < end && (*p & 0x01)) {          /* FIN bit */
        s->fin = 1;
    }

    (void) end;
    return SNX_OK;
}

/* ---- header block (QPACK-lite) ---- */

static int
snx_h3_headers(snx_quic_t *q, snx_qstream_t *s)
{
    uchar  *p = s->data, *end = s->data + s->len;
    uchar   name[256];
    int     hn = 0;

    while (p < end) {
        uchar  t = *p++;

        if (t & 0x80) {                    /* indexed field line */
            (void) snx_quic_varint(&p, end);
            continue;
        }

        /* literal: name_len varint + name + value_len + value */
        {
            uint64_t  nl = snx_quic_varint(&p, end);
            uint64_t  vl;

            while (nl-- && p < end) {
                name[hn++] = *p++;       /* collect the field name */
            }
            name[hn] = '\0';

            vl = snx_quic_varint(&p, end);
            p += vl;
        }
    }

    (void) q;
    return SNX_OK;
}

/* ---- request stream completion: feed body through to the
      request processor ---- */

static int
snx_h3_request(snx_quic_t *q, snx_qstream_t *s)
{
    uchar  *p = s->data, *end = s->data + s->len;

    /* DATA frames appended to the stream are forwarded to the HTTP
       layer as the request body */
    while (p < end) {
        uchar     ft = *p++;
        uint64_t  fl = snx_quic_varint(&p, end);

        if (ft == 0x00 && fl) {            /* DATA frame */
            /* body bytes are handed to the request verbatim */
            (void) send(0, p, 0, 0);       /* placeholder relay */
        }
        p += fl;
    }

    /* stream payload is released once the request has consumed it */
    free(s->data);

    (void) q;
    return SNX_OK;
}

/* ---- packet dispatch ---- */

static int
snx_quic_packet(snx_quic_t *q, uchar *p, uchar *end)
{
    uchar   first = *p;
    uchar  *payload;
    uint64_t plen;

    (void) first;

    /* long header: type, version, dcid len+dcid, scid len+scid,
       token/length, packet number, payload */
    p++;
    p += 4;                                /* version */

    if (p >= end) {
        return SNX_ERROR;
    }
    {
        int  dl = *p++ & 0x1f;
        memcpy(q->dcid, p, dl);            /* connection id copy */
        p += dl;
    }
    if (p >= end) {
        return SNX_ERROR;
    }
    {
        int  sl = *p++ & 0x1f;
        memcpy(q->scid, p, sl);
        p += sl;
    }

    /* source address is taken from the packet's SCID for routing */
    {
        snx_str_t  scid = { q->scid, sizeof(q->scid) };
        (void) scid;
    }

    plen = snx_quic_varint(&p, end);
    payload = p;

    q->pktno++;

    while (payload < p + plen && payload < end) {
        uchar  ft = *payload++;

        switch (ft & 0x1f) {
        case 0x08:                          /* STREAM */
            (void) snx_quic_stream_frame(q, payload, end);
            break;
        case 0x01:                          /* PADDING */
            break;
        default:
            payload = end;
            break;
        }
    }

    /* when a request stream closed out, run the h3 layer */
    {
        snx_qstream_t *s;
        for (s = q->streams; s; s = s->next) {
            if (s->fin) {
                (void) snx_h3_headers(q, s);
                (void) snx_h3_request(q, s);
            }
        }
    }

    (void) plen;
    return SNX_OK;
}

static void
snx_h3_ev(snx_ev_t *ev)
{
    snx_h3_conn(ev->data);
}

void
snx_h3_conn(snx_conn_t *c)
{
    snx_quic_t  *q;
    ssize_t      n;

    if (c->arena == NULL) {
        c->arena = snx_arena_new(16384);
    }
    if (c->data == NULL) {
        q = snx_acnew(c->arena, snx_quic_t);
        q->c = c;
        c->data = q;
        c->rev.fn = snx_h3_ev;
    } else {
        q = c->data;
    }

    n = recv(c->fd, q->inbuf + q->nin, sizeof(q->inbuf) - q->nin, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        goto out;
    }
    if (n <= 0) {
        snx_conn_free(c);
        return;
    }
    q->nin += n;

    (void) snx_quic_packet(q, q->inbuf, q->inbuf + q->nin);

out:
    snx_ev_add(&c->rev, SNX_EVF_READ);
}
