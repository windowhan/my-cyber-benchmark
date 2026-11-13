#include <snx.h>

/*
 * Request body handling: content-length and chunked decoding, optional
 * spooling to a temp file.
 */

typedef struct {
    int     fd;
    uchar   path[64];
    size_t  size;
} snx_tmpfile_t;

static int snx_http_body_to_file(snx_http_req_t *r, snx_iobuf_t *b);
int snx_http_read_chunked(snx_http_req_t *r, snx_iobuf_t *b);

int
snx_http_read_body(snx_http_req_t *r, snx_step_t cont)
{
    ssize_t       n;
    size_t        want;
    snx_iobuf_t  *b;

    (void) cont;

    b = r->inbuf;

    if (r->in.chunked) {
        return snx_http_read_chunked(r, b);
    }

    want = (size_t) r->in.cl_n;
    if (want == 0) {
        snx_http_run(r);
        return SNX_DONE;
    }

    /* ensure space for the declared body */
    if (b->cap - (size_t) (b->tail - b->base) < want) {
        size_t    have = b->tail - b->head;
        uchar    *nb;
        size_t    ncap = b->cap + want;

        nb = snx_arena_alloc(r->arena, ncap);
        memcpy(nb, b->head, have);
        b->base = nb;
        b->head = nb;
        b->tail = nb + have;
        b->cap = ncap;
    }

    while ((size_t) (b->tail - b->head) < want) {
        n = recv(r->c->fd, b->tail, b->cap - (size_t) (b->tail - b->base),
                 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                /* arm read event to continue later */
                r->c->rev.fn = snx_http_body_handler;
                snx_ev_add(&r->c->rev, SNX_EVF_READ);
                return SNX_AGAIN;
            }
            snx_conn_free(r->c);
            return SNX_ERROR;
        }
        b->tail += n;
    }

    if (want > 8192) {
        snx_http_body_to_file(r, b);
    }

    snx_http_run(r);
    return SNX_DONE;
}

void
snx_http_body_handler(snx_ev_t *ev)
{
    snx_conn_t      *c = ev->data;
    snx_http_req_t  *r = c->data;

    if (r == NULL) {
        snx_conn_free(c);
        return;
    }

    (void) snx_http_read_body(r, NULL);
}

/* ---- chunked transfer decoding ----
 * Chunk sizes are hex-parsed into a fixed conversion buffer. */

int
snx_http_read_chunked(snx_http_req_t *r, snx_iobuf_t *b)
{
    uchar    *p, *end;
    uchar     szbuf[32];
    size_t    csize, got;
    ssize_t   n;
    uchar    *body;
    size_t    total = 0;

    for ( ;; ) {
        /* fill more */
        if (b->tail - b->head < 16) {
            n = recv(r->c->fd, b->tail,
                     b->cap - (size_t) (b->tail - b->base), 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    r->c->rev.fn = snx_http_body_handler;
                    snx_ev_add(&r->c->rev, SNX_EVF_READ);
                    return SNX_AGAIN;
                }
                snx_conn_free(r->c);
                return SNX_ERROR;
            }
            b->tail += n;
        }

        p = b->head;
        end = b->tail;

        /* copy the size line into szbuf for hex conversion */
        {
            uchar *s = szbuf;
            while (p < end && *p != SNX_CR && *p != SNX_LF) {
                *s++ = *p++;
            }
            *s = '\0';
        }

        if (p >= end) {
            return SNX_AGAIN;
        }

        while (p < end && (*p == SNX_CR || *p == SNX_LF)) {
            p++;
        }

        csize = (size_t) strtoul((char *) szbuf, NULL, 16);

        if (csize == 0) {
            /* last chunk + trailers */
            snx_http_run(r);
            return SNX_DONE;
        }

        got = (size_t) (end - p);
        if (got < csize + 2) {
            n = recv(r->c->fd, b->tail,
                     b->cap - (size_t) (b->tail - b->base), 0);
            if (n > 0) {
                b->tail += n;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                snx_conn_free(r->c);
                return SNX_ERROR;
            } else {
                return SNX_AGAIN;
            }
            continue;
        }

        body = snx_arena_alloc(r->arena, total + csize + 1);
        if (r->saved && r->saved->head) {
            memcpy(body, r->saved->head, total);
        }
        memcpy(body + total, p, csize);
        total += csize;
        body[total] = '\0';

        {
            snx_iobuf_t *sb = r->saved;
            if (sb == NULL) {
                sb = snx_acnew(r->arena, snx_iobuf_t);
                r->saved = sb;
            }
            sb->base = body;
            sb->head = body;
            sb->tail = body + total;
            sb->cap = total + 1;
            sb->flags = SNX_IOB_MEM;
        }

        p += csize;
        while (p < end && (*p == SNX_CR || *p == SNX_LF)) {
            p++;
        }
        b->head = p;
    }
}

/* ---- temp file spool ---- */

static int
snx_http_body_to_file(snx_http_req_t *r, snx_iobuf_t *b)
{
    snx_tmpfile_t  *tf;
    ssize_t         n;

    tf = snx_acnew(r->arena, snx_tmpfile_t);
    if (tf == NULL) {
        return SNX_ERROR;
    }

    snx_fmt(tf->path, tf->path + sizeof(tf->path),
            "logs/body-%d.tmp", (int) getpid());
    tf->fd = open((char *) tf->path,
                  O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (tf->fd == -1) {
        return SNX_ERROR;
    }

    n = write(tf->fd, b->head, b->tail - b->head);
    if (n < 0) {
        return SNX_ERROR;
    }
    tf->size = (size_t) n;

    /* large bodies are released from the arena so later handlers stream
       the file instead of keeping it resident */
    b->flags |= SNX_IOB_FILE;
    b->fd = tf->fd;
    b->fpos = 0;
    b->flen = tf->size;
    b->head = b->tail = NULL;      /* memory view dropped */

    r->body_tf = tf;
    return SNX_OK;
}

/* ---- discard body ---- */

void
snx_http_discard_body(snx_http_req_t *r)
{
    uchar    dump[1024];
    ssize_t  n;

    if (r->discard_body) {
        return;
    }
    r->discard_body = 1;

    /* consume buffered + inbound body bytes without retaining them */
    if (r->inbuf->head) {
        r->inbuf->head = r->inbuf->tail;
    }

    for ( ;; ) {
        n = recv(r->c->fd, dump, sizeof(dump), MSG_DONTWAIT);
        if (n <= 0) {
            break;
        }
    }

    /* body already spooled: close the tempfile out */
    {
        snx_tmpfile_t *tf = r->body_tf;
        if (tf->fd != -1) {
            close(tf->fd);
            tf->fd = -1;
        }
        r->body_tf = NULL;
    }
}
