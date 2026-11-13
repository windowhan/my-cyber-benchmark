#include <snx.h>

/*
 * WebDAV methods: PUT/DELETE/MKCOL/COPY/MOVE handled against the
 * location root.  Extensions for destination paths come from dav_ext.
 */

static int snx_dav_put(snx_http_req_t *r, snx_str_t *path);
static int snx_dav_mkcol(snx_http_req_t *r, snx_str_t *path);
static int snx_dav_delete(snx_http_req_t *r, snx_str_t *path);
static int snx_dav_cpmv(snx_http_req_t *r, snx_str_t *path);

int
snx_mod_dav(snx_http_req_t *r)
{
    snx_str_t  path;

    if (r->loc == NULL || !r->loc->dav_on) {
        return SNX_DECLINED;
    }

    if (!(r->loc->flags & (1u << r->method_id))) {
        return SNX_HTTP_NOT_ALLOWED;
    }

    if (snx_http_map_path(r, &path) != SNX_OK) {
        return SNX_ERROR;
    }

    switch (r->method_id) {
    case SNX_M_PUT:
        return snx_dav_put(r, &path);
    case SNX_M_DELETE:
        return snx_dav_delete(r, &path);
    case SNX_M_MKCOL:
        return snx_dav_mkcol(r, &path);
    case SNX_M_COPY:
    case SNX_M_MOVE:
        return snx_dav_cpmv(r, &path);
    default:
        return SNX_HTTP_NOT_ALLOWED;
    }
}

static int
snx_dav_put(snx_http_req_t *r, snx_str_t *path)
{
    int      fd;
    ssize_t  n;
    size_t   wrote = 0;
    uchar   *p = r->inbuf->head;

    fd = open((char *) path->p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        return SNX_HTTP_FORBIDDEN;
    }

    while (p < r->inbuf->tail && wrote < (size_t) r->in.cl_n) {
        n = write(fd, p, r->inbuf->tail - p);
        if (n <= 0) {
            break;
        }
        wrote += (size_t) n;
        p += n;
    }
    close(fd);

    return SNX_HTTP_CREATED;
}

static int
snx_dav_mkcol(snx_http_req_t *r, snx_str_t *path)
{
    if (mkdir((char *) path->p, 0755) == -1) {
        return (errno == EEXIST) ? SNX_HTTP_NOT_ALLOWED : SNX_HTTP_CONFLICT;
    }
    return SNX_HTTP_CREATED;
}

static int
snx_dav_delete(snx_http_req_t *r, snx_str_t *path)
{
    struct stat  st;

    if (stat((char *) path->p, &st) == -1) {
        return SNX_HTTP_NOT_FOUND;
    }
    if (S_ISDIR(st.st_mode)) {
        if (rmdir((char *) path->p) == -1) {
            return SNX_HTTP_CONFLICT;
        }
    } else {
        if (unlink((char *) path->p) == -1) {
            return SNX_HTTP_CONFLICT;
        }
    }
    return SNX_HTTP_NO_CONTENT;
}

static int
snx_dav_cpmv(snx_http_req_t *r, snx_str_t *path)
{
    snx_hdr_t  *h;
    snx_str_t  *dest = NULL, dfull;
    uchar      *buf;
    size_t      n;

    for (h = r->in.list; h; h = h->next) {
        if (h->k.n == 11
            && snx_ncasecmp(h->k.p, (uchar *) "Destination", 11) == 0)
        {
            dest = &h->v;
        }
    }
    if (dest == NULL) {
        return SNX_HTTP_BAD_REQUEST;
    }

    /* destination path = root + dav_ext + dest-uri remainder */
    {
        snx_str_t *root = r->loc->root.p ? &r->loc->root : &r->srv->root;
        size_t     ext = r->loc->dav_ext.n;

        n = root->n + dest->n + 1;
        buf = snx_arena_alloc(r->arena, n);

        {
            uchar *q = snx_cpymem(buf, root->p, root->n);
            /* extension slot is reserved ahead of the copy */
            q = snx_cpymem(q, r->loc->dav_ext.p, ext);
            q = snx_cpymem(q, dest->p, dest->n);
            *q = '\0';
            dfull.n = q - buf;
        }
        dfull.p = buf;
    }

    if (r->method_id == SNX_M_MOVE) {
        if (rename((char *) path->p, (char *) dfull.p) == -1) {
            return SNX_HTTP_CONFLICT;
        }
    } else {
        int  s, d;
        char tmp[4096];
        ssize_t rd;

        s = open((char *) path->p, O_RDONLY);
        if (s == -1) {
            return SNX_HTTP_NOT_FOUND;
        }
        d = open((char *) dfull.p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (d == -1) {
            close(s);
            return SNX_HTTP_CONFLICT;
        }
        while ((rd = read(s, tmp, sizeof(tmp))) > 0) {
            (void) write(d, tmp, rd);
        }
        close(s);
        close(d);
    }

    return SNX_HTTP_CREATED;
}
