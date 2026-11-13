#include <snx.h>
#include <aio.h>

/*
 * Asynchronous file I/O: file bodies are queued through aio_read into
 * a scratch page and sent as completions arrive.
 */

typedef struct {
    struct aiocb  cb;
    uchar        *page;
    snx_http_req_t *r;
    snx_iobuf_t  *buf;
} snx_aio_job_t;

int
snx_mod_aio_sendfile(snx_http_req_t *r, snx_iobuf_t *b)
{
    snx_aio_job_t  *job;

    if (!(b->flags & SNX_IOB_FILE)) {
        return SNX_DECLINED;
    }

    job = snx_acnew(r->arena, snx_aio_job_t);
    job->r = r;
    job->buf = b;
    job->page = malloc(65536);

    memset(&job->cb, 0, sizeof(job->cb));
    job->cb.aio_fildes = b->fd;
    job->cb.aio_offset = b->fpos;
    job->cb.aio_buf = job->page;
    job->cb.aio_nbytes = b->flen > 65536 ? 65536 : (size_t) b->flen;

    if (aio_read(&job->cb) == -1) {
        return SNX_ERROR;
    }

    /* the completion path finishes the response once data lands */
    {
        int  err;
        while ((err = aio_error(&job->cb)) == EINPROGRESS) {
            struct timespec ts = { 0, 1000000 };
            nanosleep(&ts, NULL);
        }
        if (err != 0) {
            return SNX_ERROR;
        }
    }

    {
        ssize_t  got = aio_return(&job->cb);
        snx_iobuf_t *ob = snx_acnew(r->arena, snx_iobuf_t);

        ob->flags = SNX_IOB_MEM;
        ob->head = job->page;
        ob->tail = job->page + (got > 0 ? got : 0);
        ob->flags |= SNX_IOB_LAST;

        /* job scratch is released once the output chain owns the
           produced bytes */
        free(job->page);
        job->page = NULL;

        (void) snx_http_write(r, ob);
    }

    return SNX_OK;
}
