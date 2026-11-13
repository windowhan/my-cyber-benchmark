/* unit harness: http-layer overread / NULL-deref paths */
#include <snx.h>

#include "../src/snx_http_body.c"

int  snx_http_parse_reqline(snx_http_req_t *r, snx_iobuf_t *b);

int
main(int argc, char **argv)
{
    const char *cve = argc > 1 ? argv[1] : "";

    if (strcmp(cve, "CVE-2009-2629") == 0) {
        /* request line starting at the buffer head: the leading-CRLF
           tolerance check reads *(p-1) before the buffer */
        snx_http_req_t   r;
        snx_conn_t       c;
        snx_iobuf_t      b;
        uchar           *base = malloc(64);
        static uchar     line[] = "\nGET / HTTP/1.1\r\n";

        memset(&r, 0, sizeof(r));
        memset(&c, 0, sizeof(c));
        memset(&b, 0, sizeof(b));
        r.c = &c;
        c.data = &r;
        r.log = &snx_stderr_log;
        r.arena = snx_arena_new(4096);
        b.base = base;
        b.cap = 64;
        b.head = base;
        b.tail = base + sizeof(line) - 1;
        memcpy(base, line, sizeof(line) - 1);
        r.inbuf = &b;
        r.req_start = b.head;      /* parser state: at buffer head */

        (void) snx_http_parse_reqline(&r, &b);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2016-4450") == 0) {
        /* keep-alive drain of an unread body touches tf->fd on a
           NULL body tempfile */
        snx_http_req_t   r;
        snx_conn_t       c;
        snx_iobuf_t      b;
        uchar            buf[64];

        memset(&r, 0, sizeof(r));
        memset(&c, 0, sizeof(c));
        memset(&b, 0, sizeof(b));
        c.fd = -1;
        r.c = &c;
        r.inbuf = &b;
        b.base = buf;
        b.head = buf;
        b.tail = buf;
        b.cap = sizeof(buf);
        r.body_tf = NULL;

        snx_http_discard_body(&r);
        printf("no crash\n");

    } else {
        fprintf(stderr, "unknown\n");
        return 2;
    }
    return 0;
}
