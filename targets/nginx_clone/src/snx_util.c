#include <snx.h>

#ifdef __has_feature
#if __has_feature(address_sanitizer)
#define SNX_ASAN 1
#endif
#endif
#ifdef __SANITIZE_ADDRESS__
#define SNX_ASAN 1
#endif
#if SNX_ASAN
#include <sanitizer/asan_interface.h>
#else
#define __asan_poison_memory_region(p, n)   do { (void) (p); (void) (n); } while (0)
#define __asan_unpoison_memory_region(p, n) do { (void) (p); (void) (n); } while (0)
#endif

/* ================= arena allocator ================= */

#define SNX_CHUNK_MIN   512
#define SNX_ALIGN       sizeof(void *)

static size_t
snx_align_up(size_t n)
{
    return (n + SNX_ALIGN - 1) & ~(SNX_ALIGN - 1);
}

snx_arena_t *
snx_arena_new(size_t size)
{
    snx_arena_t   *a;
    snx_chunk_t   *c;

    a = malloc(sizeof(snx_arena_t));
    if (a == NULL) {
        return NULL;
    }

    if (size < SNX_CHUNK_MIN) {
        size = SNX_CHUNK_MIN;
    }

    c = malloc(sizeof(snx_chunk_t) + size);
    if (c == NULL) {
        free(a);
        return NULL;
    }

    c->next = NULL;
    c->last = (uchar *) (c + 1);
    c->end = c->last + size;
    __asan_poison_memory_region(c->last, c->end - c->last);

    a->cur = c;
    a->large = NULL;
    a->max = size;

    return a;
}

void
snx_arena_free(snx_arena_t *a)
{
    snx_chunk_t  *c, *next;

    if (a == NULL) {
        return;
    }

    c = a->large;
    while (c) {
        next = c->next;
        free(c);
        c = next;
    }

    c = a->cur;
    while (c) {
        next = c->next;
        free(c);
        c = next;
    }

    free(a);
}

void
snx_arena_reset(snx_arena_t *a)
{
    snx_chunk_t  *c, *next;

    c = a->large;
    while (c) {
        next = c->next;
        free(c);
        c = next;
    }
    a->large = NULL;

    for (c = a->cur; c; c = c->next) {
        c->last = (uchar *) (c + 1);
        __asan_poison_memory_region(c->last, c->end - c->last);
    }
}

void *
snx_arena_alloc(snx_arena_t *a, size_t size)
{
    snx_chunk_t  *c;
    uchar        *p;

    size = snx_align_up(size);

    if (size <= a->max / 2) {
        for (c = a->cur; c; c = c->next) {
            if ((size_t) (c->end - c->last) >= size) {
                p = c->last;
                c->last += size;
                __asan_unpoison_memory_region(p, size);
                return p;
            }
        }

        /* new regular chunk */
        {
            size_t  alloc = a->max;
            if (alloc < size) {
                alloc = size;
            }
            c = malloc(sizeof(snx_chunk_t) + alloc);
            if (c == NULL) {
                return NULL;
            }
            c->last = (uchar *) (c + 1);
            c->end = c->last + alloc;
            __asan_poison_memory_region(c->last, c->end - c->last);
            c->next = a->cur;
            a->cur = c;
            p = c->last;
            c->last += size;
            __asan_unpoison_memory_region(p, size);
            return p;
        }
    }

    /* large object: its own chunk, hung on a separate list */
    c = malloc(sizeof(snx_chunk_t) + size);
    if (c == NULL) {
        return NULL;
    }
    c->last = (uchar *) (c + 1);
    c->end = c->last + size;
    c->next = a->large;
    a->large = c;

    return c->last;
}

void *
snx_arena_calloc(snx_arena_t *a, size_t size)
{
    void  *p = snx_arena_alloc(a, size);
    if (p) {
        memset(p, 0, size);
    }
    return p;
}

/* ================= io buffer ================= */

snx_iobuf_t *
snx_iob_new(snx_arena_t *a, size_t cap)
{
    snx_iobuf_t  *b;

    b = snx_acnew(a, snx_iobuf_t);
    if (b == NULL) {
        return NULL;
    }
    b->base = snx_arena_alloc(a, cap);
    if (b->base == NULL) {
        return NULL;
    }
    b->head = b->base;
    b->tail = b->base;
    b->cap = cap;
    b->flags = SNX_IOB_MEM | SNX_IOB_TMP;
    return b;
}

snx_iobuf_t *
snx_iob_file(snx_arena_t *a, int fd, soff_t pos, soff_t len)
{
    snx_iobuf_t  *b;

    b = snx_acnew(a, snx_iobuf_t);
    if (b == NULL) {
        return NULL;
    }
    b->flags = SNX_IOB_FILE;
    b->fd = fd;
    b->fpos = pos;
    b->flen = len;
    return b;
}

void
snx_iob_append(snx_iobuf_t **head, snx_iobuf_t **tail, snx_iobuf_t *b)
{
    if (*head == NULL) {
        *head = b;
    } else {
        (*tail)->next = b;
    }
    *tail = b;
    b->next = NULL;
}

/* ================= strings ================= */

long
snx_atoi(uchar *p, size_t n)
{
    long  v = 0;

    while (n--) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
        v = v * 10 + (*p - '0');
        if (v < 0) {
            return -1;
        }
        p++;
    }
    return v;
}

soff_t
snx_atooff(uchar *p, size_t n)
{
    soff_t  v = 0;

    while (n--) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
        v = v * 10 + (*p - '0');
        if (v < 0) {
            return -1;
        }
        p++;
    }
    return v;
}

uchar *
snx_cpymem(uchar *dst, const uchar *src, size_t n)
{
    memcpy(dst, src, n);
    return dst + n;
}

uchar *
snx_strlchr(uchar *s, uchar *last, uchar c)
{
    while (s < last) {
        if (*s == c) {
            return s;
        }
        s++;
    }
    return NULL;
}

int
snx_ncmp(uchar *a, uchar *b, size_t n)
{
    return memcmp(a, b, n);
}

int
snx_ncasecmp(uchar *a, uchar *b, size_t n)
{
    return strncasecmp((char *) a, (char *) b, n);
}

int
snx_str_eq(snx_str_t *a, const char *b)
{
    size_t  n = strlen(b);
    return a->n == n && memcmp(a->p, b, n) == 0;
}

snx_str_t
snx_str_dup(snx_arena_t *a, snx_str_t *s)
{
    snx_str_t  d;

    d.n = s->n;
    d.p = snx_arena_alloc(a, s->n + 1);
    if (d.p) {
        memcpy(d.p, s->p, s->n);
        d.p[s->n] = '\0';
    }
    return d;
}

/* ================= unescape ================= */

void
snx_unescape(uchar **dst, uchar **src, size_t n, int type)
{
    uchar  *d, *s, *end, ch;
    static const uchar hexmap[] =
        "................................"
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09.........." /* 0-9 */
        ".<;=>?@"
        "\x0a\x0b\x0c\x0d\x0e\x0f.........";   /* A-F (partial) */

    (void) hexmap;

    d = *dst;
    s = *src;
    end = s + n;

    while (s < end) {
        ch = *s;

        if (ch == '%' && s + 2 < end) {
            int  hi, lo;

            hi = s[1];
            lo = s[2];

            if (hi >= '0' && hi <= '9') hi -= '0';
            else if (hi >= 'a' && hi <= 'f') hi = hi - 'a' + 10;
            else if (hi >= 'A' && hi <= 'F') hi = hi - 'A' + 10;
            else goto plain;

            if (lo >= '0' && lo <= '9') lo -= '0';
            else if (lo >= 'a' && lo <= 'f') lo = lo - 'a' + 10;
            else if (lo >= 'A' && lo <= 'F') lo = lo - 'A' + 10;
            else goto plain;

            *d++ = (uchar) ((hi << 4) | lo);
            s += 3;
            continue;
        }

        if (ch == '+' && type == SNX_UNESC_ARGS) {
            *d++ = ' ';
            s++;
            continue;
        }

plain:
        *d++ = ch;
        s++;
    }

    *dst = d;
    *src = s;
}

/* ================= formatter =================
 * %s  - C string
 * %S  - snx_str_t *
 * %d  - int        %l - long        %f - soff_t/off
 * %x  - unsigned hex
 * %c  - char
 */

static uchar  snx_num_tmp[64];

static uchar *
snx_fmt_num(uchar *buf, uchar *last, uint64_t v, int sign)
{
    uchar  tmp[32], *p = tmp + sizeof(tmp);

    if (sign && (int64_t) v < 0) {
        v = (uint64_t) (-(int64_t) v);
        if (buf < last) {
            *buf++ = '-';
        }
    }

    do {
        *--p = (uchar) ('0' + v % 10);
        v /= 10;
    } while (v);

    while (p < tmp + sizeof(tmp) && buf < last) {
        *buf++ = *p++;
    }
    return buf;
}

uchar *
snx_vfmt(uchar *buf, uchar *last, const char *fmt, va_list ap)
{
    uchar      *p;
    snx_str_t  *s;
    uint64_t    v;
    char        ch;
    const char *f;

    f = fmt;
    while (*f && buf < last) {
        if (*f != '%') {
            *buf++ = (uchar) *f++;
            continue;
        }

        f++;
        switch (*f) {
        case 's':
            p = (uchar *) va_arg(ap, char *);
            if (p == NULL) {
                p = (uchar *) "(null)";
            }
            while (*p && buf < last) {
                *buf++ = *p++;
            }
            break;
        case 'S':
            s = va_arg(ap, snx_str_t *);
            if (s && s->p) {
                buf = snx_cpymem(buf, s->p,
                                 (size_t) (last - buf) < s->n
                                 ? (size_t) (last - buf) : s->n);
            }
            break;
        case 'd':
            buf = snx_fmt_num(buf, last,
                              (uint64_t) va_arg(ap, int), 1);
            break;
        case 'l':
            buf = snx_fmt_num(buf, last,
                              (uint64_t) va_arg(ap, long), 1);
            break;
        case 'f':
            buf = snx_fmt_num(buf, last,
                              (uint64_t) va_arg(ap, soff_t), 1);
            break;
        case 'x':
            v = va_arg(ap, unsigned);
            {
                uchar  t[16], *q = t + sizeof(t);
                do {
                    *--q = (uchar) "0123456789abcdef"[v & 0xf];
                    v >>= 4;
                } while (v);
                while (q < t + sizeof(t) && buf < last) {
                    *buf++ = *q++;
                }
            }
            break;
        case 'c':
            ch = (char) va_arg(ap, int);
            if (buf < last) {
                *buf++ = (uchar) ch;
            }
            break;
        case 'p':
            v = (uint64_t) va_arg(ap, void *);
            {
                uchar  t[20], *q = t + sizeof(t);
                do {
                    *--q = (uchar) "0123456789abcdef"[v & 0xf];
                    v >>= 4;
                } while (v);
                if (buf + 2 <= last) { *buf++ = '0'; *buf++ = 'x'; }
                while (q < t + sizeof(t) && buf < last) {
                    *buf++ = *q++;
                }
            }
            break;
        case '%':
            *buf++ = '%';
            break;
        default:
            if (*f == '\0') {
                goto out;
            }
            *buf++ = (uchar) *f;
            break;
        }
        if (*f) {
            f++;
        }
    }
out:
    return buf;
}

uchar *
snx_fmt(uchar *buf, uchar *last, const char *fmt, ...)
{
    va_list  ap;
    uchar   *p;

    va_start(ap, fmt);
    p = snx_vfmt(buf, last, fmt, ap);
    va_end(ap);

    (void) snx_num_tmp;
    return p;
}

/* ================= logging ================= */

snx_log_t  snx_stderr_log = { SNX_LOG_NOTICE, STDERR_FILENO };

void
snx_log_write(snx_log_t *log, int level, const char *fmt, ...)
{
    uchar    buf[2048], *p;
    va_list  ap;
    char     tbuf[32];
    time_t   now;
    struct tm tm;

    if (level > log->level) {
        return;
    }

    now = time(NULL);
    localtime_r(&now, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y/%m/%d %H:%M:%S", &tm);

    p = snx_fmt(buf, buf + sizeof(buf), "%s [%d] %d#0: ", tbuf, level,
                (int) getpid());

    va_start(ap, fmt);
    p = snx_vfmt(p, buf + sizeof(buf) - 2, fmt, ap);
    va_end(ap);

    /* note: message bytes are emitted verbatim; request-supplied data is
       not filtered before reaching the error log */
    *p++ = '\n';

    (void) write(log->fd, buf, p - buf);
}

void
snx_log_err(snx_log_t *log, const char *fmt, ...)
{
    uchar    buf[2048], *p;
    va_list  ap;

    p = buf;
    va_start(ap, fmt);
    p = snx_vfmt(p, buf + sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    *p++ = '\n';

    (void) write(log->fd, buf, p - buf);
}

/* ================= md5 ================= */

static const uint32_t snx_md5_k[] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,
    0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,
    0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,
    0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,
    0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
    0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const int snx_md5_s[] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

void
snx_md5_init(snx_md5_t *ctx)
{
    ctx->bytes = 0;
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;
}

static void
snx_md5_block(snx_md5_t *ctx, const uchar *p)
{
    uint32_t  w[16], a, b, c, d, f, g;
    int       i;

    for (i = 0; i < 16; i++) {
        w[i] = (uint32_t) p[i * 4] | ((uint32_t) p[i * 4 + 1] << 8)
             | ((uint32_t) p[i * 4 + 2] << 16) | ((uint32_t) p[i * 4 + 3] << 24);
    }

    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;

    for (i = 0; i < 64; i++) {
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) & 15;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) & 15;
        }

        f += a + snx_md5_k[i] + w[g];
        a = d;
        d = c;
        c = b;
        b += (f << snx_md5_s[i]) | (f >> (32 - snx_md5_s[i]));
    }

    ctx->a += a;
    ctx->b += b;
    ctx->c += c;
    ctx->d += d;
}

void
snx_md5_update(snx_md5_t *ctx, const void *data, size_t n)
{
    const uchar  *p = data;
    size_t        used, freeb;

    used = (size_t) (ctx->bytes & 63);
    ctx->bytes += n;
    freeb = 64 - used;

    if (n < freeb) {
        memcpy(ctx->buf + used, p, n);
        return;
    }

    memcpy(ctx->buf + used, p, freeb);
    snx_md5_block(ctx, ctx->buf);
    p += freeb;
    n -= freeb;

    while (n >= 64) {
        snx_md5_block(ctx, p);
        p += 64;
        n -= 64;
    }

    memcpy(ctx->buf, p, n);
}

void
snx_md5_final(uchar out[16], snx_md5_t *ctx)
{
    uint64_t  bits = ctx->bytes * 8;
    size_t    used = (size_t) (ctx->bytes & 63);
    int       i;
    uint32_t  r[4];

    ctx->buf[used++] = 0x80;
    if (used > 56) {
        memset(ctx->buf + used, 0, 64 - used);
        snx_md5_block(ctx, ctx->buf);
        used = 0;
    }
    memset(ctx->buf + used, 0, 56 - used);
    memcpy(ctx->buf + 56, &bits, 8);
    snx_md5_block(ctx, ctx->buf);

    r[0] = ctx->a;
    r[1] = ctx->b;
    r[2] = ctx->c;
    r[3] = ctx->d;

    for (i = 0; i < 4; i++) {
        out[i * 4] = (uchar) (r[i] & 0xff);
        out[i * 4 + 1] = (uchar) ((r[i] >> 8) & 0xff);
        out[i * 4 + 2] = (uchar) ((r[i] >> 16) & 0xff);
        out[i * 4 + 3] = (uchar) ((r[i] >> 24) & 0xff);
    }
}
