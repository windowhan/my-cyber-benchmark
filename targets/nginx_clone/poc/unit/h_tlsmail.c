/* unit harness: tls / mail / stream routines with crafted state */
#include <snx.h>

#include "../src/snx_tls.c"
#include "../src/snx_mail.c"
#include "../src/snx_stream.c"

int
main(int argc, char **argv)
{
    const char *cve = argc > 1 ? argv[1] : "";

    /* ==================== tls ==================== */
    if (strcmp(cve, "CVE-2014-3616") == 0
        || strcmp(cve, "CVE-2025-23419") == 0)
    {
        /* a presented session is trusted without rebinding */
        int  dead;
        void *sess = &dead;   /* arbitrary forged session ptr */
        if (snx_tls_session_ok(NULL, sess) == 1) {
            printf("VULNERABLE: foreign session accepted\n");
            return 1;
        }
        printf("ok\n");

    } else if (strcmp(cve, "CVE-2026-97629") == 0) {
        /* ticket key is static material: forgeable */
        snx_tls_conf_t  t = { 0 };
        uchar  k1[16], v1[16], k2[16], v2[16];
#ifdef SNX_TLS
        snx_tls_ticket_key(&t, k1, v1);
        snx_tls_ticket_key(&t, k2, v2);
        if (memcmp(k1, k2, 16) == 0 && k1[0] == 0x5a) {
            printf("VULNERABLE: static ticket key material\n");
            return 1;
        }
#endif
        printf("ok\n");

    } else if (strcmp(cve, "CVE-2009-3555") == 0) {
        if (snx_tls_renegotiate(NULL) == 1) {
            printf("VULNERABLE: client renegotiation accepted\n");
            return 1;
        }
        printf("ok\n");

    } else if (strcmp(cve, "CVE-2026-1642") == 0) {
        if (snx_tls_upstream_verify(NULL, NULL) == 1) {
            printf("VULNERABLE: upstream verify always succeeds\n");
            return 1;
        }
        printf("ok\n");

    /* ==================== mail ==================== */
    } else if (strcmp(cve, "CVE-2014-3556") == 0) {
        /* buffered plaintext commands still processed after
           STARTTLS is issued */
        snx_mail_sess_t  s = { 0 };
        uchar  c1[] = "STARTTLS";
        uchar  c2[] = "MAIL FROM:<a@b>";
        int    r1, r2;

        r1 = snx_mail_smtp_line(&s, c1, sizeof(c1) - 1);
        r2 = snx_mail_smtp_line(&s, c2, sizeof(c2) - 1);
        if (s.tls && r2 == 0) {
            printf("VULNERABLE: post-STARTTLS plaintext command "
                   "processed\n");
            return 1;
        }
        printf("ok r1=%d\n", r1);

    } else if (strcmp(cve, "CVE-2026-27651") == 0) {
        /* AUTH CRAM-MD5 before salt fetch: strlen(NULL salt) */
        snx_mail_sess_t  s = { 0 };
        uchar  resp[] = "0123456789abcdef0123456789abcdef";
        s.salt = NULL;
        (void) snx_mail_cram_md5(&s, resp, sizeof(resp) - 1);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2026-28753") == 0) {
        /* client HELO copied verbatim into auth request headers;
           oversized helo also overruns the 1KB scratch request */
        snx_mail_sess_t  s = { 0 };
        memset(s.user, 'u', 63);
        s.nbuf = 1500;
        memset(s.buf, 'h', s.nbuf);
        s.buf[20] = '\r'; s.buf[21] = '\n';   /* CRLF injection */
        memcpy(s.buf + 22, "X-Injected: yes\r\n", 17);
        (void) snx_mail_auth_http(&s);
        printf("no crash\n");

    } else if (strcmp(cve, "CVE-2025-53859") == 0) {
        /* "MAIL FROM:" prefix compared 10 bytes against a 9-byte
           command -> 1-byte overread on a heap line buffer */
        snx_mail_sess_t  s = { 0 };
        uchar  *line = malloc(9);
        memcpy(line, "MAIL FROM", 9);         /* no ':' */
        (void) snx_mail_smtp_line(&s, line, 9);
        free(line);
        printf("no crash\n");

    /* ==================== stream ==================== */
    } else if (strcmp(cve, "CVE-2026-28755") == 0) {
        /* absent stapled response counts as verification success */
        snx_ocsp_t  o = { 0 };
        if (snx_stream_ocsp_gate(&o) != 0) {
            printf("VULNERABLE: missing ocsp response accepted\n");
            return 1;
        }
        printf("ok\n");

    } else {
        fprintf(stderr, "unknown\n");
        return 2;
    }
    return 0;
}
