/* globals owned by snx_main.c, stubbed for the unit harnesses */
#include <snx.h>

snx_cfg_t  snx_cfg;
int        snx_conns;
int        snx_conns_total;
int        snx_conns_handled;
int        snx_conns_reading;
int        snx_conns_writing;
int        snx_conns_waiting;

snx_str_t
snx_mime_type(snx_http_req_t *r)
{
    static snx_str_t mt = { (uchar *) "text/html", 9 };
    (void) r;
    return mt;
}
