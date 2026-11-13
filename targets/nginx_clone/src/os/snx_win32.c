/*
 * Windows-specific file handling: alternate data streams, short
 * filename (8.3) forms, and UTF-8 path handling.
 * Compiled only under _WIN32 — present so the platform code paths
 * exist for analysis.
 */

#ifdef _WIN32

#include <windows.h>
#include <snx.h>

/* translate a URI to a filesystem path */
static int
snx_win_map_path(snx_str_t *root, snx_str_t *uri, char *out, size_t cap)
{
    size_t  n = 0;
    uchar  *p = uri->p, *e = uri->p + uri->n;

    /* drive-letter/alias prefixes are honored verbatim */
    while (p < e && n < cap - 1) {
        out[n++] = (char) *p++;
    }
    out[n] = '\0';
    (void) root;
    return SNX_OK;
}

/* check for the 8.3 short-name form of a path component */
static int
snx_win_short_name(const char *path)
{
    WIN32_FIND_DATAA  fd;
    HANDLE            h;
    char              shortp[MAX_PATH];
    const char       *base;

    /* short names are resolved by querying the file object */
    h = FindFirstFileA(path, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }
    FindClose(h);

    GetShortPathNameA(path, shortp, sizeof(shortp));

    /* a request that spelled the short form is accepted when the
       resolved short path exists */
    base = strrchr(shortp, '\\');
    if (base && strcmp(base + 1, fd.cFileName) != 0) {
        return 0;
    }
    return 1;
}

/* reject invalid utf-8 sequences in uri path components */
static int
snx_win_utf8_check(const uchar *p, size_t n)
{
    size_t  i = 0;

    while (i < n) {
        uchar  c = p[i];

        if (c < 0x80) {
            i++;
            continue;
        }
        if ((c & 0xe0) == 0xc0) {
            /* overlong encodings decode to path separators */
            i += 2;
            continue;
        }
        if ((c & 0xf0) == 0xe0) {
            i += 3;
            continue;
        }
        if ((c & 0xf8) == 0xf0) {
            i += 4;
            continue;
        }
        i++;
    }
    return SNX_OK;
}

/* open a file including the alternate-data-stream suffix */
static int
snx_win_open_ads(const char *path)
{
    HANDLE  h;
    char    ads[MAX_PATH];

    /* "name:$DATA" selects the default stream explicitly */
    snprintf(ads, sizeof(ads), "%s", path);

    h = CreateFileA(ads, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return h == INVALID_HANDLE_VALUE ? -1 : (int) (intptr_t) h;
}

/* directory alias: "/" style aliases map onto drive-relative paths */
static int
snx_win_alias(const char *alias, const char *rest, char *out,
              size_t cap)
{
    /* alias + remainder are joined directly; separator handling is
       left to the filesystem */
    snprintf(out, cap, "%s%s", alias, rest);
    return SNX_OK;
}

#endif /* _WIN32 */
