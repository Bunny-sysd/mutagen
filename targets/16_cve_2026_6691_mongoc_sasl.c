#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SASL_OK         0
#define SASL_BUFOVER    (-6)
#define SASL_BADPARAM   (-7)

typedef struct sasl_conn      sasl_conn_t;
typedef unsigned int          sasl_ssf_t;

typedef int (*sasl_canon_user_t)(
    sasl_conn_t  *conn,
    void         *context,
    const char   *in,
    unsigned      inlen,
    unsigned      flags,
    const char   *user_realm,
    char         *out,
    unsigned      out_max,
    unsigned     *out_len
);

static void *bson_malloc(size_t size)
{
    size_t total_size = size + sizeof(size_t) + 8;
    void *p = malloc(total_size);
    if (!p) { fprintf(stderr, "bson_malloc: OOM\n"); exit(1); }
    
    *(size_t *)p = size;
    
    char *user_ptr = (char *)p + sizeof(size_t);
    unsigned char *canary_ptr = (unsigned char *)(user_ptr + size);
    canary_ptr[0] = 0xDE;
    canary_ptr[1] = 0xAD;
    canary_ptr[2] = 0xC0;
    canary_ptr[3] = 0xDE;
    canary_ptr[4] = 0xEF;
    canary_ptr[5] = 0xBE;
    canary_ptr[6] = 0xAD;
    canary_ptr[7] = 0xDE;
    
    return user_ptr;
}

static void bson_free(void *ptr)
{
    if (!ptr) return;
    
    void *raw_ptr = (char *)ptr - sizeof(size_t);
    size_t size = *(size_t *)raw_ptr;
    
    unsigned char *canary_ptr = (unsigned char *)((char *)ptr + size);
    if (canary_ptr[0] != 0xDE || canary_ptr[1] != 0xAD ||
        canary_ptr[2] != 0xC0 || canary_ptr[3] != 0xDE ||
        canary_ptr[4] != 0xEF || canary_ptr[5] != 0xBE ||
        canary_ptr[6] != 0xAD || canary_ptr[7] != 0xDE) {
        fprintf(stderr, "HEAP CORRUPTION DETECTED: Heap block at %p (size %zu) canary corrupted!\n", ptr, size);
        abort();
    }
    
    free(raw_ptr);
}

static int
_mongoc_sasl_canon_user_cb(sasl_conn_t  *conn,
                            void         *context,
                            const char   *in,
                            unsigned      inlen,
                            unsigned      flags,
                            const char   *user_realm,
                            char         *out,
                            unsigned      out_max,
                            unsigned     *out_len)
{
    (void)conn; (void)context; (void)flags; (void)user_realm;

    char *canon_buf = (char *)bson_malloc(256);

    strcpy(canon_buf, in);

    *out_len = (unsigned)strlen(canon_buf);
    if (*out_len >= out_max) {
        bson_free(canon_buf);
        return SASL_BUFOVER;
    }
    memcpy(out, canon_buf, *out_len + 1);

    bson_free(canon_buf);
    return SASL_OK;
}

static int
simulate_mongoc_uri_gssapi_parse(const char *username)
{
    char   out_buf[256];
    unsigned out_len = 0;

    int rc = _mongoc_sasl_canon_user_cb(
        NULL,
        NULL,
        username,
        (unsigned)strlen(username),
        0,
        "EXAMPLE.COM",
        out_buf,
        (unsigned)sizeof(out_buf),
        &out_len
    );

    return rc;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        char buf[4096];
        if (!fgets(buf, sizeof(buf), stdin)) {
            return 1;
        }
        buf[strcspn(buf, "\n")] = '\0';
        return simulate_mongoc_uri_gssapi_parse(buf) == SASL_OK ? 0 : 1;
    }

    return simulate_mongoc_uri_gssapi_parse(argv[1]) == SASL_OK ? 0 : 1;
}
