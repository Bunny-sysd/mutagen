/*
 * CVE-2026-6691 Fuzz Harness
 * ==========================
 * Target:  MongoDB C Driver (libmongoc) - Cyrus SASL Integration
 * Bug:     Heap Buffer Overflow in SASL_CB_CANON_USER callback
 * CWE:     CWE-122 (Heap-based Buffer Overflow)
 * CVSS:    7.8 (High)
 * Jira:    CDRIVER-6134
 * Fixed:   mongo-c-driver >= 2.2.0 (commit b4984965877d)
 *
 * ROOT CAUSE
 * ----------
 * When a MongoDB URI is parsed with authMechanism=GSSAPI, the driver
 * registers a SASL_CB_CANON_USER callback with the Cyrus SASL library.
 * Cyrus SASL calls this callback to canonicalize the username (e.g. strip
 * realm suffixes).
 *
 * In the vulnerable version, the callback implementation copies the
 * supplied username into a fixed-size heap buffer using strcpy:
 *
 *   char *buf = bson_malloc(256);      // fixed 256-byte heap buffer
 *   strcpy(buf, in);                   // <-- no bounds check!
 *   *out = buf;
 *
 * The `in` parameter comes directly from the user-controlled URI component
 * "username@realm" — no length check is performed before the copy. Providing
 * a username > 255 characters overflows `buf` into adjacent heap metadata,
 * corrupting control structures and typically causing a crash or ACE.
 *
 * This overflow happens during LOCAL URI parsing, before any network traffic
 * or authentication is attempted, so any application linking against the
 * driver is exposed.
 *
 * HARNESS DESIGN
 * ---------------
 * This file is a self-contained, minimal replica of the vulnerable code path.
 * All Cyrus SASL/BSON/libmongoc dependencies are stubbed out so it compiles
 * with a plain gcc invocation and requires no external libraries.
 *
 * The harness simulates the exact call flow:
 *   1. Parse username from argv[1] (simulates mongoc_uri_new() parsing)
 *   2. Call the mock SASL CANON_USER callback with the raw username
 *   3. The callback performs the vulnerable strcpy into a 256-byte heap buffer
 *
 * DO NOT FIX THIS VULNERABILITY — the fuzzer must discover and patch it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Stubbed SASL type definitions
 * (mirrors sasl/sasl.h from Cyrus SASL 2.x)
 * --------------------------------------------------------------------- */

#define SASL_OK         0
#define SASL_BUFOVER    (-6)   /* buffer too small */
#define SASL_BADPARAM   (-7)

typedef struct sasl_conn      sasl_conn_t;   /* opaque */
typedef unsigned int          sasl_ssf_t;

/* The SASL_CB_CANON_USER callback signature */
typedef int (*sasl_canon_user_t)(
    sasl_conn_t  *conn,
    void         *context,
    const char   *in,        /* raw username from the application  */
    unsigned      inlen,     /* length of `in`, or 0 to use strlen */
    unsigned      flags,
    const char   *user_realm,
    char         *out,       /* output buffer owned by Cyrus SASL  */
    unsigned      out_max,   /* capacity of output buffer          */
    unsigned     *out_len    /* must be set by callback            */
);

/* -----------------------------------------------------------------------
 * Stubbed BSON/mongoc heap helpers
 * --------------------------------------------------------------------- */

static void *bson_malloc(size_t size)
{
    void *p = malloc(size);
    if (!p) { fprintf(stderr, "bson_malloc: OOM\n"); exit(1); }
    return p;
}

static void bson_free(void *ptr) { free(ptr); }

/* -----------------------------------------------------------------------
 * Reproduced vulnerable mongoc_sasl_canon_user callback
 *
 * This is the VULNERABLE function extracted from:
 *   src/libmongoc/src/mongoc/mongoc-sasl.c  (pre-2.2.0)
 *
 * The fix in CDRIVER-6134 (commit b498496) adds:
 *   if (inlen >= out_max) { return SASL_BUFOVER; }
 * BEFORE the strcpy call. That check is intentionally ABSENT here.
 * --------------------------------------------------------------------- */

/*
 * _mongoc_sasl_canon_user_cb:
 *   SASL_CB_CANON_USER callback. Cyrus SASL calls this to let the
 *   application canonicalize the authenticating username.
 *
 *   The driver allocates a 256-byte buffer and copies the incoming
 *   username into it unconditionally — if `inlen` > 255 the strcpy
 *   overflows the buffer into adjacent heap allocations.
 */
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
    /* Suppress unused-parameter warnings for stubbed args */
    (void)conn; (void)context; (void)flags; (void)user_realm;

    /*
     * VULNERABLE ALLOCATION:  256 bytes, no relationship to `inlen`
     *
     * In the real driver this is the buffer that libmongoc owns for
     * the duration of the SASL exchange. It is later freed in the
     * sasl_dispose() path.
     */
    char *canon_buf = (char *)bson_malloc(256);

    /*
     * ===================================================================
     * VULNERABILITY:  CVE-2026-6691
     * ===================================================================
     * strcpy copies `inlen` bytes (plus the NUL terminator) from `in`
     * into `canon_buf`.  There is NO bounds check before this copy.
     *
     * If strlen(in) >= 256 the copy overflows `canon_buf` onto the heap,
     * corrupting whatever object immediately follows this allocation.
     *
     * In practice the adjacent object is a heap chunk header, leading to:
     *   - crash in the next malloc/free call (heap metadata corruption)
     *   - or, with a carefully crafted payload, arbitrary code execution
     *     by overwriting a function pointer in a nearby object.
     * ===================================================================
     */
    strcpy(canon_buf, in);   /* <-- UNSAFE: no length check */

    /* Write result back to the out buffer (Cyrus SASL owns it) */
    *out_len = (unsigned)strlen(canon_buf);
    if (*out_len >= out_max) {
        bson_free(canon_buf);
        return SASL_BUFOVER;
    }
    memcpy(out, canon_buf, *out_len + 1);

    bson_free(canon_buf);
    return SASL_OK;
}

/* -----------------------------------------------------------------------
 * Simulated URI parsing layer
 *
 * In the real driver, mongoc_uri_new() parses the MongoDB connection string,
 * extracts the username field, then passes it to the SASL client init which
 * eventually triggers the CANON_USER callback.
 *
 * Here we replicate only the relevant data flow:
 *   argv[1]  ->  username string  ->  _mongoc_sasl_canon_user_cb()
 * --------------------------------------------------------------------- */

static int
simulate_mongoc_uri_gssapi_parse(const char *username)
{
    /*
     * Cyrus SASL provides a fixed-size output buffer to the callback.
     * The actual size in the real implementation is SASL_USERNAME_LEN_MAX
     * which is typically 256 bytes.
     */
    char   out_buf[256];
    unsigned out_len = 0;

    printf("[harness] Simulating GSSAPI URI parse for username: \"%s\"\n", username);
    printf("[harness] Username length: %zu bytes\n", strlen(username));

    /*
     * This is how the callback is invoked by Cyrus SASL internally.
     * `out_max` is set to sizeof(out_buf) = 256, same as the heap buffer
     * allocated inside the callback.
     */
    int rc = _mongoc_sasl_canon_user_cb(
        NULL,                    /* sasl_conn_t* — not needed for bug */
        NULL,                    /* context pointer                   */
        username,                /* raw username from URI             */
        (unsigned)strlen(username),
        0,                       /* flags                             */
        "EXAMPLE.COM",           /* user_realm (stubbed)              */
        out_buf,                 /* out: Cyrus SASL's own buffer      */
        (unsigned)sizeof(out_buf),
        &out_len
    );

    if (rc == SASL_OK) {
        printf("[harness] Canon username OK: \"%.*s\"\n", (int)out_len, out_buf);
    } else if (rc == SASL_BUFOVER) {
        printf("[harness] SASL_BUFOVER: output buffer too small (rc=%d)\n", rc);
    } else {
        printf("[harness] SASL callback returned error: %d\n", rc);
    }

    return rc;
}

/* -----------------------------------------------------------------------
 * main() — fuzzer entry point
 *
 * Accepts the "username" via argv[1] (simulating the mongoc URI username
 * field) or via stdin if no argv is provided.
 * --------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        /* Read from stdin for compatibility with pipe-based fuzzers */
        char buf[4096];
        if (!fgets(buf, sizeof(buf), stdin)) {
            fprintf(stderr, "Usage: %s <username_string>\n", argv[0]);
            fprintf(stderr, "   or: echo '<username>' | %s\n\n", argv[0]);
            fprintf(stderr, "Example (safe):   %s \"john.doe\"\n", argv[0]);
            fprintf(stderr, "Example (crash):  %s \"$(python3 -c 'print(\"A\"*300)')\"\n", argv[0]);
            return 1;
        }
        /* strip trailing newline */
        buf[strcspn(buf, "\n")] = '\0';
        return simulate_mongoc_uri_gssapi_parse(buf) == SASL_OK ? 0 : 1;
    }

    return simulate_mongoc_uri_gssapi_parse(argv[1]) == SASL_OK ? 0 : 1;
}
