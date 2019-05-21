/***********************************************************************
 *          OPENSSL.C
 *
 *          OpenSSL-specific code for the TLS/SSL layer
 *
 *          Copyright (c) 2018 Niyamaka.
 *          All Rights Reserved.
***********************************************************************/
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "../ytls.h"
#include "openssl.h"

/***************************************************************
 *              Constants
 ***************************************************************/

/***************************************************************
 *              Structures
 ***************************************************************/
typedef struct ytls_s {
    api_tls_t *api_tls;     // HACK must be the first item
    json_t *jn_config;
    BOOL server;
    SSL_CTX *ctx;
} ytls_t;

typedef struct sskt_s {
    ytls_t *ytls;
    SSL *ssl;
    BIO *internal_bio, *network_bio;
    BOOL handshake_informed;
    int (*on_handshake_done_cb)(void *user_data, int error);
    int (*on_clear_data_cb)(void *user_data, GBUFFER *gbuf, int error);
    int (*on_encrypted_data_cb)(void *user_data, GBUFFER *gbuf, int error);
    void *user_data;
    char last_error[256];
} sskt_t;

/***************************************************************
 *              Prototypes
 ***************************************************************/
PRIVATE hytls init(
        json_t *jn_config,  // not owned
        BOOL server
);
PRIVATE void cleanup(hytls ytls);
PRIVATE const char *version(hytls ytls);
PRIVATE hsskt new_secure_filter(
    hytls ytls,
    int (*on_handshake_done_cb)(void *user_data, int error),
    int (*on_clear_data_cb)(void *user_data, GBUFFER *gbuf, int error),
    int (*on_encrypted_data_cb)(void *user_data, GBUFFER *gbuf, int error),
    void *user_data
);
PRIVATE void free_secure_filter(hsskt sskt);
PRIVATE int do_handshake(hsskt sskt);
PRIVATE int flush_encrypted_data(sskt_t *sskt);
PRIVATE int encrypt_data(hsskt sskt, GBUFFER *gbuf);
PRIVATE int flush_clear_data(sskt_t *sskt);
PRIVATE int decrypt_data(hsskt sskt, GBUFFER *gbuf);
PRIVATE const char *last_error(hsskt sskt);

/***************************************************************
 *              Data
 ***************************************************************/
PRIVATE api_tls_t api_tls = {
    "OPENSSL",
    init,
    cleanup,
    version,
    new_secure_filter,
    free_secure_filter,
    do_handshake,
    encrypt_data,
    decrypt_data,
    last_error,
};

BOOL __initialized__ = FALSE;

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void ssl_tls_trace(
    int direction,
    int ssl_ver,
    int content_type,
    const void *buf,
    size_t len,
    SSL *ssl,
    void *userp
)
{
    trace_msg("**** direction %d, version %d, c_type %d, %.*s",
        direction,
        version,
        buf,
        len
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE hytls init(
        json_t *jn_config,  // not owned
        BOOL server
)
{
    /*--------------------------------*
     *      Init OPENSSL
     *--------------------------------*/
    if(!__initialized__) {
        __initialized__ = TRUE;
        SSL_library_init();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    const SSL_METHOD *method = 0;
    if(server) {
        method = SSLv23_server_method();        /* Create new server-method instance */
    } else {
        method = SSLv23_client_method();        /* Create new client-method instance */
    }
    SSL_CTX *ctx = SSL_CTX_new(method);         /* Create new context */
    if(!ctx) {
        unsigned long err = ERR_get_error();
        log_error(0,
            "gobj",         "%s", __FILE__,
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "SSL_CTX_new() FAILED",
            "error",        "%s", ERR_error_string(err, NULL),
            NULL
        );
        return 0;
    }

    /*--------------------------------*
     *      Options
     *--------------------------------*/
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    SSL_CTX_set_options(ctx, options);

    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY
        | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
        | SSL_MODE_ENABLE_PARTIAL_WRITE
#if defined(SSL_MODE_RELEASE_BUFFERS)
        | SSL_MODE_RELEASE_BUFFERS
#endif
    );

    /*--------------------------------*
     *      Alloc memory
     *--------------------------------*/
    ytls_t *ytls = gbmem_malloc(sizeof(ytls_t));
    if(!ytls) {
        log_error(0,
            "gobj",             "%s", __FILE__,
            "function",         "%s", __FUNCTION__,
            "msgset",           "%s", MSGSET_MEMORY_ERROR,
            "msg",              "%s", "no memory for sizeof(ytls_t)",
            "sizeof(ytls_t)",   "%d", sizeof(ytls_t),
            NULL
        );
        return 0;
    }

    ytls->api_tls = &api_tls;
    ytls->jn_config = json_deep_copy(jn_config);
    ytls->server = server;
    ytls->ctx = ctx;

    /* the SSL trace callback is only used for verbose logging */
    if(kw_get_bool(jn_config, "trace", 0, 0)) {
        SSL_CTX_set_msg_callback(ytls->ctx, ssl_tls_trace);
        SSL_CTX_set_msg_callback_arg(ytls->ctx, ytls);
    }

    return (hytls)ytls;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void cleanup(hytls ytls_)
{
    ytls_t *ytls = ytls_;

    // TODO manten una lista de sskt y cierralos

    EXEC_AND_RESET(json_decref, ytls->jn_config);
    SSL_CTX_free(ytls->ctx);

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    gbmem_free(ytls);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE const char *version(hytls ytls)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100001L)
    return OpenSSL_version(OPENSSL_VERSION);
#else
    return SSLeay_version(SSLEAY_VERSION);
#endif
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE hsskt new_secure_filter(
    hytls ytls_,
    int (*on_handshake_done_cb)(void *user_data, int error),
    int (*on_clear_data_cb)(void *user_data, GBUFFER *gbuf, int error),
    int (*on_encrypted_data_cb)(void *user_data, GBUFFER *gbuf, int error),
    void *user_data
)
{
    ytls_t *ytls = ytls_;

    /*--------------------------------*
     *      Alloc memory
     *--------------------------------*/
    sskt_t *sskt = gbmem_malloc(sizeof(sskt_t));
    if(!sskt) {
        log_error(0,
            "gobj",             "%s", __FILE__,
            "function",         "%s", __FUNCTION__,
            "msgset",           "%s", MSGSET_MEMORY_ERROR,
            "msg",              "%s", "no memory for sizeof(sskt_t)",
            "sizeof(sskt_t)",   "%d", sizeof(sskt_t),
            NULL
        );
        return 0;
    }

    sskt->ytls = ytls;
    sskt->on_handshake_done_cb = on_handshake_done_cb;
    sskt->on_clear_data_cb = on_clear_data_cb;
    sskt->on_encrypted_data_cb = on_encrypted_data_cb;
    sskt->user_data = user_data;

    sskt->ssl = SSL_new(ytls->ctx);
    if(!sskt->ssl) {
        unsigned long err = ERR_get_error();
        log_error(0,
            "gobj",         "%s", __FILE__,
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "SSL_new() FAILED",
            "error",        "%s", ERR_error_string(err, NULL),
            NULL
        );
        gbmem_free(sskt);
        return 0;
    }

    if(ytls->server) {
        SSL_set_accept_state(sskt->ssl);
    } else {
        SSL_set_connect_state(sskt->ssl);
    }

#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_set_options(sskt->ssl, SSL_OP_NO_RENEGOTIATION); // New to openssl 1.1.1
#endif

    if(BIO_new_bio_pair(&sskt->internal_bio, 0, &sskt->network_bio, 0)!=1) {
        unsigned long err = ERR_get_error();
        log_error(0,
            "gobj",         "%s", __FILE__,
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "SSL_new() FAILED",
            "error",        "%s", ERR_error_string(err, NULL),
            NULL
        );
        SSL_free(sskt->ssl);
        gbmem_free(sskt);
        return 0;
    }
    SSL_set_bio(sskt->ssl, sskt->internal_bio, sskt->internal_bio);

    do_handshake(sskt);

    return sskt;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void free_secure_filter(hsskt sskt_)
{
    sskt_t *sskt = sskt_;

    if(sskt->handshake_informed) {
        SSL_shutdown(sskt->ssl);
    }
    flush_encrypted_data(sskt);
    BIO_free(sskt->network_bio);
    SSL_free(sskt->ssl);    /* implicitly frees internal_bio */

    gbmem_free(sskt);
}

/***************************************************************************
    Do handshake
 ***************************************************************************/
PRIVATE int do_handshake(hsskt sskt_)
{
    sskt_t *sskt = sskt_;

    ERR_clear_error();
    sskt->last_error[0] = 0;
    int ret = SSL_do_handshake(sskt->ssl);
    if(ret <= 0) {
        int detail = SSL_get_error(sskt->ssl, ret);
        switch(detail) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            flush_encrypted_data(sskt);
            flush_clear_data(sskt);
            return 0;

        default:
            {
                unsigned long err = ERR_get_error();
                ERR_error_string_n(err, sskt->last_error, sizeof(sskt->last_error));
                log_error(0,
                    "gobj",         "%s", __FILE__,
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                    "msg",          "%s", "SSL_do_handshake() FAILED",
                    "error",        "%s", sskt->last_error,
                    NULL
                );
                sskt->on_handshake_done_cb(sskt->user_data, -1);
            }
            return -1;
        }
    } else {
        if(!sskt->handshake_informed) {
            sskt->handshake_informed = TRUE;
            sskt->on_handshake_done_cb(sskt->user_data, 0);
        }
        return 1;
    }
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int flush_encrypted_data(sskt_t *sskt)
{
    size_t pending;
    while((pending = BIO_ctrl(sskt->network_bio, BIO_CTRL_PENDING, 0, NULL))>0) {
        GBUFFER *gbuf = gbuf_create(pending, pending, 0, 0);
        char *p = gbuf_cur_wr_pointer(gbuf);
        int ret = BIO_read(sskt->network_bio, p, pending);
        if(ret <= 0) {
            log_error(0,
                "gobj",         "%s", __FILE__,
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                "msg",          "%s", "BIO_read() FAILED",
                "ret",          "%d", ret,
                "pending",      "%d", (int)pending,
                NULL
            );
            sskt->on_encrypted_data_cb(sskt->user_data, gbuf, -1);
        } else {
            gbuf_set_wr(gbuf, pending);
            sskt->on_encrypted_data_cb(sskt->user_data, gbuf, 0);
        }
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int encrypt_data(hsskt sskt_, GBUFFER *gbuf)
{
    sskt_t *sskt = sskt_;

    size_t len;
    while((len = gbuf_chunk(gbuf))>0) {
        char *p = gbuf_cur_rd_pointer(gbuf);    // Don't pop data, be sure it's written
        int written = SSL_write(sskt->ssl, p, len);
        if(written <= 0) {
            int detail = SSL_get_error(sskt->ssl, written);
            switch(detail) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                flush_encrypted_data(sskt);
                flush_clear_data(sskt);
                return 0;

            default:
                {
                    unsigned long err = ERR_get_error();
                    ERR_error_string_n(err, sskt->last_error, sizeof(sskt->last_error));
                    log_error(0,
                        "gobj",         "%s", __FILE__,
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                        "msg",          "%s", "SSL_write() FAILED",
                        "error",        "%s", sskt->last_error,
                        NULL
                    );
                    sskt->on_handshake_done_cb(sskt->user_data, -1);
                }
                return -1;
            }
        } else {
            gbuf_get(gbuf, written);    // Pop data
            flush_encrypted_data(sskt);
        }
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int flush_clear_data(sskt_t *sskt)
{
    size_t pending;
    while((pending = SSL_pending(sskt->ssl))>0) {
        GBUFFER *gbuf = gbuf_create(pending, pending, 0, 0);
        char *p = gbuf_cur_wr_pointer(gbuf);
        int consumed = SSL_read(sskt->ssl, p, pending);
        if(consumed <= 0) {
            int detail = SSL_get_error(sskt->ssl, consumed);
            switch(detail) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                flush_encrypted_data(sskt);
                break;

            case SSL_ERROR_NONE:        /* this is not an error */
            case SSL_ERROR_ZERO_RETURN: /* no more data */
                break;

            default:
                {
                    unsigned long err = ERR_get_error();
                    ERR_error_string_n(err, sskt->last_error, sizeof(sskt->last_error));
                    log_error(0,
                        "gobj",         "%s", __FILE__,
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                        "msg",          "%s", "SSL_read() FAILED",
                        "error",        "%s", sskt->last_error,
                        NULL
                    );
                    sskt->on_clear_data_cb(sskt->user_data, gbuf, -1);
                }
                return -1;
            }
        }
        // Callback clear data
        gbuf_set_wr(gbuf, pending);
        sskt->on_clear_data_cb(sskt->user_data, gbuf, 0);
    }
    return 0;
}

/***************************************************************************
    Use this function decrypt encrypted data.
    The clear data will be returned in on_clear_data_cb callback.
 ***************************************************************************/
PRIVATE int decrypt_data(hsskt sskt_, GBUFFER *gbuf)
{
    sskt_t *sskt = sskt_;

    size_t len;
    while((len = gbuf_chunk(gbuf))>0) {
        size_t bytes = BIO_ctrl_get_write_guarantee(sskt->network_bio);
        if(bytes <= 0) {
            break;
        }
        int towrite = MIN(len, bytes);
        char *p = gbuf_cur_rd_pointer(gbuf);    // Don't pop data, be sure it's written

        int written = BIO_write(sskt->network_bio, p, towrite);
        if(written <= 0) {
            break;
        }
        gbuf_get(gbuf, written);    // Pop data

        if(SSL_is_init_finished(sskt->ssl)) {
            flush_clear_data(sskt);
        } else {
            do_handshake(sskt);
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE const char *last_error(hsskt sskt_)
{
    sskt_t *sskt = sskt_;
    return sskt->last_error;
}




            /***************************
             *      Public
             ***************************/




/***************************************************************************
 *  Get api_tls_t
 ***************************************************************************/
PUBLIC api_tls_t *openssl_api_tls(void)
{
    return &api_tls;
}
