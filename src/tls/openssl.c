/***********************************************************************
 *          OPENSSL.C
 *
 *          OpenSSL-specific code for the TLS/SSL layer
 *
 *          Copyright (c) 2018 Niyamaka.
 *          All Rights Reserved.
 *

HOWTO from https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca

Running
-------

Running the program requires that a SSL certificate and private key are
available to be loaded. These can be generated using the 'openssl' program using
these steps:

1. Generate the private key, this is what we normally keep secret:

    openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
    openssl rsa -passin pass:x -in server.pass.key -out server.key
    rm -f server.pass.key

2. Next generate the CSR.  We can leave the password empty when prompted
   (because this is self-sign):

    openssl req -new -key server.key -out server.csr

3. Next generate the self signed certificate:

    openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
    rm -f server.csr

The openssl program can also be used to connect to this program as an SSL
client. Here's an example command (assuming we're using port 55555):

    openssl s_client -connect 127.0.0.1:55555 -msg -debug -state -showcerts


Flow of encrypted & unencrypted bytes
-------------------------------------

This diagram shows how the read and write memory BIO's (rbio & wbio) are
associated with the socket read and write respectively.  On the inbound flow
(data into the program) bytes are read from the socket and copied into the rbio
via BIO_write.  This represents the the transfer of encrypted data into the SSL
object. The unencrypted data is then obtained through calling SSL_read.  The
reverse happens on the outbound flow to convey unencrypted user data into a
socket write of encrypted data.


  +------+                                    +-----+
  |......|--> read(fd) --> BIO_write(rbio) -->|.....|--> SSL_read(ssl)  --> IN
  |......|                                    |.....|
  |.sock.|                                    |.SSL.|
  |......|                                    |.....|
  |......|<-- write(fd) <-- BIO_read(wbio) <--|.....|<-- SSL_write(ssl) <-- OUT
  +------+                                    +-----+

          |                                  |       |                     |
          |<-------------------------------->|       |<------------------->|
          |         encrypted bytes          |       |  unencrypted bytes  |


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
    BOOL server;
    SSL_CTX *ctx;
    BOOL trace;
} ytls_t;

typedef struct sskt_s {
    ytls_t *ytls;
    SSL *ssl;
    //BIO *internal_bio, *network_bio;
    BIO *rbio; /* SSL reads from, we write to. */
    BIO *wbio; /* SSL writes to, we read from. */
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
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
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
    ytls->server = server;
    ytls->ctx = ctx;

    /* the SSL trace callback is only used for verbose logging */
    ytls->trace = kw_get_bool(jn_config, "trace", 0, KW_WILD_NUMBER);

    if(ytls->trace) {
        SSL_CTX_set_msg_callback(ytls->ctx, ssl_tls_trace);
        SSL_CTX_set_msg_callback_arg(ytls->ctx, ytls);
    }

    const char *ssl_certificate = kw_get_str(
        jn_config, "ssl_certificate", "", server?KW_REQUIRED:0
    );
    const char *ssl_certificate_key = kw_get_str(
        jn_config, "ssl_certificate_key", "", server?KW_REQUIRED:0
    );
    const char *ssl_ciphers = kw_get_str(
        jn_config, "ssl_ciphers", "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4", 0
    );
    //const char *ssl_protocols = kw_get_str(jn_config, "ssl_protocols", "", 0); // TODO

    if(SSL_CTX_set_cipher_list(ytls->ctx, ssl_ciphers)<0) {
        unsigned long err = ERR_get_error();
        log_error(0,
            "gobj",         "%s", __FILE__,
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "SSL_CTX_set_cipher_list() FAILED",
            "error",        "%s", ERR_error_string(err, NULL),
            NULL
        );
    }

    if(server) {
        if(SSL_CTX_use_certificate_file(ytls->ctx, ssl_certificate, SSL_FILETYPE_PEM)<0) {
            unsigned long err = ERR_get_error();
            log_error(0,
                "gobj",         "%s", __FILE__,
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "SSL_CTX_use_certificate_chain_file() FAILED",
                "error",        "%s", ERR_error_string(err, NULL),
                NULL
            );
        }
        if(SSL_CTX_use_PrivateKey_file(ytls->ctx, ssl_certificate_key, SSL_FILETYPE_PEM)<0) {
            unsigned long err = ERR_get_error();
            log_error(0,
                "gobj",         "%s", __FILE__,
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "SSL_CTX_use_PrivateKey_file() FAILED",
                "error",        "%s", ERR_error_string(err, NULL),
                NULL
            );
        }
    } else {
        // TODO SSL_set_tlsext_host_name : "yuneta.io"
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

    sskt->rbio = BIO_new(BIO_s_mem());
    sskt->wbio = BIO_new(BIO_s_mem());

    SSL_set_bio(sskt->ssl, sskt->rbio, sskt->wbio);

//     if(BIO_new_bio_pair(&sskt->internal_bio, 0, &sskt->network_bio, 0)!=1) {
//         unsigned long err = ERR_get_error();
//         log_error(0,
//             "gobj",         "%s", __FILE__,
//             "function",     "%s", __FUNCTION__,
//             "msgset",       "%s", MSGSET_SYSTEM_ERROR,
//             "msg",          "%s", "BIO_new_bio_pair() FAILED",
//             "error",        "%s", ERR_error_string(err, NULL),
//             NULL
//         );
//         SSL_free(sskt->ssl);
//         gbmem_free(sskt);
//         return 0;
//     }
//     SSL_set_bio(sskt->ssl, sskt->internal_bio, sskt->internal_bio);

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
    SSL_free(sskt->ssl);   /* free the SSL object and its BIO's */

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
            if(sskt->ytls->trace) {
                trace_msg("------- handshake: %s",
                    detail==SSL_ERROR_WANT_READ?"SSL_WANT_READ":"SSL_WANT_WRITE"
                );
            }
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
    if(sskt->ytls->trace) {
        trace_msg("------- flush_encrypted_data()");
    }

    while(1) {
        int max_size = 4*1024;
        GBUFFER *gbuf = gbuf_create(max_size, max_size, 0, 0);
        char *p = gbuf_cur_wr_pointer(gbuf);
        int ret = BIO_read(sskt->wbio, p, max_size);
        if(sskt->ytls->trace) {
            trace_msg("------- flush_encrypted_data() %d", ret);
        }
        if(ret <= 0) {
            GBUF_DECREF(gbuf);
            break;
        } else {
            gbuf_set_wr(gbuf, ret);
            sskt->on_encrypted_data_cb(sskt->user_data, gbuf, 0);
        }
    }

    //BIO_ctrl_get_read_request
//     long pending;
//     while((pending = BIO_ctrl(sskt->wbio, BIO_CTRL_PENDING, 0, NULL))>0) {
//         if(sskt->ytls->trace) {
//             trace_msg("------- flush_encrypted_data() pending %d", pending);
//         }
//         GBUFFER *gbuf = gbuf_create(pending, pending, 0, 0);
//         char *p = gbuf_cur_wr_pointer(gbuf);
//         int ret = BIO_read(sskt->wbio, p, pending);
//         if(ret <= 0) {
//             log_error(0,
//                 "gobj",         "%s", __FILE__,
//                 "function",     "%s", __FUNCTION__,
//                 "msgset",       "%s", MSGSET_SYSTEM_ERROR,
//                 "msg",          "%s", "BIO_read() FAILED",
//                 "ret",          "%d", ret,
//                 "pending",      "%d", (int)pending,
//                 NULL
//             );
//             sskt->on_encrypted_data_cb(sskt->user_data, gbuf, -1);
//         } else {
//             gbuf_set_wr(gbuf, pending);
//             sskt->on_encrypted_data_cb(sskt->user_data, gbuf, 0);
//         }
//     }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int encrypt_data(
    hsskt sskt_,
    GBUFFER *gbuf // owned
)
{
    sskt_t *sskt = sskt_;

//     if (!SSL_is_init_finished(sskt->ssl)) { TODO
//         return 0;
//     }

    size_t len;
    while((len = gbuf_chunk(gbuf))>0) {
        char *p = gbuf_cur_rd_pointer(gbuf);    // Don't pop data, be sure it's written
        int written = SSL_write(sskt->ssl, p, len);
        if(written <= 0) {
            int ret = SSL_get_error(sskt->ssl, written);
            switch(ret) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                if(sskt->ytls->trace) {
                    trace_msg("------- encrypt_data: %s",
                        ret==SSL_ERROR_WANT_READ?"SSL_WANT_READ":"SSL_WANT_WRITE"
                    );
                }
                flush_encrypted_data(sskt);
                flush_clear_data(sskt);
                GBUF_DECREF(gbuf); // TODO se perderán los datos
                return 0;

            default:
                {
                    unsigned long err = ERR_get_error();
                    ERR_error_string_n(err, sskt->last_error, sizeof(sskt->last_error));
                    log_error(0,
                        "gobj",         "%s", __FILE__,
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                        "msg",          "%s", "BIO_write() FAILED",
                        "error",        "%s", sskt->last_error,
                        NULL
                    );
                    sskt->on_handshake_done_cb(sskt->user_data, -1);
                }
                GBUF_DECREF(gbuf);
                return -1;
            }
            break;
        }
        gbuf_get(gbuf, written);    // Pop data

        //if(SSL_is_init_finished(sskt->ssl)) {
        // if(SSL_in_init
        if(sskt->handshake_informed) {
            if(sskt->ytls->trace) {
                log_debug_dump(0, p, len, "------- ==> encrypt_data DATA");
            }
            gbuf_get(gbuf, written);    // Pop data
            flush_encrypted_data(sskt);
        } else {
            if(sskt->ytls->trace) {
                log_debug_dump(0, p, len, "------- ==> encrypt_data HANDSHAKE");
            }
            do_handshake(sskt);
        }
    }
    GBUF_DECREF(gbuf);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int flush_clear_data(sskt_t *sskt)
{
    if(sskt->ytls->trace) {
        trace_msg("------- flush_clear_data()");
    }
    unsigned long sslerror;

    while(1) {
        int max_size = 4*1024;
        GBUFFER *gbuf = gbuf_create(max_size, max_size, 0, 0);
        char *p = gbuf_cur_wr_pointer(gbuf);
        int nread = SSL_read(sskt->ssl, p, max_size);
        if(sskt->ytls->trace) {
            trace_msg("------- flush_clear_data() %d", nread);
        }
        if(nread <= 0) {
            GBUF_DECREF(gbuf);

            int err = SSL_get_error(sskt->ssl, nread);
            switch(err) {
                case SSL_ERROR_NONE: /* this is not an error */
                    break;
                case SSL_ERROR_ZERO_RETURN: /* no more data */
                    /* close_notify alert */
                    //connclose(conn, "TLS close_notify");
                    break;
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    break;
                default:
                    /* openssl/ssl.h for SSL_ERROR_SYSCALL says "look at error stack/return
                        value/errno" */
                    /* https://www.openssl.org/docs/crypto/ERR_get_error.html */
                    sslerror = ERR_get_error();
                    if((nread < 0) || sslerror) {
                        /* If the return code was negative or there actually is an error in the
                        queue */
                        return -1;
                    }
                    break;
            }
            break;
        }

        // Callback clear data
        gbuf_set_wr(gbuf, nread);
        sskt->on_clear_data_cb(sskt->user_data, gbuf, 0);
    }
    return 0;
}

/***************************************************************************
    Use this function decrypt encrypted data.
    The clear data will be returned in on_clear_data_cb callback.
 ***************************************************************************/
PRIVATE int decrypt_data(
    hsskt sskt_,
    GBUFFER *gbuf // owned
)
{
    sskt_t *sskt = sskt_;

    size_t len;
    while((len = gbuf_chunk(gbuf))>0) {
        char *p = gbuf_cur_rd_pointer(gbuf);    // Don't pop data, be sure it's written

        int written = BIO_write(sskt->rbio, p, len);
        if(written <= 0) {
            GBUF_DECREF(gbuf); // TODO se pierden datos
            return -1;
        }

        gbuf_get(gbuf, written);    // Pop data

        if(SSL_is_init_finished(sskt->ssl)) {
        //if(sskt->handshake_informed) {
            if(sskt->ytls->trace) {
                log_debug_dump(0, p, len, "------- <== decrypt_data DATA");
            }
            flush_clear_data(sskt);
        } else {
            if(sskt->ytls->trace) {
                log_debug_dump(0, p, len, "------- <== decrypt_data HANDSHAKE");
            }
            do_handshake(sskt);
        }
    }
    GBUF_DECREF(gbuf);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE const char *last_error(hsskt sskt_)
{
    sskt_t *sskt = sskt_;
    if(!sskt) {
        return "???";
    }
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
