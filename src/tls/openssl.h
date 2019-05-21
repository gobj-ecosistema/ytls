/****************************************************************************
 *          OPENSSL.H
 *
 *          OpenSSL-specific code for the TLS/SSL layer
 *
 *          Copyright (c) 2018 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/

#ifndef _C_OPENSSL_H
#define _C_OPENSSL_H 1

#include <ghelpers.h>

#ifdef __cplusplus
extern "C"{
#endif

/***************************************************************
 *              Prototypes
 ***************************************************************/

/**rst**
   Get api_tls_t
**rst**/
PUBLIC api_tls_t *openssl_api_tls(void);

#ifdef __cplusplus
}
#endif

#endif
