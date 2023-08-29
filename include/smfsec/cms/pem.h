/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_PEM_H
#define CYNG_CRYPTO_PEM_H

#include <smfsec/crypto.h>

namespace cyng {
    namespace crypto {
        namespace pem {
            X509_ptr read_x509(const char *file_name);
            X509_ptr read_x509(FILE *fp);

            PKCS7_ptr read_pkcs7(const char *file_name);
            PKCS7_ptr read_pkcs7(FILE *fp);

            /**
             * @see https://www.openssl.org/docs/man1.1.1/man3/PEM_read_PrivateKey.html
             */
            EVP_PKEY_ptr read_private_key(const char *file_name);
            EVP_PKEY_ptr read_private_key(FILE *fp);
            EVP_PKEY_ptr read_private_key(BIO *);

        } // namespace pem
    }     // namespace crypto
} // namespace cyng

#endif
