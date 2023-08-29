/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_PKCS7_H
#define CYNG_CRYPTO_PKCS7_H

#include <smfsec/crypto.h>

#include <smfsec/crypto.h>

namespace cyng {
    namespace crypto {
        namespace pkcs7 {
            PKCS7_ptr encrypt(BIO *in, x509::set const &, EVP_CIPHER *);
            void decrypt(BIO *in);
            void to_PEM(BIO *out, PKCS7 *p7);
        } // namespace pkcs7
    }     // namespace crypto
} // namespace cyng

#endif
