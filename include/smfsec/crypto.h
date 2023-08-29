/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_H
#define CYNG_CRYPTO_H

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <openssl/opensslv.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h> //	bignum
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>

namespace cyng {
    namespace crypto {
        /**
         * A return value of 1 indicates success.
         */
        constexpr int OK = 1;

        /**
         * Use RAII to free all pointers automatically.
         */
        using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
        using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;

        /**
         * EVP_PKEY objects are used to store a public key and (optionally) a private key,
         * along with an associated algorithm and parameters. They are also capable of storing
         * symmetric MAC keys.
         * @see https://wiki.openssl.org/index.php/EVP
         */
        using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

#if OPENSSL_VERSION_NUMBER > 0x30000000L

        /**
         * EVP_CIPHER is a structure for cipher method implementation.
         *
         * @see https://www.openssl.org/docs/man3.1/man3/EVP_Cipher.html
         */
        using EVP_CIPHER_ptr = std::unique_ptr<EVP_CIPHER, decltype(&::EVP_CIPHER_free)>;
#endif

        /**
         * An EC_KEY represents a public key and, optionally, the associated private key.
         */
        using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&::EC_KEY_free)>;

        using BIO_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
        using BIO_ADDR_ptr = std::unique_ptr<BIO_ADDR, decltype(&::BIO_ADDR_free)>;

        using BIO_ptr_all = std::unique_ptr<BIO, decltype(&::BIO_free_all)>;
        using BIO_METHOD_ptr = std::unique_ptr<BIO_METHOD, decltype(&::BIO_meth_free)>;

        /**
         *  Represents an x509 certificate in memory.
         */
        using X509_ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
        using X509_REQ_ptr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
        // using X509_NAME_ptr = std::unique_ptr<X509_NAME, decltype(&::???)>;
        using X509_STORE_ptr = std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>;

        /**
         *  Represents an PKCS #7 certificate
         */
        using PKCS7_ptr = std::unique_ptr<PKCS7, decltype(&::PKCS7_free)>;

        using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)>;

        /**
         * An SSL structure is reference counted. Creating an SSL structure
         * for the first time increments the reference count. Freeing it (using SSL_free)
         * decrements it.
         */
        using SSLptr = std::unique_ptr<SSL, decltype(&::SSL_free)>;

        using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;

        using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;

        using X509_EXTENSION_ptr = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;

        /**
         * ECDSA_SIG is an opaque structure consisting of two BIGNUMs for the r and s value of an
         * ECDSA signature (see X9.62 or FIPS 186-2).
         */
        using ECDSA_SIG_ptr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

        /**
         *  struct stack_st_X509
         */
        using X509_SET = stack_st_X509;
        // using X509_SET = STACK_OF(X509);
        namespace x509 {
            class set;
        }
    } // namespace crypto
} // namespace cyng
#endif
