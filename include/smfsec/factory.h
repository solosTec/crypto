/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_FACTORY_H
#define CYNG_CRYPTO_FACTORY_H

#include <boost/asio.hpp>
#include <smfsec/crypto.h>
#include <string>

namespace cyng {
    namespace crypto {
        /**
         * create a bignum structure
         */
        BN_ptr create_bignum();
        BN_ptr create_bignum_from_hex(std::string);
        BN_ptr create_bignum_rsa_f4();

        /**
         * provide a X509 structure.
         * Represents an x509 certificate in memory.
         * A value of 2 stands for version 1.3, a value of 1 encodes
         * version 1.2.
         * The values of these constants are defined by standards (X.509 et al)
         * to be one less than the certificate version. So X509_VERSION_3 has
         * value 2 and X509_VERSION_1 has value 0.
         *
         * @param v version (usually == 2)
         */
        X509_ptr create_x509(long v);

        /**
         * Create a X509 from a certificate string and password
         */
        X509_ptr create_x509(const std::string &certstr, const std::string &pw);

        /**
         * create an empty RSA structure
         */
        RSA_ptr create_rsa();

        /**
         * create a RSA key with the specified size (typically 1024 or 2048)
         */
        RSA_ptr create_rsa_key(BIGNUM *, int bits);

        /**
         * Create RSA key from EVP structure
         */
        RSA_ptr create_rsa_key(EVP_PKEY *);

        /**
         * create a x509 request structure
         *
         * @param v version (mostly 1)
         */
        X509_REQ_ptr create_x509_request(int v);

#if OPENSSL_VERSION_NUMBER < 0x10100000L

        /**
         * create a key store
         */
        EVP_PKEY_ptr create_evp_pkey();

        /**
         * decode the public key for a certificate
         */
        EVP_PKEY_ptr create_evp_pkey(X509 *x509);

        /**
         * Hold a public and optionally a private key.
         * Contains no associated curve.
         */
        EC_KEY_ptr create_ec_key();

        /**
         * PEM_read_bio_EC_PUBKEY
         */
        EC_KEY_ptr create_ec_pub_key(BIO *, std::string pwd);

        /**
         * PEM_read_bio_ECPrivateKey
         */
        EC_KEY_ptr create_ec_priv_key(BIO *, std::string pwd);

#endif

        /**
         * create a signing context
         */
        EVP_MD_CTX_ptr create_evp_ctx();

        /**
         * create an SSL context
         * The supported protocols are SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2.
         */
        SSL_CTX_ptr create_ssl_ctx();
        SSL_CTX_ptr create_ssl_ctx_v23();
        SSL_CTX_ptr create_ssl_ctx_v23_client();
        SSL_CTX_ptr create_ssl_ctx_v23_server();
        SSL_CTX_ptr create_ssl_ctx_dtls();

        SSLptr create_ssl(SSL_CTX *);

        /**
         * Pointer is initialized with ASN1_TIME_new().
         *
         * @return pointer to ASN1_TIME
         */
        ASN1_TIME_ptr create_asn1_time();

        /**
         * helper function to populate a x509_name structure.
         *
         * @param subject entry name
         * @param txt text/value of this entry
         */
        bool add_entry_by_txt(X509_NAME *, const char *subject, const char *txt);

        /**
         * ECDSA_SIG is an opaque structure consisting of two BIGNUMs for the r and s
         * value of an ECDSA signature (see X9.62 or FIPS 186-2).
         */
        ECDSA_SIG_ptr create_ecdsa_sig();

        BIO_ptr create_connection();
    } // namespace crypto
} // namespace cyng

#endif
