/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#include <smfsec/factory.h>

#include <smfsec/bio.h>

#include <assert.h>
#include <boost/assert.hpp>

namespace cyng {
    namespace crypto {
        BN_ptr create_bignum() { return BN_ptr(BN_new(), BN_free); }

        BN_ptr create_bignum_from_hex(std::string s) {
            auto p = create_bignum();
            BIGNUM *bn = p.get();
            auto const r = BN_hex2bn(&bn, s.c_str());
            return p;
        }

        BN_ptr create_bignum_rsa_f4() {
            auto p = create_bignum();
            auto ret = BN_set_word(p.get(), RSA_F4);
            assert(ret == 1);
            return p;
        }

        X509_ptr create_x509(long v) {
            BOOST_ASSERT_MSG(v <= X509_VERSION_3, "invalid X509 version");
            auto p = X509_ptr(X509_new(), X509_free);
            X509_set_version(p.get(), v);
            return p;
        }

        X509_ptr create_x509(const std::string &certstr, const std::string &pw) {
            auto certbio = create_bio_str(certstr);
            X509 *x509 = PEM_read_bio_X509(certbio.release(), nullptr, nullptr, const_cast<char *>(pw.c_str()));
            return X509_ptr(x509, X509_free);
        }

        RSA_ptr create_rsa() { return RSA_ptr(::RSA_new(), ::RSA_free); }

        RSA_ptr create_rsa_key(BIGNUM *bnp, int bits) {
            auto p = create_rsa();
            auto ret = RSA_generate_key_ex(p.release(), bits, bnp, NULL);
            assert(ret == 1);
            return p;
        }

        RSA_ptr create_rsa_key(EVP_PKEY *key) {
            return (key != nullptr) ? RSA_ptr(::EVP_PKEY_get1_RSA(key), ::RSA_free) : create_rsa();
        }

        X509_REQ_ptr create_x509_request(int v) {
            auto p = X509_REQ_ptr(X509_REQ_new(), X509_REQ_free);
            auto ret = X509_REQ_set_version(p.get(), v);
            assert(ret == 1);
            return p;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L

        EVP_PKEY_ptr create_evp_pkey() { return EVP_PKEY_ptr(EVP_PKEY_new(), EVP_PKEY_free); }

        EVP_PKEY_ptr create_evp_pkey(X509 *x509) {
            assert(x509 != nullptr);
            return EVP_PKEY_ptr(X509_get_pubkey(x509), EVP_PKEY_free);
        }

        EC_KEY_ptr create_ec_key() { return EC_KEY_ptr(EC_KEY_new(), EC_KEY_free); }

        EC_KEY_ptr create_ec_pub_key(BIO *bio, std::string pub_pwd) {
            return EC_KEY_ptr(::PEM_read_bio_EC_PUBKEY(bio, nullptr, nullptr, const_cast<char *>(pub_pwd.c_str())), ::EC_KEY_free);
        }

        EC_KEY_ptr create_ec_priv_key(BIO *bio, std::string priv_pwd) {
            return EC_KEY_ptr(
                ::PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, const_cast<char *>(priv_pwd.c_str())), ::EC_KEY_free);
        }

#endif

        EVP_MD_CTX_ptr create_evp_ctx() {
            // If openssl version less than 1.1
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            return EVP_MD_CTX_ptr(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
            return EVP_MD_CTX_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
        }

        SSL_CTX_ptr create_ssl_ctx() { return SSL_CTX_ptr(nullptr, SSL_CTX_free); }

        SSL_CTX_ptr create_ssl_ctx_v23() { return SSL_CTX_ptr(SSL_CTX_new(SSLv23_method()), SSL_CTX_free); }

        SSL_CTX_ptr create_ssl_ctx_v23_client() { return SSL_CTX_ptr(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free); }

        SSL_CTX_ptr create_ssl_ctx_v23_server() { return SSL_CTX_ptr(SSL_CTX_new(SSLv23_server_method()), SSL_CTX_free); }

        SSL_CTX_ptr create_ssl_ctx_dtls() { return SSL_CTX_ptr(SSL_CTX_new(DTLS_method()), SSL_CTX_free); }

        SSLptr create_ssl(SSL_CTX *ctx) { return SSLptr(SSL_new(ctx), SSL_free); }

        ASN1_TIME_ptr create_asn1_time() { return ASN1_TIME_ptr(ASN1_TIME_new(), ASN1_STRING_free); }

        bool add_entry_by_txt(X509_NAME *x509_name, const char *subject, const char *txt) {
            auto const ret = X509_NAME_add_entry_by_txt(x509_name, subject, MBSTRING_ASC, (const unsigned char *)txt, -1, -1, 0);
            return ret == 1;
        }

        ECDSA_SIG_ptr create_ecdsa_sig() { return ECDSA_SIG_ptr(::ECDSA_SIG_new(), ::ECDSA_SIG_free); }

    } // namespace crypto
} // namespace cyng
