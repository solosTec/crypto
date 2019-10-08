/*
* The MIT License (MIT)
*
* Copyright (c) 2019 Sylko Olzscher
*
*/

#include <cyng/factory.h>
#include <assert.h>

namespace cyng 
{
	namespace crypto
	{
		BN_ptr create_bignum()
		{
			return BN_ptr(BN_new(), BN_free);
		}

		BN_ptr create_bignum_rsa_f4()
		{
			auto p = create_bignum();
			auto ret = BN_set_word(p.get(), RSA_F4);
			assert(ret == 1);
			return p;
		}

		RSA_ptr create_rsa()
		{
			return RSA_ptr(RSA_new(), RSA_free);
		}

		RSA_ptr create_rsa_key(BIGNUM* bnp, int bits)
		{
			auto p = create_rsa();
			auto ret = RSA_generate_key_ex(p.get(), bits, bnp, NULL);
			assert(ret == 1);
			return p;
		}

		X509_ptr create_x509(long v)
		{
			auto p = X509_ptr(X509_new(), X509_free);
			X509_set_version(p.get(), v);
			return p;
		}

		X509_REQ_ptr create_x509_request(int v)
		{
			auto p = X509_REQ_ptr(X509_REQ_new(), X509_REQ_free);
			auto ret = X509_REQ_set_version(p.get(), v);
			assert(ret == 1);
			return p;
		}

		EVP_PKEY_ptr create_evp_pkey()
		{
			return EVP_PKEY_ptr(EVP_PKEY_new(), EVP_PKEY_free);
		}

		EVP_MD_CTX_ptr create_evp_ctx()
		{
			return EVP_MD_CTX_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);
		}

		SSL_CTX_ptr create_ssl_ctx()
		{
			return SSL_CTX_ptr(nullptr, SSL_CTX_free);
		}

		SSL_CTX_ptr create_ssl_ctx_v23()
		{
			return SSL_CTX_ptr(SSL_CTX_new(SSLv23_method()), SSL_CTX_free);
		}

		SSL_CTX_ptr create_ssl_ctx_v23_client()
		{
			return SSL_CTX_ptr(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);
		}

		SSL_CTX_ptr create_ssl_ctx_v23_server()
		{
			return SSL_CTX_ptr(SSL_CTX_new(SSLv23_server_method()), SSL_CTX_free);
		}

		SSL_CTX_ptr create_ssl_ctx_dtls()
		{
			return SSL_CTX_ptr(SSL_CTX_new(DTLS_method()), SSL_CTX_free);
		}


		SSLptr create_ssl(SSL_CTX* ctx)
		{
			return SSLptr(SSL_new(ctx), SSL_free);
		}

		ASN1_TIME_ptr create_asn1_time()
		{
			return ASN1_TIME_ptr(ASN1_TIME_new(), ASN1_STRING_free);
		}

		bool add_entry_by_txt(X509_NAME* x509_name, const char* subject, const char* txt)
		{
			auto const ret = X509_NAME_add_entry_by_txt(x509_name, subject, MBSTRING_ASC, (const unsigned char*)txt, -1, -1, 0);
			return ret == 1;
		}

	}
}
