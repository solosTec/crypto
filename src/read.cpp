/*
* The MIT License (MIT)
*
* Copyright (c) 2018 Sylko Olzscher
*
*/

#include <crypto/read.h>
#include <crypto/factory.h>
#include <crypto/bio.h>
#include <crypto/print.h>

namespace cyng 
{
	namespace crypto
	{

		X509_ptr load_CA(const char* filename)
		{
			X509* x509p = nullptr;
			auto biop = create_bio_file(filename, "r");
			PEM_read_bio_X509(biop.get(), &x509p, NULL, NULL);
			return X509_ptr(x509p, X509_free);
		}

		X509_REQ_ptr load_x509_request(const char* filename)
		{
			X509_REQ* x509_reqp = nullptr;
			auto biop = create_bio_file(filename, "r");
			PEM_read_bio_X509_REQ(biop.get(), &x509_reqp, NULL, NULL);
			return X509_REQ_ptr(x509_reqp, X509_REQ_free);
		}

		RSA_ptr load_private_key(const char* filename)
		{
			RSA* rsa = nullptr;
			auto biop = create_bio_file(filename, "r");
			PEM_read_bio_RSAPrivateKey(biop.get(), &rsa, NULL, NULL);
#ifdef _DEBUG
			print_stdout_RSA(rsa);
#endif

			return RSA_ptr(rsa, RSA_free);
		}

		EVP_PKEY_ptr load_CA_private_key(const char* filename)
		{
			auto rsap = load_private_key(filename);
			auto evp_pkeyp = create_evp_pkey();

			//
			//	EVP_PKEY manages lifetime of RSA structure
			//
			EVP_PKEY_assign_RSA(evp_pkeyp.get(), rsap.release());
			return evp_pkeyp;
		}

		EVP_PKEY_ptr read_pub_key(BIO* p, std::string passphrase)
		{
			return EVP_PKEY_ptr(::PEM_read_bio_PUBKEY(p, nullptr, nullptr, (void*)passphrase.c_str()), EVP_PKEY_free);
		}

		EVP_PKEY_ptr read_priv_key(BIO* p, std::string passphrase)
		{
			return EVP_PKEY_ptr(::PEM_read_bio_PrivateKey(p, nullptr, nullptr, (void*)passphrase.c_str()), EVP_PKEY_free);
		}

	}
}
