/*
* The MIT License (MIT)
*
* Copyright (c) 2019 Sylko Olzscher
*
*/

#include <smfsec/write.h>
#include <smfsec/factory.h>
#include <smfsec/read.h>
#include <smfsec/bio.h>
#include <smfsec/print.h>

namespace cyng 
{
	namespace crypto
	{
		bool write_private_key(RSA* rsa, const char* file_name)
		{
			auto bio_privp = create_bio_file(file_name, "w+");
			if (!bio_privp) return false;

			auto ret = PEM_write_bio_RSAPrivateKey(
				bio_privp.get(), //	file
				rsa,	//	the private key
				NULL,	//	default cipher for encrypting the key on disk (EVP_des_ede3_cbc)
				NULL,	//	passphrase
				0,		//	length of passphrase
				NULL,	//	callback for requesting the password
				NULL);	//	data to pass to the callback
			return ret == 1;
		}

		bool write_private_key(EVP_PKEY* pkey, const char* file_name)
		{
			auto bio_privp = create_bio_file(file_name, "w+");
			if (!bio_privp) return false;

			auto ret = PEM_write_bio_PrivateKey(
				bio_privp.get(), //	file
				pkey,	//	the private key
				NULL,	//	default cipher for encrypting the key on disk (EVP_des_ede3_cbc)
				NULL,	//	passphrase
				0,		//	length of passphrase
				NULL,	//	callback for requesting the password
				NULL);	//	data to pass to the callback
			return ret == 1;
		}

		bool write_certificate(X509* x509, const char* file_name)
		{
			auto bio_privp = create_bio_file(file_name, "w+");
			if (!bio_privp) return false;
			auto ret = PEM_write_bio_X509(bio_privp.get(), x509);
			return ret == 1;
		}

		bool write_public_key(RSA* rsa, const char* file_name)
		{
			auto biop = create_bio_file(file_name, "w+");
			if (!biop) return false;
			auto ret = PEM_write_bio_RSAPublicKey(biop.get(), rsa);
			if (ret != OK)	return false;
			return true;
		}
	}
}
