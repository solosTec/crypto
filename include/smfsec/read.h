/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_READ_H
#define CYNG_CRYPTO_READ_H

#include <smfsec/crypto.h>
#include <string>

namespace cyng
{
	namespace crypto
	{	 
		/**
		 * load a CA from the specified file
		 */
		X509_ptr load_CA(const char* filename);

		/**
		 * Read a private key and create an RSA pointer.
		 * Raw RSA* pointer not longer supported
		 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		RSA_ptr load_private_key(const char* filename);
#endif

		/**
		 * load (CA) private key (without password)
		 */
		EVP_PKEY_ptr load_CA_private_key(const char* filename);

		/**
		 * read public key in PEM format
		 */
		EVP_PKEY_ptr read_pub_key(BIO*, std::string passphrase);

		/**
		 * read private key in PEM format
		 */
		EVP_PKEY_ptr read_priv_key(BIO*, std::string passphrase);

		/**
		 * load X509 certificate request (without password)
		 */
		X509_REQ_ptr load_x509_request(const char* filename);

	}
}

#endif	

