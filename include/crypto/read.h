/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_READ_H
#define CYNG_CRYPTO_READ_H

#include <crypto/crypto.h>

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
		 */
		RSA_ptr load_private_key(const char* filename);

		/**
		 * load (CA) private key (without password)
		 */
		EVP_PKEY_ptr load_CA_private_key(const char* filename);

		/**
		 * load X509 certificate request (without password)
		 */
		X509_REQ_ptr load_x509_request(const char* filename);

	}
}

#endif	

