/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_WRITE_H
#define CYNG_CRYPTO_WRITE_H

#include <crypto/crypto.h>

namespace cyng
{
	namespace crypto
	{
		/**
		 * Writing a private key to disk without a passphrase and encryption
		 */
		bool write_private_key(RSA*, const char* file_name);
		bool write_private_key(EVP_PKEY*, const char* file_name);

		/**
		 * Writing a public key to disk.
		 */
		bool write_public_key(RSA*, const char* file_name);

		/**
		 * Writing certificate to disk.
		 */
		bool write_certificate(X509* x509, const char* file_name);

	}
}

#endif	

