/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_PRINT_H
#define CYNG_CRYPTO_PRINT_H

#include <smfsec/crypto.h>

namespace cyng
{
	namespace crypto
	{
		bool print_stdout_public(EVP_PKEY*);
		bool print_stdout_private(EVP_PKEY*);
		bool print_stdout_params(EVP_PKEY*);

		bool print_stdout_X509(X509 const*);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		/**
		 * RSA* pointer not longer supported
		 */
		bool print_stdout_RSA(RSA*);
#endif

		bool dump_evp(const char* filename);
		bool dump_x509(const char* filename);
	}
}

#endif	

