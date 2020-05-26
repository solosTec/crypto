/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

/**@file jwt.h
 * @see https://jwt.io/
 */
#ifndef CYNG_CRYPTO_JWT_H
#define CYNG_CRYPTO_JWT_H

#include <crypto/crypto.h>
#include <string>

namespace cyng
{
	namespace crypto
	{
		/**
		 * ...
		 */
		std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw = "");

		EVP_PKEY_ptr load_public_key_from_string(const std::string& key, const std::string& passphrase = "");

	}
}

#endif	

