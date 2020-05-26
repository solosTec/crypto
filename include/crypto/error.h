/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_ERROR_H
#define CYNG_CRYPTO_ERROR_H

#include <crypto/crypto.h>
#include <string>
#include <openssl/err.h>

namespace cyng
{
	namespace crypto
	{
        /**
         * not thread safe
         */
        std::string get_error_msg();
	}
}

#endif	

