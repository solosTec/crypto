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

namespace cyng
{
	namespace crypto
	{
        /**
         * Convert a BIGNUM to a std::string
         */
        std::string to_str(BIGNUM const*);

        /**
         * Convert an std::string to a BIGNUM
         */
        BN_ptr create_bignum(std::string const&);
	}
}

#endif	

