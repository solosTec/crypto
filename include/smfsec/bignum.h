/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_ERROR_H
#define CYNG_CRYPTO_ERROR_H

#include <smfsec/crypto.h>
#include <string>

namespace cyng
{
	namespace crypto
	{
        /**
         * Convert a BIGNUM to a std::string
         */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        std::string to_str(BIGNUM*);
#else
        std::string to_str(BIGNUM const*);
#endif

        /**
         * Convert an std::string to a BIGNUM
         */
        BN_ptr create_bignum(std::string const&);
	}
}

#endif	

