/*
* The MIT License (MIT)
*
* Copyright (c) 2020 Sylko Olzscher
*
*/

#include <smfsec/bignum.h>
#include <openssl/bn.h>
#include <vector>

namespace cyng 
{
	namespace crypto
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		std::string to_str(BIGNUM* p)
#else
		std::string to_str(BIGNUM const* p)
#endif
		{
			if (p != nullptr) {
				std::vector<unsigned char> vec;
				vec.resize(BN_num_bytes(p));	//	macro
				BN_bn2bin(p, vec.data());
				return std::string(vec.begin(), vec.end());
			}
			return std::string{};
		}

		BN_ptr create_bignum(std::string const& str)
		{
			return BN_ptr(BN_bin2bn((const unsigned char*)str.data(), static_cast<int>(str.size()), nullptr), BN_free);
		}

	}
}
