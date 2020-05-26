/*
* The MIT License (MIT)
*
* Copyright (c) 2019 Sylko Olzscher
*
*/

#include <crypto/algorithm/hmacsha.h>
#include <algorithm>
#include <vector>

namespace cyng 
{
	namespace crypto
	{
		namespace algorithm
		{
			hmacsha::hmacsha(std::string key
				, const EVP_MD* (*md)()
				, const std::string& name)
			: base(name)
				, secret_(std::move(key))
				, md_(md)
			{}

			/**
			 * Sign jwt data
			 * @param data The data to sign
			 * @return HMAC signature for the given data
			 * @throws signature_generation_exception
			 */
			std::string hmacsha::sign(const std::string& data) const 
			{
				std::vector<unsigned char> vec;
				vec.resize(EVP_MAX_MD_SIZE);	// 64

				unsigned int len = static_cast<unsigned int>(vec.size());

				//
				//	computes the message authentication code of the n 
				//	bytes at d using the hash function evp_md and the key key which is key_len bytes long.
				//	unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,	const unsigned char* d, size_t n, unsigned char* md, unsigned int* md_len);
				//
				auto const p = HMAC(
					md_(),	//	generator
					secret_.data(), //	[key]
					static_cast<int>(secret_.size()), //	[key_len]
					(const unsigned char*)data.data(),	//	data
					data.size(), //	[n] - byte count
					vec.data(), //	[md] - output
					&len);

				if (p== nullptr)	throw "signature_generation_exception()";

				return std::string(vec.begin(), vec.begin() + len);
			}

			/**
			 * Check if signature is valid
			 * @param data The data to check signature against
			 * @param signature Signature provided by the jwt
			 * @throws signature_verification_exception If the provided signature does not match
			 */
			void hmacsha::verify(const std::string& data, const std::string& signature) const 
			{
				try {
					auto res = sign(data);
					bool matched = true;

					for (size_t idx = 0; idx < std::min<size_t>(res.size(), signature.size()); ++idx) {
						if (res[idx] != signature[idx]) {
							matched = false;
						}
					}
					if (res.size() != signature.size()) {
						matched = false;
					}
					if (!matched)
						throw "signature_verification_exception()";
				}
				catch (const std::string& s) {
					//throw signature_verification_exception();
					throw s;
				}
				//catch (const signature_generation_exception&) {
				//	throw signature_verification_exception();
				//}
			}


			hs256::hs256(std::string key)
				: hmacsha(std::move(key), EVP_sha256, "HS256")
			{}

			hs384::hs384(std::string key)
				: hmacsha(std::move(key), EVP_sha384, "HS384")
			{}

			hs512::hs512(std::string key)
				: hmacsha(std::move(key), EVP_sha512, "HS512")
			{}

		}
	}
}
