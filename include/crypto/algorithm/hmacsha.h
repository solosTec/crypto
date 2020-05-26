/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_ALGO_HMACSHA_H
#define CYNG_CRYPTO_ALGO_HMACSHA_H

#include <crypto/crypto.h>
#include <crypto/algorithm/none.h>

namespace cyng
{
	namespace crypto
	{
		namespace algorithm
		{
			class hmacsha : public base
			{
			public:
				/**
				 * Construct new hmac algorithm
				 * @param key Key to use for HMAC
				 * @param md Pointer to hash function
				 * @param name Name of the algorithm
				 */
				hmacsha(std::string key, const EVP_MD* (*md)(), const std::string& name);

				/**
				 * Sign jwt data
				 * @param data The data to sign
				 * @return HMAC signature for the given data
				 * @throws signature_generation_exception
				 */
				virtual std::string sign(const std::string& data) const override;

				/**
				 * Check if signature is valid
				 * @param data The data to check signature against
				 * @param signature Signature provided by the jwt
				 * @throws signature_verification_exception If the provided signature does not match
				 */
				virtual void verify(const std::string& data, const std::string& signature) const override;

			private:
				/**
				 * HMAC secrect
				 */
				std::string const secret_;

				/**
				 * HMAC hash generator
				 */
				EVP_MD const* (*md_)();

			};

			/**
			 * HS256 algorithm
			 */
			class hs256 : public hmacsha
			{
			public:
				/**
				 * Construct new instance of algorithm
				 * @param key HMAC signing key
				 */
				explicit hs256(std::string key);
			};

			/**
			 * HS384 algorithm
			 */
			struct hs384 : public hmacsha 
			{
			public:
				/**
				 * Construct new instance of algorithm
				 * @param key HMAC signing key
				 */
				explicit hs384(std::string key);
			};

			/**
			 * HS512 algorithm
			 */
			struct hs512 : public hmacsha 
			{
				/**
				 * Construct new instance of algorithm
				 * @param key HMAC signing key
				 */
				explicit hs512(std::string key);
			};
		}
	}
}

#endif	

