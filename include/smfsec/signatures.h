/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_EVP_H
#define CYNG_CRYPTO_EVP_H

#include <smfsec/crypto.h>
#include <vector>
#include <string>

namespace cyng
{
	namespace crypto
	{
		/**
		 * high level interface to sign digital signatures.
		 */
		class evp_sign
		{
		public:
			/**
			 * @param type digest type
			 */
			evp_sign(EVP_MD const* type);

			void update(std::string const& data);
			void update(std::vector<unsigned char> const& data);

			std::string finalize(EVP_PKEY* pkey);

		private:
			void init(EVP_MD const* type);
		private:
			EVP_MD_CTX_ptr ctx_;
		};

		/**
		 * high level interface to verify digital signatures.
		 */
		class evp_verify
		{
		public:
			/**
			 * @param type digest type
			 */
			evp_verify(EVP_MD const* type);

			void update(std::string const& data);
			void update(std::vector<unsigned char> const& data);

			bool finalize(EVP_PKEY* pkey, std::string const& signature);
			bool finalize(EVP_PKEY* pkey, std::vector<unsigned char> const& signature);

		private:
			void init(EVP_MD const* type);
		private:
			EVP_MD_CTX_ptr ctx_;
		};

		/**
		 * High level interface to message digest.
		 * Should be used instead of the cipher-specific functions
		 */
		class evp_digest
		{
		public:
			/**
			 * @param type digest type
			 */
			evp_digest(EVP_MD const* type);

			void update(std::string const& data);
			void update(std::vector<unsigned char> const& data);

			std::string finalize();

		private:
			void init(EVP_MD const* type);

		private:
			EVP_MD_CTX_ptr ctx_;
		};

		/** 
		 * @return the maximum size of a signature in bytes. 
		 * The actual signature returned by EVP_SignFinal() may be smaller.
		 */
		std::size_t get_evp_key_size(EVP_PKEY* pkey);

		/**
		 * @return Return the size of the message digest.
		 */
		std::size_t get_evp_digest_size(EVP_MD_CTX* ctx);

		/**
		 * Similar to ECDSA_sign() except the signature is returned 
		 * as a newly allocated ECDSA_SIG structure (or NULL on error).
		 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
		ECDSA_SIG_ptr do_sign(std::string const& data, EC_KEY* eckey);
		ECDSA_SIG_ptr do_sign(std::vector<unsigned char> const& data, EC_KEY* eckey);
#endif
	}
}

#endif	

