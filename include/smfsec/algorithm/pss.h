/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_ALGO_PSS_H
#define CYNG_CRYPTO_ALGO_PSS_H

#include <smfsec/algorithm/none.h>
#include <smfsec/crypto.h>

namespace cyng
{
	namespace crypto
	{
		EVP_PKEY_ptr create_evp_key(const std::string& public_key
			, const std::string& private_key
			, const std::string& public_key_password
			, const std::string& private_key_password);

		namespace algorithm
		{
			/**
			 * PSS-RSA family of algorithms
			 */
			class pss : public base
			{
			public:
				/**
				 * Construct new pss algorithm
				 * @param public_key RSA public key in PEM format
				 * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 * @param md Pointer to hash function
				 * @param name Name of the algorithm
				 */
				pss(const std::string& public_key
					, const std::string& private_key
					, const std::string& public_key_password
					, const std::string& private_key_password
					, const EVP_MD* (*md)()
					, const std::string& name);

				/**
				 * @return empty string
				 */
				virtual std::string sign(const std::string&) const override;

				/**
				 * Check if the given signature is empty. JWT's with "none" algorithm should not contain a signature.
				 */
				virtual void verify(const std::string&, const std::string& signature) const override;

			private:
				std::string generate_hash(std::string const& data) const;

			private:
				/**
				 * structure containing keys
				 */
				EVP_PKEY_ptr pkey_;

				/**
				 * HMAC hash generator
				 */
				const EVP_MD* (*md_)();
			};

			/**
			 * PS256 algorithm
			 */
			struct ps256 : public pss {
				/**
				 * Construct new instance of algorithm
				 * @param public_key RSA public key in PEM format
				 * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit ps256(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
			/**
			 * PS384 algorithm
			 */
			struct ps384 : public pss {
				/**
				 * Construct new instance of algorithm
				 * @param public_key RSA public key in PEM format
				 * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit ps384(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
			/**
			 * PS512 algorithm
			 */
			struct ps512 : public pss {
				/**
				 * Construct new instance of algorithm
				 * @param public_key RSA public key in PEM format
				 * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit ps512(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
		}
	}
}

#endif	

