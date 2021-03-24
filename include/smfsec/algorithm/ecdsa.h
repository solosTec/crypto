/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_ALGO_ECDSA_H
#define CYNG_CRYPTO_ALGO_ECDSA_H

#include <smfsec/algorithm/none.h>
#include <smfsec/crypto.h>

namespace cyng
{
	namespace crypto
	{
		EC_KEY_ptr create_ec_key(const std::string& public_key
			, const std::string& private_key
			, const std::string& public_key_password
			, const std::string& private_key_password
			, std::size_t siglen);

		EC_KEY_ptr create_ec_pub_key(const std::string & public_key
			, const std::string & public_key_password
			, std::size_t siglen);

		EC_KEY_ptr create_ec_priv_key(const std::string& private_key
			, const std::string& private_key_password
			, std::size_t siglen);

		namespace algorithm
		{
			class ecdsa : public base
			{
			public:

				/**
				 * Construct new ecdsa algorithm
				 * @param public_key ECDSA public key in PEM format
				 * @param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 * @param md Pointer to hash function
				 * @param name Name of the algorithm
				 */
				ecdsa(const std::string& public_key
					, const std::string& private_key
					, const std::string& public_key_password
					, const std::string& private_key_password
					, const EVP_MD* (*md)()
					, const std::string& name
					, size_t siglen);

				/**
				 * @return empty string
				 */
				virtual std::string sign(std::string const&) const override;

				/**
				 * Check if the given signature is empty. JWT's with "none" algorithm should not contain a signature.
				 */
				virtual void verify(const std::string&, const std::string& signature) const override;

			private:
				/**
				 * Hash the provided data using the hash function specified in constructor
				 * @param data Data to hash
				 * @return Hash of data
				 */
				std::string generate_hash(std::string const& data) const;

			private:
				/**
				 * containing key(s)
				 */
				EC_KEY_ptr pkey_;

				/**
				 * HMAC hash generator
				 */
				EVP_MD const* (*md_)();

				/**
				 * Length of the resulting signature
				 */
				std::size_t const signature_length_;
			};

			/**
			 * ES256 algorithm
			 */
			struct es256 : public ecdsa {
				/**
				 * Construct new instance of algorithm
				 * @param public_key ECDSA public key in PEM format
				 * @param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit es256(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
			/**
			 * ES384 algorithm
			 */
			struct es384 : public ecdsa {
				/**
				 * Construct new instance of algorithm
				 * @param public_key ECDSA public key in PEM format
				 * @param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit es384(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
			/**
			 * ES512 algorithm
			 */
			struct es512 : public ecdsa {
				/**
				 * Construct new instance of algorithm
				 * @param public_key ECDSA public key in PEM format
				 * @param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit es512(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
		}
	}
}

#endif	

