/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_ALGO_RSA_H
#define CYNG_CRYPTO_ALGO_RSA_H

#include <crypto/algorithm/none.h>
#include <crypto/crypto.h>

namespace cyng
{
	namespace crypto
	{
		EVP_PKEY_ptr create_evp_pkey(const std::string& public_key
			, const std::string& private_key
			, const std::string& public_key_password
			, const std::string& private_key_password);

		namespace algorithm
		{
			class rsa : public base
			{
			public:
				/**
				  * Construct new rsa algorithm
				  * @param public_key RSA public key in PEM format
				  * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				  * @param public_key_password Password to decrypt public key pem.
				  * @param privat_key_password Password to decrypt private key pem.
				  * @param md Pointer to hash function
				  * @param name Name of the algorithm
				  */
				rsa(const std::string& public_key
					, const std::string& private_key
					, const std::string& public_key_password
					, const std::string& private_key_password
					, const EVP_MD* (*md)()
					, const std::string& name);

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
				 * containing converted keys
				 */
				EVP_PKEY_ptr pkey_;

				/**
				 * HMAC hash generator
				 */
				EVP_MD const* (*md_)();

			};


			/**
			 * RS256 algorithm
			 */
			struct rs256 : public rsa {
				/**
				 * Construct new instance of algorithm
				 * @param public_key RSA public key in PEM format
				 * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit rs256(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
			/**
			 * RS384 algorithm
			 */
			struct rs384 : public rsa {
				/**
				 * Construct new instance of algorithm
				 * @param public_key RSA public key in PEM format
				 * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit rs384(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
			/**
			 * RS512 algorithm
			 */
			struct rs512 : public rsa {
				/**
				 * Construct new instance of algorithm
				 * @param public_key RSA public key in PEM format
				 * @param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * @param public_key_password Password to decrypt public key pem.
				 * @param privat_key_password Password to decrypt private key pem.
				 */
				explicit rs512(const std::string& public_key
					, const std::string& private_key = ""
					, const std::string& public_key_password = ""
					, const std::string& private_key_password = "");
			};
		}
	}
}

#endif	

