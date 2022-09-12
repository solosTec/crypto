/*
* The MIT License (MIT)
*
* Copyright (c) 2020 Sylko Olzscher
*
*/

#include <smfsec/algorithm/rsa.h>
#include <smfsec/factory.h>
#include <smfsec/jwt.h>
#include <smfsec/signatures.h>

namespace cyng 
{
	namespace crypto
	{
		EVP_PKEY_ptr create_evp_pkey(const std::string& public_key
			, const std::string& private_key
			, const std::string& public_key_password
			, const std::string& private_key_password)
		{
			if (!private_key.empty()) {
				return load_private_key_from_string(private_key, private_key_password);
			}
			else if (!public_key.empty()) {
				return load_public_key_from_string(public_key, public_key_password);
			}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			return create_evp_pkey();
#else 
			return std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>(nullptr, [](EVP_PKEY*) {});
#endif
		}

		namespace algorithm
		{
			rsa::rsa(const std::string& public_key
				, const std::string& private_key
				, const std::string& public_key_password
				, const std::string& private_key_password
				, const EVP_MD* (*md)()
				, const std::string& name)
			: base(name)
				, pkey_(create_evp_pkey(public_key, private_key, public_key_password, private_key_password))
				, md_(md)
			{}

			std::string rsa::sign(std::string const& data) const
			{
				//
				//	sign a digital signature
				//
				evp_sign ds(md_());
				ds.update(data);
				return ds.finalize(pkey_.get());
			}

			void rsa::verify(const std::string& data, const std::string& signature) const 
			{
				//
				//	verify digital signature
				//
				evp_verify ds(md_());
				ds.update(data);
				ds.finalize(pkey_.get(), signature);
			}

			rs256::rs256(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256")
			{}

			rs384::rs384(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384")
			{}

			rs512::rs512(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512")
			{}


		}
	}
}
