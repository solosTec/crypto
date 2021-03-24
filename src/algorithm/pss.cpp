/*
* The MIT License (MIT)
*
* Copyright (c) 2020 Sylko Olzscher
*
*/

#include <smfsec/algorithm/pss.h>
#include <smfsec/factory.h>
#include <smfsec/jwt.h>
#include <smfsec/signatures.h>

namespace cyng 
{
	namespace crypto
	{
		EVP_PKEY_ptr create_evp_key(const std::string& public_key
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
			return create_evp_pkey();
		}

		namespace algorithm
		{
			pss::pss(const std::string& public_key
				, const std::string& private_key
				, const std::string& public_key_password
				, const std::string& private_key_password
				, const EVP_MD* (*md)()
				, const std::string& name)
			: base(name)
				, pkey_(create_evp_key(public_key, private_key, public_key_password, private_key_password))
				, md_(md)
			{}

			std::string pss::sign(const std::string& data) const
			{
				auto const hash = generate_hash(data);

				auto const key = create_rsa_key(pkey_.get());
				int const size = RSA_size(key.get());

				std::string padded(size, 0x00);
				if (!RSA_padding_add_PKCS1_PSS_mgf1(key.get(), (unsigned char*)padded.data(), (const unsigned char*)hash.data(), md_(), md_(), -1)) {
					throw "failed to create signature: RSA_padding_add_PKCS1_PSS_mgf1 failed";
					//throw signature_generation_exception("failed to create signature: RSA_padding_add_PKCS1_PSS_mgf1 failed");
				}

				std::string res(size, 0x00);
				if (RSA_private_encrypt(size, (const unsigned char*)padded.data(), (unsigned char*)res.data(), key.get(), RSA_NO_PADDING) < 0) {
					throw "failed to create signature: RSA_private_encrypt failed";
					//throw signature_generation_exception("failed to create signature: RSA_private_encrypt failed");
				}
				return res;
			}

			void pss::verify(const std::string& data, const std::string& signature) const 
			{
				auto const hash = generate_hash(data);

				auto const key = create_rsa_key(pkey_.get());
				int const size = RSA_size(key.get());

				std::string sig(size, 0x00);
				if (!RSA_public_decrypt(static_cast<int>(signature.size()), (const unsigned char*)signature.data(), (unsigned char*)sig.data(), key.get(), RSA_NO_PADDING)) {
					throw "Invalid signature";
					//throw signature_verification_exception("Invalid signature");
				}

				if (!RSA_verify_PKCS1_PSS_mgf1(key.get(), (const unsigned char*)hash.data(), md_(), md_(), (const unsigned char*)sig.data(), -1)) {
					throw "Invalid signature";
					//throw signature_verification_exception("Invalid signature");
				}
			}

			std::string pss::generate_hash(std::string const& data) const
			{
				evp_digest digest(md_());
				digest.update(data);
				return digest.finalize();
			}

			ps256::ps256(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256")
			{}

			ps384::ps384(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384")
			{}

			ps512::ps512(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512")
			{}

		}
	}
}
