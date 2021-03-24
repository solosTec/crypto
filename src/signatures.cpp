/*
* The MIT License (MIT)
*
* Copyright (c) 2020 Sylko Olzscher
*
*/

#include <smfsec/signatures.h>
#include <smfsec/factory.h>
#include <cassert>

namespace cyng 
{
	namespace crypto
	{
		evp_sign::evp_sign(EVP_MD const* type)
			: ctx_(create_evp_ctx())
		{
			init(type);
		}

		void evp_sign::init(EVP_MD const* type)
		{
			::EVP_SignInit(ctx_.get(), type);
		}

		void evp_sign::update(std::string const& data)
		{
			auto const rc = ::EVP_SignUpdate(ctx_.get(), data.data(), data.size());
			assert(rc == 1);
		}

		void evp_sign::update(std::vector<unsigned char> const& data)
		{
			auto const rc = ::EVP_SignUpdate(ctx_.get(), data.data(), data.size());
			assert(rc == 1);
		}

		std::string evp_sign::finalize(EVP_PKEY* pkey)
		{
			std::vector<unsigned char> vec;
			vec.resize(get_evp_key_size(pkey));

			unsigned int len{ 0 };
			auto const rc = EVP_SignFinal(ctx_.get(), vec.data(), &len, pkey);
			assert(rc == 1);

			return std::string(vec.begin(), vec.begin() + len);
		}

		evp_verify::evp_verify(EVP_MD const* type)
			: ctx_(create_evp_ctx())
		{
			init(type);
		}

		void evp_verify::init(EVP_MD const* type)
		{
			::EVP_VerifyInit(ctx_.get(), type);
		}

		void evp_verify::update(std::string const& data)
		{
			auto const rc = ::EVP_VerifyUpdate(ctx_.get(), data.data(), data.size());
			assert(rc == 1);
		}

		void evp_verify::update(std::vector<unsigned char> const& data)
		{
			auto const rc = ::EVP_VerifyUpdate(ctx_.get(), data.data(), data.size());
			assert(rc == 1);
		}

		bool evp_verify::finalize(EVP_PKEY* pkey, std::string const& signature)
		{
			std::vector<unsigned char> const vec(signature.begin(), signature.end());
			return finalize(pkey, vec);
		}

		bool evp_verify::finalize(EVP_PKEY* pkey, std::vector<unsigned char> const& signature)
		{
			auto const rc = ::EVP_VerifyFinal(ctx_.get()
				, signature.data()
				, static_cast<unsigned int>(signature.size())
				, pkey);
			return rc == 1;
		}

		std::size_t get_evp_key_size(EVP_PKEY* pkey)
		{
			return (pkey != nullptr)
				? ::EVP_PKEY_size(pkey)
				: 0u
				;
		}

		std::size_t get_evp_digest_size(EVP_MD_CTX* ctx)
		{
			return (ctx != nullptr)
				? ::EVP_MD_CTX_size(ctx)
				: 0u
				;
		}

		evp_digest::evp_digest(EVP_MD const* type)
			: ctx_(create_evp_ctx())
		{
			init(type);
		}

		void evp_digest::init(EVP_MD const* type)
		{
			auto const rc = ::EVP_DigestInit(ctx_.get(), type);
			assert(rc == 1);

		}
		void evp_digest::update(std::string const& data)
		{
			auto const rc = ::EVP_DigestUpdate(ctx_.get(), data.data(), data.size());
			assert(rc == 1);
		}

		void evp_digest::update(std::vector<unsigned char> const& data)
		{
			auto const rc = ::EVP_DigestUpdate(ctx_.get(), data.data(), data.size());
			assert(rc == 1);
		}

		std::string evp_digest::finalize()
		{
			unsigned int len = 0;
			std::vector<unsigned char> vec;
			vec.resize(get_evp_digest_size(ctx_.get()));

			auto const rc = ::EVP_DigestFinal(ctx_.get(), vec.data(), &len);
			//assert(rc == 1);
			return (rc == 1)
				? std::string(vec.begin(), vec.begin() + len)
				: std::string()
				;

		}

		ECDSA_SIG_ptr do_sign(std::string const& hash, EC_KEY* eckey)
		{
			std::vector<unsigned char> const vec(hash.begin(), hash.end());
			return do_sign(vec, eckey);
		}

		ECDSA_SIG_ptr do_sign(std::vector<unsigned char> const& hash, EC_KEY* eckey)
		{
			return ECDSA_SIG_ptr(::ECDSA_do_sign(hash.data(), static_cast<int>(hash.size()), eckey), ::ECDSA_SIG_free);
		}

	}
}
