/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Sylko Olzscher 
 * 
 */ 

#include <smfsec/hash/sha256.h>
#include <openssl/crypto.h>	//	OPENSSL_cleanse

namespace cyng
{
	namespace crypto
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L

		sha256::sha256()
			: ctx_()
		{
			SHA256_Init(&ctx_);
		}

		bool sha256::update(std::string const& str)
		{
			return update(str.c_str(), str.length());
		}

		bool sha256::update(const void* ptr, std::size_t length)
		{
			return SHA256_Update(&ctx_, ptr, length) != 0;
		}

		digest_sha256::digest_type sha256::finalize()
		{
			digest_sha256::digest_type d;
			SHA256_Final(d.data(), &ctx_);
			OPENSSL_cleanse(&ctx_, sizeof(ctx_));
			return d;
		}
#else
		sha256::sha256()
			: ctx_(EVP_MD_CTX_new())
		{
			EVP_DigestInit_ex(ctx_, EVP_sha256(), NULL);
		}

		sha256::~sha256() {
			EVP_MD_CTX_free(ctx_);
		}

		bool sha256::update(std::string const& str) {
			return update(str.c_str(), str.length());
		}

		bool sha256::update(const void* ptr, std::size_t length) {
			return EVP_DigestUpdate(ctx_, ptr, length) != 0;
		}

		digest_sha256::digest_type sha256::finalize() {

			unsigned int digest_len = EVP_MD_size(EVP_sha256());
			//BOOST_ASSERT(digest_len == digest_sha1::size());

			digest_sha256::digest_type digest;
			EVP_DigestFinal_ex(ctx_, digest.data(), &digest_len);
			return digest;
		}
#endif

	}

	crypto::digest_sha256::digest_type sha256_hash(std::string const& str)
	{
		crypto::sha256 h;
		h.update(str);
		return h.finalize();
	}

	crypto::digest_sha256::digest_type sha256_hash(buffer_t const& b)
	{
		crypto::sha256 h;
		h.update(b.data(), b.size());
		return h.finalize();
	}
}
