/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Sylko Olzscher 
 * 
 */ 

#include <smfsec/hash/sha1.h>

#include <openssl/crypto.h>	//	OPENSSL_cleanse

namespace cyng
{
	namespace crypto 
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L

		sha1::sha1()
		: ctx_()
		{
			SHA1_Init(&ctx_);
		}
		
		bool sha1::update(std::string const& str)
		{
			return update(str.c_str(), str.length());
		}
		
		bool sha1::update(const void* ptr, std::size_t length)
		{
			return SHA1_Update(&ctx_, ptr, length) != 0;
		}
		
		digest_sha1::digest_type sha1::finalize()
		{
			digest_sha1::digest_type d;
			SHA1_Final(d.data(), &ctx_);
			OPENSSL_cleanse(&ctx_, sizeof(ctx_));
			return d;
		}
#else
		sha1::sha1()
			: ctx_(EVP_MD_CTX_new())
		{
			EVP_DigestInit_ex(ctx_, EVP_sha1(), NULL);
		}

		sha1::~sha1() {
			EVP_MD_CTX_free(ctx_);
		}

		bool sha1::update(std::string const& str) {
			return update(str.c_str(), str.length());
		}

		bool sha1::update(const void* ptr, std::size_t length) {
			return EVP_DigestUpdate(ctx_, ptr, length) != 0;
		}

		digest_sha1::digest_type sha1::finalize() {

			unsigned int digest_len = EVP_MD_size(EVP_sha1());
			//BOOST_ASSERT(digest_len == digest_sha1::size());

			digest_sha1::digest_type digest;
			EVP_DigestFinal_ex(ctx_, digest.data(), &digest_len);
			return digest;
		}

#endif
	}
	
	crypto::digest_sha1::digest_type sha1_hash(std::string const& str)
	{
		crypto::sha1 h;
		h.update(str);
		return h.finalize();
	}
	
	crypto::digest_sha1::digest_type sha1_hash(buffer_t const& b)
	{
		crypto::sha1 h;
		h.update(b.data(), b.size());
		return h.finalize();
	}	
}
