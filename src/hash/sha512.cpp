/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Sylko Olzscher 
 * 
 */ 

#include <smfsec/hash/sha512.h>
#include <openssl/crypto.h>	//	OPENSSL_cleanse

namespace cyng
{
	namespace crypto 
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L

		sha512::sha512()
		: ctx_()
		{
			SHA512_Init(&ctx_);
		}
		
		bool sha512::update(std::string const& str)
		{
			return update(str.c_str(), str.length());
		}
		
		bool sha512::update(const void* ptr, std::size_t length)
		{
			return SHA512_Update(&ctx_, ptr, length) != 0;
		}
		
		digest_sha512::digest_type sha512::finalize()
		{
			digest_sha512::digest_type d;
			SHA512_Final(d.data(), &ctx_);
			OPENSSL_cleanse(&ctx_, sizeof(ctx_));
			return d;
		}
#else
		sha512::sha512()
			: ctx_(EVP_MD_CTX_new())
		{
			EVP_DigestInit_ex(ctx_, EVP_sha512(), NULL);
		}

		sha512::~sha512() {
			EVP_MD_CTX_free(ctx_);
		}

		bool sha512::update(std::string const& str) {
			return update(str.c_str(), str.length());
		}

		bool sha512::update(const void* ptr, std::size_t length) {
			return EVP_DigestUpdate(ctx_, ptr, length) != 0;
		}

		digest_sha512::digest_type sha512::finalize() {

			unsigned int digest_len = EVP_MD_size(EVP_sha512());
			//BOOST_ASSERT(digest_len == digest_sha1::size());

			digest_sha512::digest_type digest;
			EVP_DigestFinal_ex(ctx_, digest.data(), &digest_len);
			return digest;
		}


#endif

	}
	
	crypto::digest_sha512::digest_type sha512_hash(std::string const& str)
	{
		crypto::sha512 h;
		h.update(str);
		return h.finalize();
	}
	
	crypto::digest_sha512::digest_type sha512_hash(buffer_t const& b)
	{
		crypto::sha512 h;
		h.update(b.data(), b.size());
		return h.finalize();
	}
}
