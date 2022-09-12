/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Sylko Olzscher 
 * 
 */ 

#include <smfsec/hash/md5.h>

#include <openssl/crypto.h>	//	OPENSSL_cleanse
//#include <boost/

namespace cyng
{
	namespace crypto 
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		md5::md5()
		: ctx_()
		{
			MD5_Init(&ctx_);
		}
		
		bool md5::update(std::string const& str)
		{
			return update(str.c_str(), str.length());
		}
		
		bool md5::update(const void* ptr, std::size_t length)
		{
			return MD5_Update(&ctx_, ptr, length) != 0;
		}
		
		digest_md5::digest_type md5::finalize()
		{
			digest_md5::digest_type d;
			MD5_Final(d.data (), &ctx_);
			OPENSSL_cleanse(&ctx_, sizeof(ctx_));
			return d;
		}
#else
		md5::md5()
			: ctx_(EVP_MD_CTX_new())
		{
			EVP_DigestInit_ex(ctx_, EVP_md5(), NULL);
		}

		md5::~md5() {
			EVP_MD_CTX_free(ctx_);
		}

		bool md5::update(std::string const& str) {
			return update(str.c_str(), str.length());
		}

		bool md5::update(const void* ptr, std::size_t length) {
			return EVP_DigestUpdate(ctx_, ptr, length) != 0;
		}

		digest_md5::digest_type md5::finalize() {
		
			unsigned int digest_len = EVP_MD_size(EVP_md5());
			//BOOST_ASSERT(digest_len == digest_md5::size());

			digest_md5::digest_type digest;
			EVP_DigestFinal_ex(ctx_, digest.data(), &digest_len);
			return digest;
		}
#endif
	}

	
	crypto::digest_md5::digest_type md5_hash(std::string const& str)
	{
		crypto::md5 h;
		h.update(str);
		return h.finalize();
	}
	
	crypto::digest_md5::digest_type md5_hash(buffer_t const& b)
	{
		crypto::md5 h;
		h.update(b.data(), b.size());
		return h.finalize();
	}
	
}
