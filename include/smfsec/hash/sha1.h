/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Sylko Olzscher 
 * 
 */ 

#ifndef CYNG_CRYPTO_SHA1_H
#define CYNG_CRYPTO_SHA1_H

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
  #pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)


#include <string>

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/sha.h>
#else
#include <openssl/evp.h>
#endif

#include <cyng/obj/intrinsics/digest.hpp>
#include <cyng/obj/intrinsics/buffer.h>

namespace cyng
{
	namespace crypto 
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L

		class sha1
		{
		public:
			sha1();
			
			bool update(std::string const&);
			bool update(const void* ptr, std::size_t length);
			
			digest_sha1::digest_type finalize();
			
		private:
			SHA_CTX ctx_;
		};
#else
		class sha1
		{
		public:
			sha1();
			~sha1();

			bool update(std::string const&);
			bool update(const void* ptr, std::size_t length);

			digest_sha1::digest_type finalize();

		private:
			EVP_MD_CTX* ctx_;
		};
#endif

	}
	
	/**
	 * Calculate SHA1 hash 
	 */
	crypto::digest_sha1::digest_type sha1_hash(std::string const&);
	crypto::digest_sha1::digest_type sha1_hash(buffer_t const&);
}

#endif	//	CYNG_CRYPTO_SHA1_H

