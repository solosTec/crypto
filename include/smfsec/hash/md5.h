/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Sylko Olzscher 
 * 
 */ 

#ifndef CYNG_CRYPTO_HASH_MD5_H
#define CYNG_CRYPTO_HASH_MD5_H

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
  #pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <string>

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/md5.h>
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
		class md5
		{
		public:
			md5();
			
			bool update(std::string const&);
			bool update(const void* ptr, std::size_t length);
			
			digest_md5::digest_type finalize();
			
		private:
			MD5_CTX ctx_;
		};
#else
		class md5
		{
		public:
			md5();
			~md5();

			bool update(std::string const&);
			bool update(const void* ptr, std::size_t length);

			digest_md5::digest_type finalize();

		private:
			EVP_MD_CTX *ctx_;
		};
#endif

	}
	
	/**
	 * Calculate MD5 hash 
	 */
	crypto::digest_md5::digest_type md5_hash(std::string const&);
	crypto::digest_md5::digest_type md5_hash(buffer_t const&);
}

#endif
