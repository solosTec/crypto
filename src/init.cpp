/*
* The MIT License (MIT)
*
* Copyright (c) 2019 Sylko Olzscher
*
*/

#include <cyng/init.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

namespace cyng 
{
	namespace crypto
	{
		ssl::ssl()
		{
			SSL_library_init();
			SSL_load_error_strings();
			ERR_load_BIO_strings();
			OpenSSL_add_all_algorithms();
		}
		ssl::~ssl()
		{
#if OPENSSL_API_COMPAT < 0x10000000L
			ERR_remove_state(0);
#endif
			ENGINE_cleanup();
			CONF_modules_unload(1);
			ERR_free_strings();
			EVP_cleanup();
			sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
			CRYPTO_cleanup_all_ex_data();
		}
	}
}
