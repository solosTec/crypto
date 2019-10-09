/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_GENERATE_H
#define CYNG_CRYPTO_GENERATE_H

#include <crypto/crypto.h>

namespace cyng
{
	namespace crypto
	{
		/**
		 * Generates a X.509 Certificate Request
		 */
		bool generate_x509_cert_request(const char* pC	//	country
			, const char* pP	//	province
			, const char* pCity	//	city
			, const char* pOrg	//	organization
			, const char* pComm	//	common
			, const char* filename	//	name of output PEM file
			, int bits);

		/**
		 * Generate a private key
		 */
		EVP_PKEY_ptr generate_private_key(int bits);

		/**
		 * generate a private and a public key pair
		 *
		 * @param pub_pem name of file for public key
		 * @param priv_pem name of file for private key
		 * @param bits (e.g. 2048)
		 */
		bool generate_priv_pub_key_pair(const char* pub_pem
			, const char* priv_pem
			, int bits);

		/**
		 * Generate a Private Key and a CSR
         * @code
           openssl req \
            -newkey rsa:2048 -nodes -keyout domain.key \
            -out domain.csr
         * @endcode
		 */
		bool generate_ca_cert_write(const char* priv_key
			, const char* cert_file
			, const char* pC	//	country
			, const char* pP	//	province
			, const char* pCity	//	city
			, const char* pOrg	//	organization
			, const char* pComm	//	common
			, long serial
			, long days);

		/**
         * Generate a CSR from an Existing Private Key
         * 
         * @code
           openssl req \
            -key domain.key \
            -new -out domain.csr
         * @endcode
		 */
		bool generate_ca_cert_read(const char* priv_key
			, const char* cert_file
			, const char* pC	//	country
			, const char* pP	//	province
			, const char* pCity	//	city
			, const char* pOrg	//	organization
			, const char* pComm	//	common
			, long serial
			, long days);
        
        /**
         * ToDo: Generate a CSR from an Existing Certificate and Private Key
         * @code
           openssl x509 \
            -in domain.crt \
            -signkey domain.key \
            -x509toreq -out domain.csr
         * @endcode
         */

		 /**
		  * Sign a certification request
		  *
		  * To generate ca certificate use the following commands:
		  *
		  * @code
			 openssl genrsa -out cakey.pem 2048
			 openssl req -new -days 365 -x509 -key cakey.pem -out cacert.pem -nodes -subj /C=CH/ST=LU/L=Lucerne/O=solosTec/OU=solosTec/CN=solsoTec/emailAddress=info@solsotec.com
			 openssl rsa -in cakey.pem -pubout -out ca_pub.key
		  * @endcode
		  */
		bool sign_x509_with_CA(const char* caFile //  cacert.pem
			, const char* caPrivateKeyFile //	cakey.pem
			, const char* x509ReqFile	//	x509Req.pem
			, const char* szUserCert	//	cert.pem
			, long days);


	}
}

#endif	

