/*
* The MIT License (MIT)
*
* Copyright (c) 2019 Sylko Olzscher
*
*/

#include <smfsec/generate.h>
#include <smfsec/factory.h>
#include <smfsec/read.h>
#include <smfsec/write.h>
#include <smfsec/bio.h>
#include <smfsec/print.h>

namespace cyng 
{
	namespace crypto
	{
		/**
		 * sign cert
		 */
		bool sign_x509(X509* cert, EVP_PKEY* pkey, const EVP_MD* md);

		bool generate_x509_cert_request(const char* pC	//	country
			, const char* pST	//	province
			, const char* pL	//	city
			, const char* pO	//	organization
			, const char* pCN	//	common
			, const char* filename
			, int bits)
		{
			// 1. generate rsa key with exponent RSA_F4
			auto bnp = create_bignum_rsa_f4();
			if (!bnp) return false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L

			auto rsap = create_rsa_key(bnp.get(), bits);
			if (!rsap) return false;

			// 2. create a x509 request
			auto x509rp = create_x509_request(1);
			if (!x509rp) return false;

			// 3. set subject of x509 req
			auto x509_name = X509_REQ_get_subject_name(x509rp.get());
			if (!x509_name) return false;
			add_entry_by_txt(x509_name, "C", pC);
			add_entry_by_txt(x509_name, "ST", pST);
			add_entry_by_txt(x509_name, "L", pL);
			add_entry_by_txt(x509_name, "O", pO);
			add_entry_by_txt(x509_name, "CN", pCN);

			// 4. set public key of x509 req
			auto evp_pkeyp = create_evp_pkey();
			if (!evp_pkeyp) return false;

			//	rsap will be released by evp_pkeyp
			EVP_PKEY_assign_RSA(evp_pkeyp.get(), rsap.release());

			auto ret = X509_REQ_set_pubkey(x509rp.get(), evp_pkeyp.get());
			if (ret != OK) return false;

			// 5. set sign key of x509 req
			ret = X509_REQ_sign(x509rp.get(), evp_pkeyp.get(), EVP_sha1());
			if (ret <= 0) return false;

			// 6. write certificate request file
			auto biop = create_bio_file(filename, "w+");
			if (!biop) return false;

			ret = PEM_write_bio_X509_REQ(biop.get(), x509rp.get());
			if (ret != OK) return false;

			return true;
#else
			return false;
#endif
		}

		EVP_PKEY_ptr generate_private_key(int bits)
		{
#if OPENSSL_VERSION_NUMBER < 0x10100000L

			//
			//	To store private key algorithm-independent in memory.
			//
			auto evp_pkeyp = create_evp_pkey();
			if (!evp_pkeyp) return evp_pkeyp;

			//
			//	create the private key and assign it to the EVP_PKEY structure
			//
			auto bnp = create_bignum_rsa_f4();
			if (!bnp) return evp_pkeyp;

			auto rsap = create_rsa();
			if (!rsap) return evp_pkeyp;
			auto ret = RSA_generate_key_ex(rsap.get(), 2048, bnp.get(), NULL);
			if (ret != OK)	return evp_pkeyp;

			//
			//	The RSA structure will be automatically freed 
			//	when the EVP_PKEY structure is freed.
			//
			EVP_PKEY_assign_RSA(evp_pkeyp.get(), rsap.release());
			return evp_pkeyp;
#else
			return std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>(nullptr, [](EVP_PKEY*) {});
#endif
		}

		bool generate_priv_pub_key_pair(const char* pub_pem
			, const char* priv_pem
			, int bits)
		{
			// 1. generate rsa key with exponent RSA_F4
			auto bnp = create_bignum_rsa_f4();
			if (!bnp) return false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L

			auto rsap = create_rsa();
			if (!rsap) return false;
			auto ret = RSA_generate_key_ex(rsap.get(), bits, bnp.get(), NULL);
			if (ret != OK)	return false;

			// 2. save public key
			if (!write_public_key(rsap.get(), pub_pem)) {
				return false;
			}

			// 3. save private key
			return write_private_key(rsap.get(), priv_pem);
#else
			return false;
#endif

		}

		bool generate_ca_cert_write(const char* priv_key_file
			, const char* cert_file
			, const char* pC	//	country
			, const char* pST	//	province
			, const char* pL	//	city
			, const char* pO	//	organization
			, const char* pCN	//	common
			, long serial
			, long days)
		{
			//
			//	Create a EVP_PKEY struct with a private key
			//
			auto evp_pkeyp = generate_private_key(2048);

#if OPENSSL_VERSION_NUMBER < 0x10100000L

			//
			//	create a X509 structure to represent 
			//	the certificate in memory (Version 1.3)
			//
			auto x509p = create_x509(2);

			//
			//	set properties: serial
			//
			ASN1_INTEGER_set(X509_get_serialNumber(x509p.get()), serial);

			//
			//	set properties: time
			//
			X509_gmtime_adj(X509_get_notBefore(x509p.get()), 0);
			X509_gmtime_adj(X509_get_notAfter(x509p.get()), 60ul * 60ul * 24ul * days);

			//
			//	set properties: issuer name
			//
			auto x509_name = X509_get_subject_name(x509p.get());
			if (!x509_name) return false;
			add_entry_by_txt(x509_name, "C", pC);
			add_entry_by_txt(x509_name, "ST", pST);
			add_entry_by_txt(x509_name, "L", pL);
			add_entry_by_txt(x509_name, "O", pO);
			add_entry_by_txt(x509_name, "CN", pCN);

			X509_set_issuer_name(x509p.get(), x509_name);

			//
			//	signing the certificate with SHA1
			//
			X509_sign(x509p.get(), evp_pkeyp.get(), EVP_sha1());

#ifdef _DEBUG
			X509_print_fp(stdout, x509p.get());
#endif

			//
			//	write private key to disk
			//
			write_private_key(evp_pkeyp.get(), priv_key_file);

			//
			//	write certificate to disk
			//
			write_certificate(x509p.get(), cert_file);

			return true;
#else
			return false;
#endif
		}

		bool generate_ca_cert_read(const char* priv_key_file
			, const char* cert_file
			, const char* pC	//	country
			, const char* pST	//	province
			, const char* pL	//	city
			, const char* pO	//	organization
			, const char* pCN	//	common
			, long serial
			, long days)
		{
			//
			//	Create a EVP_PKEY struct with a private key
			//
			//auto evp_pkeyp = generate_private_key(2048);
			auto evp_pkeyp = load_CA_private_key(priv_key_file);
			if (!evp_pkeyp)	return false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L

			//
			//	create a X509 structure to represent 
			//	the certificate in memory (Version 1.3)
			//
			auto x509p = create_x509(2);

			//
			//	set properties: serial
			//
			ASN1_INTEGER_set(X509_get_serialNumber(x509p.get()), serial);

			//
			//	set properties: time
			//
			X509_gmtime_adj(X509_get_notBefore(x509p.get()), 0);
			X509_gmtime_adj(X509_get_notAfter(x509p.get()), 60ul * 60ul * 24ul * days);

			//
			//	set properties: issuer name
			//
			auto x509_name = X509_get_subject_name(x509p.get());
			if (!x509_name) return false;
			add_entry_by_txt(x509_name, "C", pC);
			add_entry_by_txt(x509_name, "ST", pST);
			add_entry_by_txt(x509_name, "L", pL);
			add_entry_by_txt(x509_name, "O", pO);
			add_entry_by_txt(x509_name, "CN", pCN);

			X509_set_issuer_name(x509p.get(), x509_name);

			//
			//	signing the certificate with SHA1
			//
			X509_sign(x509p.get(), evp_pkeyp.get(), EVP_sha1());

#ifdef _DEBUG
			print_stdout_X509(x509p.get());
#endif

			//
			//	write private key to disk
			//
			//write_private_key(evp_pkeyp.get(), priv_key_file);

			//
			//	write certificate to disk
			//
			write_certificate(x509p.get(), cert_file);

			return true;
#else
			return false;
#endif
		}

		bool sign_x509(X509* cert, EVP_PKEY* pkey, const EVP_MD* md)
		{
			auto mctxp = create_evp_ctx();

			EVP_PKEY_CTX* pkctx = NULL;

			auto rv = EVP_DigestSignInit(mctxp.get(), &pkctx, md, NULL, pkey);

			if (rv > 0) {
				rv = X509_sign_ctx(cert, mctxp.get());
			}
			return rv > 0;
		}

		bool sign_x509_with_CA(const char* caFile //  cacert.pem
			, const char* caPrivateKeyFile //	cakey.pem
			, const char* x509ReqFile	//	x509Req.pem
			, const char* szUserCert	//	cert.pem
			, long days)
		{

			auto cap = load_CA(caFile);
			if (!cap)	return false;

			auto evp_pkeyp = load_CA_private_key(caPrivateKeyFile);
			if (!evp_pkeyp)	return false;


			auto x509_reqp = load_x509_request(x509ReqFile);
			if (!x509_reqp)	return false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L

			// set version to X509 v3 certificate
			auto certp = create_x509(2);
			if (!certp)	return false;

			// set serial
			int serial = 1;
			ASN1_INTEGER_set(X509_get_serialNumber(certp.get()), serial);

			// set issuer name from ca
			if (!X509_set_issuer_name(certp.get(), X509_get_subject_name(cap.get()))) {
				return false;
			}

			// set time
			X509_gmtime_adj(X509_get_notBefore(certp.get()), 0);
			X509_gmtime_adj(X509_get_notAfter(certp.get()), 60ul * 60ul * 24ul * days);

			// set subject from req
			auto tmpname = X509_REQ_get_subject_name(x509_reqp.get());
			auto subject = X509_NAME_dup(tmpname);
			if (!X509_set_subject_name(certp.get(), subject)) {
				return false;
			}

			// set pubkey from req
			auto pktmp = X509_REQ_get_pubkey(x509_reqp.get());
			auto ret = X509_set_pubkey(certp.get(), pktmp);
			EVP_PKEY_free(pktmp);
			if (!ret) return false;

			// sign cert
			if (!sign_x509(certp.get(), evp_pkeyp.get(), EVP_sha1())) {
				return false;
			}

			auto biop = create_bio_file(szUserCert, "w+");
			if (!PEM_write_bio_X509(biop.get(), certp.get())) {
				return false;
			}

			return true;
#else
			return false;
#endif
		}


	}
}
