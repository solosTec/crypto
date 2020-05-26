/*
* The MIT License (MIT)
*
* Copyright (c) 2020 Sylko Olzscher
*
*/

#include <crypto/jwt.h>
#include <crypto/factory.h>
#include <crypto/read.h>
#include <crypto/bio.h>
#include <crypto/error.h>

namespace cyng 
{
	namespace crypto
	{
		std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw)
		{
			auto keybio = create_bio_s_mem(false);
			auto cert = create_x509(certstr, pw);
			if (!cert)	throw "Error loading cert into memory";
			auto key = create_evp_pkey(cert.get());
			if (!key) throw "Error getting public key from certificate";
			if (!PEM_write_bio_PUBKEY(keybio.get(), key.get())) throw "Error writing public key data in PEM format";
			return to_str(keybio.get());
		}

		EVP_PKEY_ptr load_public_key_from_string(const std::string& key, const std::string& passphrase)
		{
			auto pubkey_bio = create_bio_s_mem(false);

			if (key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") 
			{
				auto epkey = extract_pubkey_from_cert(key, passphrase);
				const int len = static_cast<int>(epkey.size());
				if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len)
					throw "failed to load public key: bio_write failed";
			}
			else 
			{
				const int len = static_cast<int>(key.size());
				if (BIO_write(pubkey_bio.get(), key.data(), len) != len)
					throw "failed to load public key: bio_write failed";
			}

			auto pkey = read_pub_key(pubkey_bio.get(), passphrase);
			if (!pkey) throw "failed to load public key: PEM_read_bio_PUBKEY failed:" + get_error_msg();
			return pkey;
		}

		EVP_PKEY_ptr load_private_key_from_string(const std::string& key, const std::string& passphrase)
		{
			auto privkey_bio = create_bio_s_mem(false);
			const int len = static_cast<int>(key.size());
			if (BIO_write(privkey_bio.get(), key.data(), len) != len)
				throw "failed to load private key: bio_write failed";
			auto pkey = read_priv_key(privkey_bio.get(), passphrase);
			if (!pkey)
				throw "failed to load private key: PEM_read_bio_PrivateKey failed";
			return pkey;
		}
	}
}
