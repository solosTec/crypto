/*
* The MIT License (MIT)
*
* Copyright (c) 2020 Sylko Olzscher
*
*/

#include <smfsec/algorithm/ecdsa.h>
#include <smfsec/factory.h>
#include <smfsec/bio.h>
#include <smfsec/jwt.h>
#include <smfsec/signatures.h>
#include <smfsec/bignum.h>
#include <stdexcept>

namespace cyng 
{
	namespace crypto
	{
		EC_KEY_ptr create_ec_pub_key(const std::string& public_key
			, const std::string& public_key_password
			, std::size_t siglen)
		{
			auto pubkey_bio = create_bio_s_mem(false);
			if (public_key.substr(0, 27) == "-----BEGIN CERTIFICATE-----")
			{
				auto epkey = extract_pubkey_from_cert(public_key, public_key_password);
				const int len = static_cast<int>(epkey.size());
				if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len) {
					throw "failed to load public key: bio_write failed";
					//throw ecdsa_exception("failed to load public key: bio_write failed");
				}
			}
			else
			{
				const int len = static_cast<int>(public_key.size());
				if (BIO_write(pubkey_bio.get(), public_key.data(), len) != len) {
					throw "failed to load public key: bio_write failed";
					//throw ecdsa_exception("failed to load public key: bio_write failed");
				}
			}

			auto pkey{ create_ec_pub_key(pubkey_bio.get(), public_key_password) };
			if (!pkey) {
				//throw "failed to load public key: PEM_read_bio_EC_PUBKEY failed:" + std::string(ERR_error_string(ERR_get_error(), NULL));
				//throw ecdsa_exception("failed to load public key: PEM_read_bio_EC_PUBKEY failed:" + std::string(ERR_error_string(ERR_get_error(), NULL)));
			}
			size_t const keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
			if (keysize != siglen * 4 && (siglen != 132 || keysize != 521)) {
				throw "invalid key size";
				//throw ecdsa_exception("invalid key size");
			}

			return pkey;
		}

		EC_KEY_ptr create_ec_priv_key(const std::string& private_key
			, const std::string& private_key_password
			, std::size_t siglen)
		{
			auto privkey_bio = create_bio_s_mem(false);
			const int len = static_cast<int>(private_key.size());
			if (BIO_write(privkey_bio.get(), private_key.data(), len) != len) {
				throw "failed to load private key: bio_write failed";
				//throw ecdsa_exception("failed to load private key: bio_write failed");
			}

			auto pkey{ create_ec_priv_key(privkey_bio.get(), private_key_password) };
			if (!pkey) {
				throw "failed to load private key: PEM_read_bio_ECPrivateKey failed";
				//throw ecdsa_exception("failed to load private key: PEM_read_bio_ECPrivateKey failed");
			}
			size_t const keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
			if (keysize != siglen * 4 && (siglen != 132 || keysize != 521)) {
				throw "invalid key size";
				//throw ecdsa_exception("invalid key size");
			}
			return pkey;
		}

		EC_KEY_ptr create_ec_key(const std::string& public_key
			, const std::string& private_key
			, const std::string& public_key_password
			, const std::string& private_key_password
			, size_t siglen)
		{
			if (!public_key.empty())
			{
				return create_ec_pub_key(public_key, public_key_password, siglen);
			}

			if (!private_key.empty())
			{
				return create_ec_priv_key(private_key, private_key_password, siglen);
			}
			//if (!pkey) {
				throw "at least one of public or private key need to be present";
				//throw ecdsa_exception("at least one of public or private key need to be present");
			//}

			//if (EC_KEY_check_key(pkey.get()) == 0) {
			//	throw "failed to load key: key is invalid";
			//	//throw ecdsa_exception("failed to load key: key is invalid");
			//}

		}

		namespace algorithm
		{
			ecdsa::ecdsa(const std::string& public_key
				, const std::string& private_key
				, const std::string& public_key_password
				, const std::string& private_key_password
				, const EVP_MD* (*md)()
				, const std::string& name
				, size_t siglen)
				: base(name)
				, pkey_(create_ec_key(public_key, private_key, public_key_password, private_key_password, siglen))
				, md_(md)
				, signature_length_(siglen)
			{}

			std::string ecdsa::sign(std::string const& data) const
			{
				auto const hash = generate_hash(data);

				auto sig = do_sign(hash, pkey_.get());
				if (!sig) throw "signature_generation_exception()";

#if OPENSSL_VERSION_NUMBER < 0x10100000L
				auto rr = to_str(sig->r);
				auto rs = to_str(sig->s);
#else
				BIGNUM const* r;
				BIGNUM const* s;
				ECDSA_SIG_get0(sig.get(), &r, &s);
				auto rr = to_str(r);
				auto rs = to_str(s);
#endif
				if (rr.size() > signature_length_ / 2 || rs.size() > signature_length_ / 2) {
					throw std::logic_error("bignum size exceeded expected length");
				}
				while (rr.size() != signature_length_ / 2) rr = '\0' + rr;
				while (rs.size() != signature_length_ / 2) rs = '\0' + rs;
				return rr + rs;
			}

			void ecdsa::verify(const std::string& data, const std::string& signature) const
			{
				auto const hash = generate_hash(data);

				auto r = create_bignum(signature.substr(0, signature.size() / 2));
				auto s = create_bignum(signature.substr(signature.size() / 2));

#if OPENSSL_VERSION_NUMBER < 0x10100000L
				ECDSA_SIG sig;
				sig.r = r.get();
				sig.s = s.get();

				if (ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), &sig, pkey.get()) != 1) {
					throw signature_verification_exception("Invalid signature");
				}
#else
				auto sig = create_ecdsa_sig();
				ECDSA_SIG_set0(sig.get(), r.release(), s.release());

				if (ECDSA_do_verify((const unsigned char*)hash.data(), static_cast<int>(hash.size()), sig.get(), pkey_.get()) != 1) {
					throw "Invalid signature";
//					//throw signature_verification_exception("Invalid signature");
				}
#endif			
			}

			std::string ecdsa::generate_hash(std::string const& data) const
			{
				evp_digest digest(md_());
				digest.update(data);
				return digest.finalize();
			}

			es256::es256(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256", 64)
			{}

			es384::es384(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384", 96)
			{}

			es512::es512(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password)
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512", 132)
			{}

		}
	}
}
