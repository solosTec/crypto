#include <smfsec/cms/pkcs7.h>

#include <smfsec/cms/x509.h>

#include <boost/assert.hpp>

namespace cyng {
    namespace crypto {
        namespace pkcs7 {
            PKCS7_ptr encrypt(BIO *in, x509::set const &certs, EVP_CIPHER *cipher) {
                return PKCS7_ptr(
                    PKCS7_encrypt(const_cast<X509_SET *>(certs.operator X509_SET const *()), in, cipher, 0), PKCS7_free);
            }
            void decrypt(BIO *out) {
                //
                BOOST_ASSERT_MSG(false, "not implemented yet");
                //  PEM_read_PrivateKey()
                //  PEM_read_X509()
            }
            void to_PEM(BIO *out, PKCS7 *p7) {
                //
                BOOST_ASSERT_MSG(false, "not implemented yet");
                // PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *data, int flags);
            }

        } // namespace pkcs7
    }     // namespace crypto
} // namespace cyng
