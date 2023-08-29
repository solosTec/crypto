#include <smfsec/cms/pem.h>

namespace cyng {
    namespace crypto {
        namespace pem {
            X509_ptr read_x509(const char *file_name) {
                auto *fp = fopen(file_name, "r");
                X509_ptr p = read_x509(fp);
                fclose(fp);
                return p;
            }
            X509_ptr read_x509(FILE *fp) {
                // X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
                return X509_ptr(PEM_read_X509(fp, NULL, NULL, NULL), X509_free);
            }

            PKCS7_ptr read_pkcs7(const char *file_name) {
                auto *fp = fopen(file_name, "r");
                PKCS7_ptr p = read_pkcs7(fp);
                fclose(fp);
                return p;
            }
            PKCS7_ptr read_pkcs7(FILE *fp) {
                // PKCS7 *PEM_read_PKCS7(FILE * fp, PKCS7 **x, pem_password_cb * cb, void *u);
                return PKCS7_ptr(PEM_read_PKCS7(fp, NULL, NULL, NULL), PKCS7_free);
            }

            EVP_PKEY_ptr read_private_key(const char *file_name) {
                auto *fp = fopen(file_name, "r");
                EVP_PKEY_ptr p = read_private_key(fp);
                fclose(fp);
                return p;
            }
            EVP_PKEY_ptr read_private_key(FILE *fp) {
                //
                return EVP_PKEY_ptr(PEM_read_PrivateKey(fp, NULL, NULL, NULL), EVP_PKEY_free);
            }
            EVP_PKEY_ptr read_private_key(BIO *bio) {
                //
                return EVP_PKEY_ptr(PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL), EVP_PKEY_free);
            }

        } // namespace pem
    }     // namespace crypto
} // namespace cyng
