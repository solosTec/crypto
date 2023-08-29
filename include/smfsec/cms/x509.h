/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_X509_H
#define CYNG_CRYPTO_X509_H

#include <smfsec/crypto.h>

#include <initializer_list>
#include <string>

namespace cyng {
    namespace crypto {
        namespace x509 {

            /**
             * Wrapper class for a set of certificates
             */
            class set final {
              public:
                set();

                /**
                 * create a copy
                 */
                set(set const &);

                /**
                 * create a copy of sk
                 */
                set(X509_SET *sk);

                /**
                 * Free up all
                 */
                ~set();

                /**
                 * Access to internal struct
                 */
                explicit operator X509_SET const *() const;

                /**
                 * Get a certificate.
                 * @return NULL if idx is out or range.
                 */
                X509 const *at(std::size_t idx) const;

                /**
                 * @return number of elements
                 */
                std::size_t size() const;

                /**
                 * reset size to zero
                 */
                void reset();

                /**
                 * add element to the end
                 */
                std::size_t push(X509 *);

                /**
                 * Reserve space for additional elements
                 */
                bool reserve(std::size_t);

                /**
                 * Move one set to another
                 */
                void move(set const &);

              private:
                /**
                 * Frees up all elements of certs_ and certs_ itself.
                 */
                void free();

              private:
                X509_SET *certs_;
            };

        } // namespace x509

        /**
         * one file can contain multiple certificates
         */
        x509::set read_certificate(std::string file_name);

        /**
         * Read a list of certificates
         */
        x509::set read_certificates(std::initializer_list<std::string> file_names);
    } // namespace crypto
} // namespace cyng

#endif
