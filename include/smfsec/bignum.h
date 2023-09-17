/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_BIGNUM_H
#define CYNG_CRYPTO_BIGNUM_H

#include <smfsec/crypto.h>

#include <cyng/obj/intrinsics/buffer.h>

#include <iostream>
#include <string>

namespace cyng {
    namespace crypto {
        /**
         * Convert a BIGNUM to a std::string
         */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        buffer_t to_buffer(BIGNUM *);
#else
        buffer_t to_buffer(BIGNUM const *);
#endif

        /**
         * Convert an std::string to a BIGNUM
         */
        BN_ptr create_bignum(std::string const &);

        class bn {

          public:
            bn();
            bn(std::string const &);
            bn(bn const &);
            explicit bn(BIGNUM *); // takes ownership
            bn(unsigned long);

            bn &operator=(bn const &);
            bn &operator=(unsigned long);

            //  cast to decimal value
            operator std::string() const;
            std::string to_dec_string() const;
            std::string to_hex_string() const;

            operator BIGNUM const *() const;
            operator BIGNUM *();

            bn &operator+=(bn const &other);
            bn &operator-=(bn const &other);

          private:
            BN_ptr bn_;
        };

        //  comparison
        bool operator==(bn const &, bn const &);
        bool operator<(bn const &, bn const &);

        //  arithmetics
        bn operator+(bn const &, bn const &);
        bn operator-(bn const &, bn const &);
        bn operator*(bn const &, bn const &);
        bn operator/(bn const &, bn const &);

        //  serialization
        std::ostream &operator<<(std::ostream &output, const bn &);

    } // namespace crypto
} // namespace cyng

#endif
