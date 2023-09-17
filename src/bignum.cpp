/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#include <smfsec/bignum.h>
#include <smfsec/factory.h>

#include <openssl/bn.h>

#include <vector>

namespace cyng {
    namespace crypto {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        buffer_t to_buffer(BIGNUM *p)
#else
        buffer_t to_buffer(BIGNUM const *p)
#endif
        {
            buffer_t vec;
            if (p != nullptr) {
                vec.resize(BN_num_bytes(p)); //	macro
                // this is safe
                BN_bn2bin(p, reinterpret_cast<unsigned char *>(vec.data()));
            }
            return vec;
        }

        BN_ptr create_bignum(std::string const &str) {
            BIGNUM *ptr = nullptr;
            auto const size = BN_dec2bn(&ptr, str.c_str());
            return BN_ptr(ptr, ::BN_free);
        }

        bn::bn()
            : bn_(BN_new(), ::BN_free) {}

        bn::bn(std::string const &s)
            : bn_(create_bignum(s)) {}

        bn::bn(bn const &other)
            : bn_(::BN_dup(other), ::BN_free) {}

        bn::bn(BIGNUM *ptr)
            : bn_(ptr, ::BN_free) {}

        bn::bn(unsigned long w)
            : bn() {
            BN_set_word(*this, w);
        }

        bn &bn::operator=(bn const &other) {
            if (this != &other) {
                ::BN_copy(*this, other);
            }
            return *this;
        }

        bn &bn::operator=(unsigned long w) {
            BN_set_word(*this, w);
            return *this;
        }

        std::string bn::to_dec_string() const {
            char *ptr = BN_bn2dec(*this);
            std::string s(ptr, ::strlen(ptr));
            OPENSSL_free(ptr);
            return s;
        }
        std::string bn::to_hex_string() const {
            char *ptr = BN_bn2hex(*this);
            std::string s(ptr, ::strlen(ptr));
            OPENSSL_free(ptr);
            return s;
        }
        bn::operator std::string() const { return to_dec_string(); }

        bn::operator BIGNUM const *() const { return bn_.get(); }
        bn::operator BIGNUM *() { return bn_.get(); }

        bn &bn::operator+=(bn const &other) {
            ::BN_add(*this, *this, other);
            return *this;
        }
        bn &bn::operator-=(bn const &other) {
            ::BN_sub(*this, *this, other);
            return *this;
        }

        bool operator==(bn const &n1, bn const &n2) { return 0 == BN_cmp(n1, n2); }
        bool operator<(bn const &n1, bn const &n2) { return 0 > BN_cmp(n1, n2); }

        bn operator+(bn const &n1, bn const &n2) {
            bn r;
            ::BN_add(r, n1, n2);
            return r;
        }
        bn operator-(bn const &n1, bn const &n2) {
            bn r;
            ::BN_sub(r, n1, n2);
            return r;
        }
        bn operator*(bn const &n1, bn const &n2) {
            bn r;
            BN_CTX_ptr ctx = create_bignum_ctx();
            ::BN_mul(r, n1, n2, ctx.get());
            return r;
        }
        bn operator/(bn const &n1, bn const &n2) {
            bn r;
            BN_CTX_ptr ctx = create_bignum_ctx();
            ::BN_div(r, NULL, n1, n2, ctx.get());
            return r;
        }

        std::ostream &operator<<(std::ostream &os, const bn &n) { return os << n.to_dec_string(); }

    } // namespace crypto
} // namespace cyng
