#include <smfsec/cms/x509.h>

namespace cyng {
    namespace crypto {
        namespace x509 {
            set::set()
                : certs_(sk_X509_new_null()) {}

            //  constructor chaining
            set::set(set const &s)
                : set(s.certs_) {}

            set::set(X509_SET *sk)
                //  consider sk_TYPE_deep_copy()
                //  increases the reference count of all certificates in chain x and returns a copy of the stack
                : certs_(X509_chain_up_ref(sk))
            //    : certs_(sk_X509_dup(sk))
            {}

            set::~set() {
                //  Free up all elements
                free();
                //  frees up the sk structure
                // sk_X509_free(certs_);
            }

            set::operator X509_SET const *() const { return certs_; }

            X509 const *set::at(std::size_t idx) const {
                // *sk_TYPE_value(STACK_OF(TYPE) *sk, int idx);
                return sk_X509_value(certs_, static_cast<int>(idx));
            }

            std::size_t set::size() const {
                auto const n = sk_X509_num(certs_);
                return (n < 0) ? 0u : static_cast<std::size_t>(n);
            }

            void set::reset() {
                //  Free up all elements
                free();

                //  initialize
                certs_ = sk_X509_new_null();
            }

            std::size_t set::push(X509 *ptr) {
                if (ptr != nullptr) {
                    auto const n = sk_X509_push(certs_, ptr);
                    return (n < 0) ? 0u : static_cast<std::size_t>(n);
                }
                return size();
            }

            void set::free() {
                //  frees up all elements of sk and sk itself.
                sk_X509_pop_free(certs_, ::X509_free);
            }

            bool set::reserve(std::size_t n) {
                auto const r = sk_X509_reserve(certs_, static_cast<int>(n));
                return r == 1;
            }

            void set::move(set const &s) {
                while (X509 *ptr = sk_X509_pop(s.certs_)) {
                    sk_X509_push(certs_, ptr);
                }
            }

        } // namespace x509

        x509::set read_certificate(std::string file_name) {
            x509::set r;
            FILE *fp = fopen(file_name.c_str(), "r");
            if (fp != NULL) {
                //
                //  one file can contain multiple certificates
                //
                while (X509 *ptr = PEM_read_X509(fp, NULL, NULL, NULL)) {
                    r.push(ptr);
                }
                fclose(fp);
            }
            return r;
        }

        x509::set read_certificates(std::initializer_list<std::string> file_names) {
            x509::set r;
            for (auto name : file_names) {
                auto const tmp = read_certificate(name);
                r.move(tmp);
            }
            return r;
        }
    } // namespace crypto
} // namespace cyng
