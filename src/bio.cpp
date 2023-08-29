/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Sylko Olzscher
 *
 */

#include <smfsec/bio.h>

namespace cyng {
    namespace crypto {
        BIO_ptr create_bio() { return BIO_ptr(nullptr, BIO_free); }

        BIO_ptr create_bio_file(const char *filename, const char *mode) {
            //
            //	Since we provide a deleter it's impossible to use of std::make_unique<>()
            //
            return BIO_ptr(BIO_new_file(filename, mode), BIO_free);
        }
        BIO_ptr create_bio_file_read(const char *filename) {
            BIO_ptr p = create_bio_s_file();
            if (1 == BIO_read_filename(p.get(), (void *)filename)) {
            }
            return p;
        }
        BIO_ptr create_bio_file_write(const char *filename) {
            BIO_ptr p = create_bio_s_file();
            BIO_write_filename(p.get(), (void *)filename);
            return p;
        }
        BIO_ptr create_bio_file_appen(const char *filename) {
            BIO_ptr p = create_bio_s_file();
            BIO_append_filename(p.get(), (void *)filename);
            return p;
        }

        BIO_ptr create_bio_fp(FILE *stream, int flags) { return BIO_ptr(BIO_new_fp(stream, flags), BIO_free); }

        BIO_ptr_all create_bio_base64() { return BIO_ptr_all(::BIO_new(BIO_f_base64()), ::BIO_free_all); }

        BIO_ptr create_bio_s_mem(bool eof) {
            BIO_ptr p(BIO_new(BIO_s_mem()), BIO_free);
            if (eof)
                BIO_set_mem_eof_return(p.get(), -1);
            return p;
        }

        BIO_ptr create_bio_socket(int sock, int close_flag) { return BIO_ptr(BIO_new_socket(sock, close_flag), BIO_free); }

        BIO_ptr create_bio_connection(const char *target) { return BIO_ptr(BIO_new_connect(target), BIO_free); }

        BIO_ptr create_bio_ssl_connection(SSL_CTX *ctx, const char *target) {
            BIO_ptr p(BIO_new_ssl_connect(ctx), BIO_free);

            //
            //	set SSL_MODE_AUTO_RETRY mode
            //
            SSL *ssl = nullptr;
            BIO_get_ssl(p.get(), &ssl);
            if (ssl == nullptr)
                return p;

            //	Never bother the application with retries if the transport is blocking
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

            //
            //	set target
            //
            BIO_set_conn_hostname(p.get(), target);

            return p;
        }

        BIO_ptr create_bio_stdin() {
            //  in = BIO_new(BIO_s_file());
            //  BIO_set_fp(in, stdin, BIO_NOCLOSE|BIO_FP_TEXT);
            return BIO_ptr(BIO_new_fp(stdin, BIO_NOCLOSE), BIO_free);
        }

        BIO_ptr create_bio_stdout() { return BIO_ptr(BIO_new_fp(stdout, BIO_NOCLOSE), BIO_free); }

        BIO_ptr create_bio_stderr() { return BIO_ptr(BIO_new_fp(stderr, BIO_NOCLOSE), BIO_free); }

        BIO_ADDR_ptr create_bio_addr() { return BIO_ADDR_ptr(BIO_ADDR_new(), BIO_ADDR_free); }

        BIO_ptr_all create_bio_str(std::string const &str) {
#if OPENSSL_VERSION_NUMBER <= 0x10100003L
            return BIO_ptr_all(BIO_new_mem_buf(const_cast<char *>(certstr.data()), certstr.size()), BIO_free_all);
#else
            return BIO_ptr_all(BIO_new_mem_buf(str.data(), static_cast<int>(str.size())), BIO_free_all);
#endif
        }

        BIO *push(BIO_ptr p, BIO_ptr append) { return BIO_push(p.get(), append.get()); }

        bool reset(BIO_ptr p) {
            if (p) {
                return BIO_reset(p.get()) == OK;
            }
            return false;
        }

        std::string to_str(BIO *p) {
            if (p) {
                char *ptr = nullptr;
                auto len = BIO_get_mem_data(p, &ptr);
                return std::string(ptr, len);
            }
            return std::string{};
        }

        BIO_ptr create_bio(BIO_METHOD const *pm) { return BIO_ptr(BIO_new(pm), BIO_free); }

        BIO_ptr create_bio_s_mem() { return create_bio(BIO_s_mem()); }
        BIO_ptr create_bio_s_secmem() { return create_bio(BIO_s_secmem()); }
        BIO_ptr create_bio_s_file() { return create_bio(BIO_s_file()); }

#ifndef OPENSSL_NO_SOCK
        BIO_ptr create_bio_s_socket() { return create_bio(BIO_s_socket()); }
        BIO_ptr create_bio_s_connect() { return create_bio(BIO_s_connect()); }
        BIO_ptr create_bio_s_accept() { return create_bio(BIO_s_accept()); }
#endif
        BIO_ptr create_bio_s_fd() { return create_bio(BIO_s_fd()); }
        BIO_ptr create_bio_s_log() { return create_bio(BIO_s_log()); }
        BIO_ptr create_bio_s_bio() { return create_bio(BIO_s_bio()); }
        BIO_ptr create_bio_s_null() { return create_bio(BIO_s_null()); }
        BIO_ptr create_bio_f_null() { return create_bio(BIO_f_null()); }
        BIO_ptr create_bio_f_buffer() { return create_bio(BIO_f_buffer()); }
        BIO_ptr create_bio_f_linebuffer() { return create_bio(BIO_f_linebuffer()); }
        BIO_ptr create_bio_f_nbio_test() { return create_bio(BIO_f_nbio_test()); }

    } // namespace crypto
} // namespace cyng
