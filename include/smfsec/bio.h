/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_BIO_H
#define CYNG_CRYPTO_BIO_H

#include <smfsec/crypto.h>
#include <string>

namespace cyng {
    namespace crypto {
        /**
         * Create a BIO nullptr
         */
        BIO_ptr create_bio();

        /**
         * Generates a BIO object
         * Example:
         @ccode
         auto bp = create_bio("public.pem", "w+");
         @endcode
         */
        BIO_ptr create_bio_file(const char *filename, const char *mode);
        BIO_ptr create_bio_file_read(const char *filename);
        BIO_ptr create_bio_file_write(const char *filename);
        /**
         * append
         */
        BIO_ptr create_bio_file_a(const char *filename);

        /**
         *  Flags can be: BIO_CLOSE, BIO_NOCLOSE (the close flag) BIO_FP_TEXT
         */
        BIO_ptr create_bio_fp(FILE *stream, int flags);

        /**
         * Doesn't support BIO_gets() or BIO_puts().
         * The flag BIO_FLAGS_BASE64_NO_NL can be set with BIO_set_flags()
         * to encode the data all on one line or expect the data to be all
         * on one line.
         */
        BIO_ptr_all create_bio_base64();

        /**
         * Be carefull when using a smart pointer with BIO_push().
         * After BIO_push() the memory is managed by the BIO (free_all) so you have to release
         * the pointer first:
         *
         * @param eof if eof is true then BIO_set_mem_eof_return(bio, -1); is called.
         *
         * example:
         @code
                auto b64 = create_bio_base64();
                auto bmem = create_bio_s_mem(false);
                bmem = ::BIO_push(b64.get(), bmem.release());
         @endcode
         */
        BIO_ptr create_bio_s_mem(bool eof);

        /**
         * example:
         * @code
         auto biop = create_bio_socket(stdout, BIO_NOCLOSE);
         * @endcode
         */
        BIO_ptr create_bio_socket(int sock, int close_flag);

        /**
         * Create an un-encrypted connection
         *
         * example:
         * @code
         auto biop = create_bio_connection("hostname:port");
         * @endcode
         */
        BIO_ptr create_bio_connection(const char *target);

        /**
         * Prepare an encrypted connection in SSL_MODE_AUTO_RETRY mode.
         *
         * example:
         * @code
         auto biop = create_bio_ssl_connection(ctx, "hostname:port");
         * @endcode
         */
        BIO_ptr create_bio_ssl_connection(SSL_CTX *ctx, const char *target);

        /**
         * using stdin
         */
        BIO_ptr create_bio_stdin();

        /**
         * using stdout
         */
        BIO_ptr create_bio_stdout();

        /**
         * using stderr
         */
        BIO_ptr create_bio_stderr();

        /**
         * The BIO_ADDR type is a wrapper around all types of socket addresses.
         */
        BIO_ADDR_ptr create_bio_addr();

        /**
         * Create BIO ptr from string (certificate)
         */
        BIO_ptr_all create_bio_str(std::string const &str);

        /**
         * Joins two BIO chains.
         * @return pointer of p
         */
        BIO *push(BIO_ptr p, BIO_ptr append);

        /**
         * resets BIO to initial state
         */
        bool reset(BIO_ptr);

        /**
         * get data from BIO as string
         */
        std::string to_str(BIO *);

        /**
         * There gazillions of BIO methods
         */
        BIO_ptr create_bio(BIO_METHOD const *);
        BIO_ptr create_bio_s_mem();
        BIO_ptr create_bio_s_secmem();
        BIO_ptr create_bio_s_file();
#ifndef OPENSSL_NO_SOCK
        BIO_ptr create_bio_s_socket();
        BIO_ptr create_bio_s_connect();
        BIO_ptr create_bio_s_accept();
#endif
        BIO_ptr create_bio_s_fd();
        BIO_ptr create_bio_s_log();
        BIO_ptr create_bio_s_bio();
        BIO_ptr create_bio_s_null();
        BIO_ptr create_bio_f_null();
        BIO_ptr create_bio_f_buffer();
        BIO_ptr create_bio_f_linebuffer();
        BIO_ptr create_bio_f_nbio_test();

    } // namespace crypto
} // namespace cyng

#endif
