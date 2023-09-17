
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#include <boost/test/unit_test.hpp>

#include <iostream>
#include <openssl/err.h>

#include <smfsec/bio.h>
#include <smfsec/print.h>

BOOST_AUTO_TEST_SUITE(BIOsuite)

BOOST_AUTO_TEST_CASE(basics) {

    // auto dec = crypto::hash_string("hello, world", "sha256");

    ////
    ////	result is: 09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b
    ////
    // BOOST_CHECK_EQUAL(dec.size(), 32);

    // BOOST_CHECK_EQUAL(dec.at(0), 0x09);
    // BOOST_CHECK_EQUAL(dec.at(1), 0xca);
    // BOOST_CHECK_EQUAL(dec.at(31), 0x5b);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    // OPENSSL_no_config();

    typedef BIO *(*func1)(const char *, const char *);
    func1 f1 = &BIO_new_file;

    using func2 = BIO *(*)(FILE *, int);
    cyng::crypto::bio::stream<func2> m2(&BIO_new_fp);

    cyng::crypto::bio::stream<cyng::crypto::bio::m0> m3(&BIO_s_mem);
    m3.create(true);

    // cyng::crypto::bio::method<BIO *(*)(FILE *, int)> m(&BIO_new_file);

    // crypto::dump_evp("private.pem");
    // crypto::dump_evp("cakey.pem");
    // debug build only
    // cyng::crypto::dump_x509("mySignedCert.pem");

} // namespace cyng
BOOST_AUTO_TEST_SUITE_END()
