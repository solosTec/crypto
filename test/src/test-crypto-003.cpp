
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#include "test-crypto-003.h"
#include <boost/test/unit_test.hpp>

#include <iostream>

#include <openssl/err.h>

#include <smfsec/generate.h>
#include <smfsec/init.h>

BOOST_AUTO_TEST_SUITE(key)

BOOST_AUTO_TEST_CASE(Priv) {
    //  init library
    cyng::crypto::ssl init;
    cyng::crypto::generate_private_key(2048);
}
BOOST_AUTO_TEST_CASE(PrivPub) {

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    // OPENSSL_no_config();

    //
    //	create a private and a public key
    //
    bool const b = cyng::crypto::generate_priv_pub_key_pair("public.pem", "private.pem", 2048);

    if (b) {

        //
        //	use private key to generate a certificate
        //
        auto r = cyng::crypto::generate_ca_cert_read(
            "private.pem",
            "mycert.pem",
            "CH",       //	country
            "LU",       //	province
            "Lucerne",  //	city
            "solosTec", //	organization
            "solostec.com",
            1,
            365);
    }

} // PrivPub
BOOST_AUTO_TEST_SUITE_END()
