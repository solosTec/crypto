
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Sylko Olzscher
 *
 */

#include <boost/test/unit_test.hpp>
#include <iostream>

#include <openssl/err.h>
#include <smfsec/bignum.h>
#include <smfsec/cms/x509.h>
#include <smfsec/print.h>

BOOST_AUTO_TEST_SUITE(BN_suite)

BOOST_AUTO_TEST_CASE(bignum) {

    cyng::crypto::bn n1("1");
    cyng::crypto::bn const n2("42");
    cyng::crypto::bn const n3(42);
    std::cout << n2.to_dec_string() << ", 0x" << n2.to_hex_string() << std::endl;

    if (n2 == n3) {
        std::cout << n2 << " equal " << n3 << std::endl;
    }
    if (n1 < n3) {
        std::cout << n1 << " less " << n3 << std::endl;
    }
    std::cout << n1.operator std::string() << " + " << n2.operator std::string() << " = " << (n1 + n2).operator std::string()
              << std::endl;

    n1 += n3;
    std::cout << n1.operator std::string() << " + " << n2.operator std::string() << " = " << (n1 + n2).operator std::string()
              << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
