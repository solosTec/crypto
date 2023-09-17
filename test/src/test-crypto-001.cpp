
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Sylko Olzscher
 *
 */

#include <boost/test/unit_test.hpp>

#include <iostream>

#include <smfsec/hash/base64.h>

BOOST_AUTO_TEST_SUITE(hash)

using namespace std::string_literals;

BOOST_AUTO_TEST_CASE(base64) {
    {
        auto r0 = "grrrr shebangit!"s;
        auto r1 = cyng::crypto::base64_encode(r0);
        BOOST_CHECK_EQUAL(r1, "Z3JycnIgc2hlYmFuZ2l0IQ==");
        auto r2 = cyng::crypto::base64_decode(r1);
        BOOST_CHECK_EQUAL(r0, r2);
    }

    {
        auto r0 = "demo:demo"s;
        auto r1 = cyng::crypto::base64_encode(r0);
        BOOST_CHECK_EQUAL(r1, "ZGVtbzpkZW1v");
        auto r2 = cyng::crypto::base64_decode(r1);
        BOOST_CHECK_EQUAL(r0, r2);
    }
}
BOOST_AUTO_TEST_SUITE_END()
