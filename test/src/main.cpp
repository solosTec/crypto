/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#define BOOST_TEST_MODULE CRYPTO
#include <boost/test/unit_test.hpp>

//
//	fix for "no OPENSSL_Applink" error
//	at runtime
//
extern "C" {
#include <openssl/applink.c>
}
