/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2019 Sylko Olzscher 
 * 
 */ 

#define BOOST_TEST_MODULE CRYPTO
#include <boost/test/unit_test.hpp>


#include "test-crypto-003.h"
#include "test-crypto-004.h"
#include "test-crypto-005.h"

BOOST_AUTO_TEST_SUITE(CRYPTO)
BOOST_AUTO_TEST_CASE(crypto_003)
{
	using namespace cyng;
	BOOST_CHECK(test_crypto_003());
}
BOOST_AUTO_TEST_CASE(crypto_004)
{
	using namespace cyng;
	BOOST_CHECK(test_crypto_004());
}
BOOST_AUTO_TEST_CASE(crypto_005)
{
	using namespace cyng;
	BOOST_CHECK(test_crypto_005());
}
BOOST_AUTO_TEST_SUITE_END()	//	CRYPTO

