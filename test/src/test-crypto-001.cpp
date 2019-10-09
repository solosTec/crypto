
/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Sylko Olzscher 
 * 
 */ 

#include "test-crypto-001.h"
#include <iostream>
#include <boost/test/unit_test.hpp>
#include <crypto/base64.h>


namespace cyng 
{
    using namespace std::string_literals;

	bool test_crypto_001()
	{
		{
 			auto r0 = "grrrr shebangit!"s;
			auto r1 = crypto::base64_encode(r0);
			BOOST_CHECK_EQUAL(r1, "Z3JycnIgc2hlYmFuZ2l0IQ==");
			auto r2 = crypto::base64_decode(r1);
			BOOST_CHECK_EQUAL(r0, r2);
		}
		
		{
			auto r0 = "demo:demo"s;
			auto r1 = crypto::base64_encode(r0);
			BOOST_CHECK_EQUAL(r1, "ZGVtbzpkZW1v");
			auto r2 = crypto::base64_decode(r1);
			BOOST_CHECK_EQUAL(r0, r2);
		}
		
		return true;
	}
	
}
