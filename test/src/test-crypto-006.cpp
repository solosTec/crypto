
/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2020 Sylko Olzscher 
 * 
 */ 

#include "test-crypto-006.h"
#include <iostream>
#include <boost/test/unit_test.hpp>
#include <crypto/jwt.h>
#include <openssl/err.h>

namespace cyng 
{
	bool test_crypto_006()
	{

		std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
		//auto decoded = jwt::decode(token);

		//for (auto& e : decoded.get_payload_claims())
		//	std::cout << e.first << " = " << e.second.to_json() << std::endl;

		return true;
	}
	
}
