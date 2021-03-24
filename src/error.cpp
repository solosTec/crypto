/*
* The MIT License (MIT)
*
* Copyright (c) 2020 Sylko Olzscher
*
*/

#include <smfsec/error.h>

namespace cyng 
{
	namespace crypto
	{
		std::string get_error_msg()
		{
			auto const ec = ERR_get_error();
			char buf[256] = { 0 };
			::ERR_error_string_n(ec, buf, sizeof(buf));
			return std::string(buf);
		}

	}
}
