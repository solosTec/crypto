/*
* The MIT License (MIT)
*
* Copyright (c) 2019 Sylko Olzscher
*
*/

#include <crypto/algorithm/none.h>

namespace cyng 
{
	namespace crypto
	{
		namespace algorithm
		{
			base::base(std::string const& name)
				: alg_name_(name)
			{}

			std::string const& base::name() const
			{
				return alg_name_;
			}


			none::none()
				: base("none")
			{}

			std::string none::sign(const std::string&) const {
				return "";
			}
			void none::verify(const std::string&, const std::string& signature) const {
				if (!signature.empty())
					throw "signature_verification_exception()";
			}
		}
	}
}
