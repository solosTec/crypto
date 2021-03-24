/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#ifndef CYNG_CRYPTO_ALGO_NONE_H
#define CYNG_CRYPTO_ALGO_NONE_H

#include <string>

namespace cyng
{
	namespace crypto
	{
		namespace algorithm
		{
			class base
			{
			public:
				base(std::string const& name);

				/**
				 * @return empty string
				 */
				virtual std::string sign(const std::string&) const = 0;

				/**
				 * Check if the given signature is empty. JWT's with "none" algorithm should not contain a signature.
				 */
				virtual void verify(const std::string&, const std::string& signature) const = 0;

				/**
				 * @return algorithm name
				 */
				std::string const& name() const;

			private:
				/**
				 * name of algorithm
				 */
				std::string const alg_name_;

			};

			class none : public base
			{
			public:

				/**
				 * default constructor
				 */
				none();

				/**
				 * @return empty string
				 */
				virtual std::string sign(const std::string&) const override;

				/**
				 * Check if the given signature is empty. JWT's with "none" algorithm should not contain a signature.
				 */
				virtual void verify(const std::string&, const std::string& signature) const override;
			};
		}
	}
}

#endif	

