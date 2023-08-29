
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Sylko Olzscher
 *
 */

#include "test-crypto-002.h"
#include <boost/test/unit_test.hpp>
#include <iostream>
// #include <cyng/compatibility/general.h>
#include <cyng/obj/intrinsics/aes_key.hpp>

BOOST_AUTO_TEST_SUITE(AES)

BOOST_AUTO_TEST_CASE(AES) {
    {
        //
        //	AES ECB
        //

        cyng::crypto::aes_128_key key;
        // crypto::aes::randomize(key);

        cyng::buffer_t inp{'h', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!', '\0'};
        // auto enc = crypto::aes::encrypt(inp, key);
        // auto dec = crypto::aes::decrypt(enc, key);
        // BOOST_CHECK_EQUAL(inp.size(), 14);
        // BOOST_CHECK_EQUAL(dec.size(), 16);
        // for(std::size_t idx = 0; idx < inp.size(); ++idx) {
        //     BOOST_CHECK_EQUAL(inp.at(idx), dec.at(idx));
        // }
    }

    {
        //
        //	AES CBC
        //

        cyng::crypto::aes_128_key key;
        // crypto::aes::randomize(key);

        // crypto::aes::iv_t iv;
        // BOOST_ASSERT(iv.size() == AES_BLOCK_SIZE);
        // crypto::aes::randomize(iv);

        // cyng::buffer_t inp{ 'h', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!' };
        // auto enc = crypto::aes::encrypt(inp, key, iv);
        // auto dec = crypto::aes::decrypt(enc, key, iv);

        // BOOST_CHECK_EQUAL(inp.size(), 13);
        // BOOST_CHECK_EQUAL(dec.size(), 16);
        // for(std::size_t idx = 0; idx < inp.size(); ++idx) {
        //     BOOST_CHECK_EQUAL(inp.at(idx), dec.at(idx));
        // }
    }

    {
        //	init key
        cyng::crypto::aes_128_key key;
        key.key_ = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11};

        // crypto::aes::iv_t iv{ 0x93, 0x15, 0x78, 0x56, 0x34, 0x12, 0x33, 0x03, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A
        // };

        // //	prepare input
        // cyng::buffer_t inp = cyng::make_buffer({ 0x59, 0x23, 0xc9, 0x5a, 0xaa, 0x26, 0xd1, 0xb2, 0xe7, 0x49, 0x3b, 0x01,
        // 0x3e, 0xc4, 0xa6, 0xf6 });

        // auto dec = crypto::aes::decrypt(inp, key, iv);

        // //	expected output:
        // //	2F 2F 0C 14 27 04 85 02 04 6D 32 37 1F 15 02 FD
        // BOOST_CHECK_EQUAL(dec.size(), 16);
        // if (dec.size() == 16) {

        // 	BOOST_CHECK_EQUAL((dec.at(0) & 0xFF), 0x2F);
        // 	BOOST_CHECK_EQUAL((dec.at(1) & 0xFF), 0x2F);
        // 	BOOST_CHECK_EQUAL((dec.at(15) & 0xFF), 0xFD);
        // }
    }
}
BOOST_AUTO_TEST_SUITE_END()
