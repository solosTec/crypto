
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Sylko Olzscher
 *
 */

#include <boost/test/unit_test.hpp>
#include <iostream>

#include <openssl/err.h>
// #include <smfsec/jwt.h>
#include <smfsec/cms/x509.h>
#include <smfsec/print.h>

BOOST_AUTO_TEST_SUITE(cert_suite)

BOOST_AUTO_TEST_CASE(cert) {
    // std::string token =
    // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE"; auto decoded =
    // jwt::decode(token);

    // for (auto& e : decoded.get_payload_claims())
    //	std::cout << e.first << " = " << e.second.to_json() << std::endl;

    auto s1 = cyng::crypto::read_certificate("F:\\shared\\PPC\\WAN-PKI\\bundle.pem");
    // std::cout << s.size() << std::endl;
    BOOST_REQUIRE_EQUAL(s1.size(), 2);

    // X509 const *at(std::size_t idx) const;
#ifdef _DEBUG
    cyng::crypto::print_stdout_X509(s1.at(0));
    cyng::crypto::print_stdout_X509(s1.at(1));
#endif

    auto s2 = cyng::crypto::read_certificates({"F:\\shared\\PPC\\WAN-PKI\\bundle.pem", "F:\\shared\\PPC\\WAN-PKI\\dstcax3.pem"});
    // std::cout << s2.size() << std::endl;
    BOOST_REQUIRE_EQUAL(s2.size(), 3);

#ifdef _DEBUG
    cyng::crypto::print_stdout_X509(s2.at(2));
#endif
}

//  Content of bundle.pem:
/*
subject=C = DE, O = OpenXPKI, OU = PKI, CN = OpenXPKI Demo Issuing CA 20230721

issuer=CN = OpenXPKI Root CA 20230721

-----BEGIN CERTIFICATE-----
MIIErjCCAxagAwIBAgIUe88ZyJ+a5811Mp7cBn2NELEHlkMwDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZT3BlblhQS0kgUm9vdCBDQSAyMDIzMDcyMTAeFw0yMzA3
MjEwOTI5NDBaFw0yODA3MjIwOTI5NDBaMFoxCzAJBgNVBAYTAkRFMREwDwYDVQQK
DAhPcGVuWFBLSTEMMAoGA1UECwwDUEtJMSowKAYDVQQDDCFPcGVuWFBLSSBEZW1v
IElzc3VpbmcgQ0EgMjAyMzA3MjEwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
AoIBgQCz2k8uTZ9bY/10YQVPwJWlT1D/4QQPU11H+s0a83h/SLq465WiQeLIW0MY
JhWX4XGZl+duOAQx+KXfQm2NtqevZwL3kSteK0MLkXZpMPmVXfdTuo+ault5NFyC
FdV1CUQ8N6vZGoxf6bKP6ErGLxfcXvzbbiiuyZsTbJsqziMK2UCtiIAkhKPSHXwm
3uzAQ1W0pRE/Wg1m6OUmY8GhhJrq/gqG+6bIh/32yS5W03VDSu25xBP65uq7oDn1
1JbYP/hkhf6rX4p38moKXKjZGbR4lJvH6ujp1Zqg2M09ozz0ZLr7uH58Mfa5Zyy/
b521vTrFmyqoCvLu6aiVint9N0z9IwS3YuO9EwTLWZYkwgmy9A7zghfvL8qCBlvp
p1Giysu1xkFSRUIr9tlMbm+muBGy+yQ9rOSx5cE2qSd7Qn36Lv8yEMLhHneAabgy
IpKx9H5Z4ceGYhea+wHgPgt15ubDIy661HmUjfHsUH3xE0WuZTH7gbTyxFCodIiy
GdZhk6cCAwEAAaOBoTCBnjAdBgNVHQ4EFgQU9rf2YOyOA8t+8ZcWGYfSmrsUwpEw
CwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wXwYDVR0jBFgwVoAUwXYKN73G
oU5A5Q1gNVWeuuStBmehKKQmMCQxIjAgBgNVBAMMGU9wZW5YUEtJIFJvb3QgQ0Eg
MjAyMzA3MjGCFCkcvqrjDjqbGc0oj5PBpxbEhz8aMA0GCSqGSIb3DQEBCwUAA4IB
gQCJaEvs/OqmJ7RRyBcpOPzDaifyI6Id+se1QBd5NzKx7L8N0v5AvzXPH9/Tj10N
/uGpg59bg6SuCqDqbCquPSkGX+NBz1u8SBvuF5Ec/DoVhfOxZSf7RqWfxVrJTWlL
fPRlZaJdLVY19sxNGiEcgnMnLwof1QXiT4TOUW2FJtIkDGgTntQvGXDyRKv0XvwB
YlH9nirK4RxAuj8zVSjHoZnEq2JLdAbWBW7fHPimFHHckbZSQIN3VBY0zijWiUVX
KTbS7KYhLPhCzlNoNc0jGrYT5j2X+VwwlGQiANhR5hYJXuWNXKgd2QL2AnemdNSh
IrSOVUOtgYFv4QQ8xDCWhyBjl3RQIGyZ9Op66/Oo3KN7oeTBy8nZKtBtq83mvoWt
HCREwE7QUBc6zsJpzTmk0jvhHWH6n5tUv8IixNjHehqTH1uY9DQrF+YxCMaFCZL5
IPlLGt6lBHaRnbhKLm12eUslyM1KVyS+AL+/fAOvUu72fgW5P5QtHe3Fn3B0kchE
w5w=
-----END CERTIFICATE-----

subject=CN = OpenXPKI Root CA 20230721

issuer=CN = OpenXPKI Root CA 20230721

-----BEGIN CERTIFICATE-----
MIIENjCCAp6gAwIBAgIUKRy+quMOOpsZzSiPk8GnFsSHPxowDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZT3BlblhQS0kgUm9vdCBDQSAyMDIzMDcyMTAeFw0yMzA3
MjEwOTI5MzlaFw0zMzA3MjMwOTI5MzlaMCQxIjAgBgNVBAMMGU9wZW5YUEtJIFJv
b3QgQ0EgMjAyMzA3MjEwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCt
rDIl/CoCKri9B0Qb7yr2U/kZ3S1DxfN9bqbdDIRUzay15ITRjfRiCPulawFlb80A
29f+r3Vw0nSAaTmvjGWLc5I9DtkePZDUc9xk/ZzdfFVLQdyfEEtjrZ2oGkGT7sL2
wPqkWas39IyX7IF3tEtR4VThwz36GrPM1zLig5iNavHCp0xb9KdUem8n32GV+ala
9LdfksqPysJ7ldshqOKhN7GbkLpnDFvYyunakk+fpbGwdux1zKng/y+17Ws9WqEQ
OsI9QtU0HSyohwF39ejOkeyyEhwXKkanvqA9KEiAXCck0iT8XPeaFWSaLMl/Zc+t
6UKvvhnP9S8wI9FNfB3ChoGLr/Z8uPwgRdJyg473Tp2pdBmVQmcnUpzPqq78BnEW
cwXYV3/tgGH4P/fM8ZGUwTD0ck28JCmo0dxDIUnXUr+pTxRc1kVb/XrQD6RX6F9X
u56P/pJxYx2r/Wd+mPK9cAcDZtpJaqRFbXNgox4CAkyuJ8A+HhHZWeEV9XMSPe0C
AwEAAaNgMF4wHQYDVR0OBBYEFMF2Cje9xqFOQOUNYDVVnrrkrQZnMAsGA1UdDwQE
AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFMF2Cje9xqFOQOUNYDVV
nrrkrQZnMA0GCSqGSIb3DQEBCwUAA4IBgQCb8pgsjS6jpgMx2AERF15qQ/6KfWwU
05+nhgXJj0WRm06Zli2IQEM5T5U4mFdWnZEh15ZOU7ecg6uJMlrXJv2XnwawvsOR
lesKU9xUa5WWkKixxF29dTsz6sK2SfqAzNP/noiizZBqjjwqNO5Gg+eOWb5LcE5X
L0AFpbMUS3znSphFo/7vqVSINue8OnAbZJP40XVEeyhHcaN/3gtXbHwckieilf6c
lU5820yssrKphQhMPEnc339GlC6Pb2t4doFdC+fIRw7nnljKqN1mBPGhUpdmaQoC
IZlEIo1MiHBoqWLUoHV76bdDQpO1BDFGiKEccBcDqtNa/9dzbhmV8VbnNTLH4/VN
EBZsUbwhZC63o+0RFRSE6vxpu5xxx+XZFRefZd8sxCn5i6JXgm3vdGcRRAB5iXWh
Nacl86uz+1+es2np+9N15zEeaLGmqVKPuXT5uYkv9a4rWfV0nnvHpFDmlc3GQ8OQ
5V26qtfFjF2IbVEoHiwkRi86oOvRvpcgXgI=
-----END CERTIFICATE-----
*/

/*
    308204ae30820316a00302010202147bcf19c89f9ae7cd75329edc067d8d10b1079643300d06092a864886f70d01010b050030243122302006035504030c194f70656e58504b4920526f6f74204341203230323330373231301e170d3233303732313039323934305a170d3238303732323039323934305a305a310b30090603550406130244453111300f060355040a0c084f70656e58504b49310c300a060355040b0c03504b49312a302806035504030c214f70656e58504b492044656d6f2049737375696e67204341203230323330373231308201a2300d06092a864886f70d01010105000382018f003082018a02820181
    00b3da4f2e4d9f5b63fd7461054fc095a54f50ffe1040f535d47facd1af3787f48bab8eb95a241e2c85b4318261597e1719997e76e380431f8a5df426d8db6a7af6702f7912b5e2b430b91766930f9955df753ba8f9aba5b79345c8215d57509443c37abd91a8c5fe9b28fe84ac62f17dc5efcdb6e28aec99b136c9b2ace230ad940ad88802484a3d21d7c26deecc04355b4a5113f5a0d66e8e52663c1a1849aeafe0a86fba6c887fdf6c92e56d375434aedb9c413fae6eabba039f5d496d83ff86485feab5f8a77f26a0a5ca8d919b478949bc7eae8e9d59aa0d8cd3da33cf464bafbb87e7c31f6b9672cbf6f9db5bd3ac59b2aa80af2eee9a8958a7b7d374cfd2304b762e3bd1304cb599624c209b2f40ef38217ef2fca82065be9a751a2cacbb5c6415245422bf6d94c6e6fa6b811b2fb243dace4b1e5c136a9277b427dfa2eff3210c2e11e778069b8322292b1f47e59e1c78662179afb01e03e0b75e6e6c3232ebad479948df1ec507df11345ae6531fb81b4f2c450a87488b219d66193a70203010001a381a130819e301d0603551d0e04160414
    f6b7f660ec8e03cb7ef197161987d29abb14c291300b0603551d0f040403020186300f0603551d130101ff040530030101ff305f0603551d23045830568014
    c1760a37bdc6a14e40e50d6035559ebae4ad0667a128a42630243122302006035504030c194f70656e58504b4920526f6f742043412032303233303732318214291cbeaae30e3a9b19cd288f93c1a716c4873f1a300d06092a864886f70d01010b05000382018100
    89684becfceaa627b451c8172938fcc36a27f223a21dfac7b54017793732b1ecbf0dd2fe40bf35cf1fdfd38f5d0dfee1a9839f5b83a4ae0aa0ea6c2aae3d29065fe341cf5bbc481bee17911cfc3a1585f3b16527fb46a59fc55ac94d694b7cf46565a25d2d5635f6cc4d1a211c8273272f0a1fd505e24f84ce516d8526d2240c68139ed42f1970f244abf45efc016251fd9e2acae11c40ba3f335528c7a199c4ab624b7406d6056edf1cf8a61471dc91b652408377541634ce28d68945572936d2eca6212cf842ce536835cd231ab613e63d97f95c3094642200d851e616095ee58d5ca81dd902f60277a674d4a122b48e5543ad81816fe1043cc43096872063977450206c99f4ea7aebf3a8dca37ba1e4c1cbc9d92ad06dabcde6be85ad1c2444c04ed050173acec269cd39a4d23be11d61fa9f9b54bfc222c4d8c77a1a931f5b98f4342b17e63108c6850992f920f94b1adea50476919db84a2e6d76794b25c8cd4a5724be00bfbf7c03af52eef67e05b93f942d1dedc59f707491c844c39c

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7b:cf:19:c8:9f:9a:e7:cd:75:32:9e:dc:06:7d:8d:10:b1:07:96:43
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=OpenXPKI Root CA 20230721
        Validity
            Not Before: Jul 21 09:29:40 2023 GMT
            Not After : Jul 22 09:29:40 2028 GMT
        Subject: C=DE, O=OpenXPKI, OU=PKI, CN=OpenXPKI Demo Issuing CA 20230721
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (3072 bit)
                Modulus:
                    00:b3:da:4f:2e:4d:9f:5b:63:fd:74:61:05:4f:c0:
                    95:a5:4f:50:ff:e1:04:0f:53:5d:47:fa:cd:1a:f3:
                    78:7f:48:ba:b8:eb:95:a2:41:e2:c8:5b:43:18:26:
                    15:97:e1:71:99:97:e7:6e:38:04:31:f8:a5:df:42:
                    6d:8d:b6:a7:af:67:02:f7:91:2b:5e:2b:43:0b:91:
                    76:69:30:f9:95:5d:f7:53:ba:8f:9a:ba:5b:79:34:
                    5c:82:15:d5:75:09:44:3c:37:ab:d9:1a:8c:5f:e9:
                    b2:8f:e8:4a:c6:2f:17:dc:5e:fc:db:6e:28:ae:c9:
                    9b:13:6c:9b:2a:ce:23:0a:d9:40:ad:88:80:24:84:
                    a3:d2:1d:7c:26:de:ec:c0:43:55:b4:a5:11:3f:5a:
                    0d:66:e8:e5:26:63:c1:a1:84:9a:ea:fe:0a:86:fb:
                    a6:c8:87:fd:f6:c9:2e:56:d3:75:43:4a:ed:b9:c4:
                    13:fa:e6:ea:bb:a0:39:f5:d4:96:d8:3f:f8:64:85:
                    fe:ab:5f:8a:77:f2:6a:0a:5c:a8:d9:19:b4:78:94:
                    9b:c7:ea:e8:e9:d5:9a:a0:d8:cd:3d:a3:3c:f4:64:
                    ba:fb:b8:7e:7c:31:f6:b9:67:2c:bf:6f:9d:b5:bd:
                    3a:c5:9b:2a:a8:0a:f2:ee:e9:a8:95:8a:7b:7d:37:
                    4c:fd:23:04:b7:62:e3:bd:13:04:cb:59:96:24:c2:
                    09:b2:f4:0e:f3:82:17:ef:2f:ca:82:06:5b:e9:a7:
                    51:a2:ca:cb:b5:c6:41:52:45:42:2b:f6:d9:4c:6e:
                    6f:a6:b8:11:b2:fb:24:3d:ac:e4:b1:e5:c1:36:a9:
                    27:7b:42:7d:fa:2e:ff:32:10:c2:e1:1e:77:80:69:
                    b8:32:22:92:b1:f4:7e:59:e1:c7:86:62:17:9a:fb:
                    01:e0:3e:0b:75:e6:e6:c3:23:2e:ba:d4:79:94:8d:
                    f1:ec:50:7d:f1:13:45:ae:65:31:fb:81:b4:f2:c4:
                    50:a8:74:88:b2:19:d6:61:93:a7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                F6:B7:F6:60:EC:8E:03:CB:7E:F1:97:16:19:87:D2:9A:BB:14:C2:91
            X509v3 Key Usage:
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Authority Key Identifier:
                keyid:C1:76:0A:37:BD:C6:A1:4E:40:E5:0D:60:35:55:9E:BA:E4:AD:06:67
                DirName:/CN=OpenXPKI Root CA 20230721
                serial:29:1C:BE:AA:E3:0E:3A:9B:19:CD:28:8F:93:C1:A7:16:C4:87:3F:1A
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        89:68:4b:ec:fc:ea:a6:27:b4:51:c8:17:29:38:fc:c3:6a:27:
        f2:23:a2:1d:fa:c7:b5:40:17:79:37:32:b1:ec:bf:0d:d2:fe:
        40:bf:35:cf:1f:df:d3:8f:5d:0d:fe:e1:a9:83:9f:5b:83:a4:
        ae:0a:a0:ea:6c:2a:ae:3d:29:06:5f:e3:41:cf:5b:bc:48:1b:
        ee:17:91:1c:fc:3a:15:85:f3:b1:65:27:fb:46:a5:9f:c5:5a:
        c9:4d:69:4b:7c:f4:65:65:a2:5d:2d:56:35:f6:cc:4d:1a:21:
        1c:82:73:27:2f:0a:1f:d5:05:e2:4f:84:ce:51:6d:85:26:d2:
        24:0c:68:13:9e:d4:2f:19:70:f2:44:ab:f4:5e:fc:01:62:51:
        fd:9e:2a:ca:e1:1c:40:ba:3f:33:55:28:c7:a1:99:c4:ab:62:
        4b:74:06:d6:05:6e:df:1c:f8:a6:14:71:dc:91:b6:52:40:83:
        77:54:16:34:ce:28:d6:89:45:57:29:36:d2:ec:a6:21:2c:f8:
        42:ce:53:68:35:cd:23:1a:b6:13:e6:3d:97:f9:5c:30:94:64:
        22:00:d8:51:e6:16:09:5e:e5:8d:5c:a8:1d:d9:02:f6:02:77:
        a6:74:d4:a1:22:b4:8e:55:43:ad:81:81:6f:e1:04:3c:c4:30:
        96:87:20:63:97:74:50:20:6c:99:f4:ea:7a:eb:f3:a8:dc:a3:
        7b:a1:e4:c1:cb:c9:d9:2a:d0:6d:ab:cd:e6:be:85:ad:1c:24:
        44:c0:4e:d0:50:17:3a:ce:c2:69:cd:39:a4:d2:3b:e1:1d:61:
        fa:9f:9b:54:bf:c2:22:c4:d8:c7:7a:1a:93:1f:5b:98:f4:34:
        2b:17:e6:31:08:c6:85:09:92:f9:20:f9:4b:1a:de:a5:04:76:
        91:9d:b8:4a:2e:6d:76:79:4b:25:c8:cd:4a:57:24:be:00:bf:
        bf:7c:03:af:52:ee:f6:7e:05:b9:3f:94:2d:1d:ed:c5:9f:70:
        74:91:c8:44:c3:9c
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            29:1c:be:aa:e3:0e:3a:9b:19:cd:28:8f:93:c1:a7:16:c4:87:3f:1a
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=OpenXPKI Root CA 20230721
        Validity
            Not Before: Jul 21 09:29:39 2023 GMT
            Not After : Jul 23 09:29:39 2033 GMT
        Subject: CN=OpenXPKI Root CA 20230721
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (3072 bit)
                Modulus:
                    00:ad:ac:32:25:fc:2a:02:2a:b8:bd:07:44:1b:ef:
                    2a:f6:53:f9:19:dd:2d:43:c5:f3:7d:6e:a6:dd:0c:
                    84:54:cd:ac:b5:e4:84:d1:8d:f4:62:08:fb:a5:6b:
                    01:65:6f:cd:00:db:d7:fe:af:75:70:d2:74:80:69:
                    39:af:8c:65:8b:73:92:3d:0e:d9:1e:3d:90:d4:73:
                    dc:64:fd:9c:dd:7c:55:4b:41:dc:9f:10:4b:63:ad:
                    9d:a8:1a:41:93:ee:c2:f6:c0:fa:a4:59:ab:37:f4:
                    8c:97:ec:81:77:b4:4b:51:e1:54:e1:c3:3d:fa:1a:
                    b3:cc:d7:32:e2:83:98:8d:6a:f1:c2:a7:4c:5b:f4:
                    a7:54:7a:6f:27:df:61:95:f9:a9:5a:f4:b7:5f:92:
                    ca:8f:ca:c2:7b:95:db:21:a8:e2:a1:37:b1:9b:90:
                    ba:67:0c:5b:d8:ca:e9:da:92:4f:9f:a5:b1:b0:76:
                    ec:75:cc:a9:e0:ff:2f:b5:ed:6b:3d:5a:a1:10:3a:
                    c2:3d:42:d5:34:1d:2c:a8:87:01:77:f5:e8:ce:91:
                    ec:b2:12:1c:17:2a:46:a7:be:a0:3d:28:48:80:5c:
                    27:24:d2:24:fc:5c:f7:9a:15:64:9a:2c:c9:7f:65:
                    cf:ad:e9:42:af:be:19:cf:f5:2f:30:23:d1:4d:7c:
                    1d:c2:86:81:8b:af:f6:7c:b8:fc:20:45:d2:72:83:
                    8e:f7:4e:9d:a9:74:19:95:42:67:27:52:9c:cf:aa:
                    ae:fc:06:71:16:73:05:d8:57:7f:ed:80:61:f8:3f:
                    f7:cc:f1:91:94:c1:30:f4:72:4d:bc:24:29:a8:d1:
                    dc:43:21:49:d7:52:bf:a9:4f:14:5c:d6:45:5b:fd:
                    7a:d0:0f:a4:57:e8:5f:57:bb:9e:8f:fe:92:71:63:
                    1d:ab:fd:67:7e:98:f2:bd:70:07:03:66:da:49:6a:
                    a4:45:6d:73:60:a3:1e:02:02:4c:ae:27:c0:3e:1e:
                    11:d9:59:e1:15:f5:73:12:3d:ed
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                C1:76:0A:37:BD:C6:A1:4E:40:E5:0D:60:35:55:9E:BA:E4:AD:06:67
            X509v3 Key Usage:
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Authority Key Identifier:
                C1:76:0A:37:BD:C6:A1:4E:40:E5:0D:60:35:55:9E:BA:E4:AD:06:67
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        9b:f2:98:2c:8d:2e:a3:a6:03:31:d8:01:11:17:5e:6a:43:fe:
        8a:7d:6c:14:d3:9f:a7:86:05:c9:8f:45:91:9b:4e:99:96:2d:
        88:40:43:39:4f:95:38:98:57:56:9d:91:21:d7:96:4e:53:b7:
        9c:83:ab:89:32:5a:d7:26:fd:97:9f:06:b0:be:c3:91:95:eb:
        0a:53:dc:54:6b:95:96:90:a8:b1:c4:5d:bd:75:3b:33:ea:c2:
        b6:49:fa:80:cc:d3:ff:9e:88:a2:cd:90:6a:8e:3c:2a:34:ee:
        46:83:e7:8e:59:be:4b:70:4e:57:2f:40:05:a5:b3:14:4b:7c:
        e7:4a:98:45:a3:fe:ef:a9:54:88:36:e7:bc:3a:70:1b:64:93:
        f8:d1:75:44:7b:28:47:71:a3:7f:de:0b:57:6c:7c:1c:92:27:
        a2:95:fe:9c:95:4e:7c:db:4c:ac:b2:b2:a9:85:08:4c:3c:49:
        dc:df:7f:46:94:2e:8f:6f:6b:78:76:81:5d:0b:e7:c8:47:0e:
        e7:9e:58:ca:a8:dd:66:04:f1:a1:52:97:66:69:0a:02:21:99:
        44:22:8d:4c:88:70:68:a9:62:d4:a0:75:7b:e9:b7:43:42:93:
        b5:04:31:46:88:a1:1c:70:17:03:aa:d3:5a:ff:d7:73:6e:19:
        95:f1:56:e7:35:32:c7:e3:f5:4d:10:16:6c:51:bc:21:64:2e:
        b7:a3:ed:11:15:14:84:ea:fc:69:bb:9c:71:c7:e5:d9:15:17:
        9f:65:df:2c:c4:29:f9:8b:a2:57:82:6d:ef:74:67:11:44:00:
        79:89:75:a1:35:a7:25:f3:ab:b3:fb:5f:9e:b3:69:e9:fb:d3:
        75:e7:31:1e:68:b1:a6:a9:52:8f:b9:74:f9:b9:89:2f:f5:ae:
        2b:59:f5:74:9e:7b:c7:a4:50:e6:95:cd:c6:43:c3:90:e5:5d:
        ba:aa:d7:c5:8c:5d:88:6d:51:28:1e:2c:24:46:2f:3a:a0:eb:
        d1:be:97:20:5e:02
*/
BOOST_AUTO_TEST_SUITE_END()
