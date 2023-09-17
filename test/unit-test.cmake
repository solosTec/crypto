# 
#	reset 
#
set (unit_test)

set (unit_test_cpp
	test/src/main.cpp
	test/src/test-crypto-001.cpp
	test/src/test-crypto-002.cpp
	test/src/test-crypto-003.cpp
	test/src/test-crypto-004.cpp
	test/src/test-crypto-005.cpp
	test/src/test-crypto-006.cpp
	test/src/test-crypto-007.cpp
)
    
set (unit_test_h
    include/smfsec/crypto.h
#	test/src/test-crypto-001.h
#	test/src/test-crypto-002.h
#	test/src/test-crypto-003.h
#	test/src/test-crypto-004.h
#	test/src/test-crypto-005.h
#	test/src/test-crypto-006.h
)


# define the unit test
set (unit_test
  ${unit_test_cpp}
#  ${unit_test_h}
)

