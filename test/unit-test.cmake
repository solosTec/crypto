# 
#	reset 
#
set (unit_test)

set (unit_test_cpp
	test/src/main.cpp
	test/src/test-crypto-003.cpp
	test/src/test-crypto-004.cpp
	test/src/test-crypto-005.cpp
)
    
set (unit_test_h
    include/cyng/crypto.h
	test/src/test-crypto-003.h
	test/src/test-crypto-004.h
	test/src/test-crypto-005.h
)


# define the unit test
set (unit_test
  ${unit_test_cpp}
  ${unit_test_h}
)

