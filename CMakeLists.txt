cmake_minimum_required (VERSION 3.10)

#
# set project name/properties
#
project(CRYPT
	VERSION 0.0.1
	LANGUAGES CXX C
	DESCRIPTION "C++ wrapper for OpenSLL - companion of CYNG library")


message(STATUS "**")  
message(STATUS "**                                                        *                 ")
message(STATUS "**                                                       **                 ")
message(STATUS "**                                                       **                 ")
message(STATUS "**             ***  ****    **   ****         ****     ********    ****     ")
message(STATUS "**     ****     **** **** *  **    ***  *    * ***  * ********    * ***  *  ")
message(STATUS "**    * ***  *   **   ****   **     ****    *   ****     **      *   ****   ")
message(STATUS "**   *   ****    **          **      **    **    **      **     **    **    ")
message(STATUS "**  **           **          **      **    **    **      **     **    **    ")
message(STATUS "**  **           **          **      **    **    **      **     **    **    ")
message(STATUS "**  **           **          **      **    **    **      **     **    **    ")
message(STATUS "**  **           **          **      **    **    **      **     **    **    ")
message(STATUS "**  ***     *    ***          *********    *******       **      ******     ")
message(STATUS "**   *******      ***           **** ***   ******         **      ****      ")
message(STATUS "**    *****                           ***  **                               ")
message(STATUS "**                             *****   *** **                               ")
message(STATUS "**                           ********  **  **                               ")
message(STATUS "**                          *      ****     **                              ")
message(STATUS "**")

if (CMAKE_COMPILER_IS_GNUCXX)
    set(GLOBAL_LIBRARY_TYPE SHARED)
elseif(MSVC)
    set(GLOBAL_LIBRARY_TYPE STATIC)
endif(CMAKE_COMPILER_IS_GNUCXX)

#
# guard against in-source builds and bad build-type strings
#
include(cmake/safeguards.cmake)

#
# place binaries and libraries according to GNU standards
#
include(GNUInstallDirs)

#
#	OpenSSL
#
find_package(OpenSSL 1.1.0 REQUIRED)
if(OPENSSL_FOUND)
	message(STATUS "** openSSL Include       : ${OPENSSL_INCLUDE_DIR}")
	message(STATUS "** openSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")
	message(STATUS "** openSSL SSL library   : ${OPENSSL_SSL_LIBRARY}")
	message(STATUS "** openSSL Libraries     : ${OPENSSL_LIBRARIES}")

#    include_directories(${OPENSSL_INCLUDE_DIR})
#    link_directories(${OPENSSL_LIBRARIES})

endif(OPENSSL_FOUND)

#
#	CYNG library
#
if(NOT DEFINED CYNG_ROOT)
	set(CYNG_ROOT "${PROJECT_SOURCE_DIR}/../cyng" CACHE PATH "cyng develop root directory")
endif()
get_filename_component(CYNG_ROOT ${CYNG_ROOT} REALPATH)
message(STATUS "** CYNG root             : ${CYNG_ROOT}")

if(NOT DEFINED CYNG_INCLUDE)
	set(CYNG_INCLUDE "${CYNG_ROOT}/src/main/include" CACHE PATH "cyng include directory")
endif()
message(STATUS "** CYNG include          : ${CYNG_INCLUDE}")

if(NOT DEFINED CYNG_LIBRARY)
	set(CYNG_LIBRARY "${CYNG_ROOT}/build" CACHE PATH "cyng library directory")
endif()
message(STATUS "** CYNG library          : ${CYNG_LIBRARY}")

add_library(cyng_core SHARED IMPORTED)
set_property(TARGET cyng_core 
	PROPERTY 
		IMPORTED_LOCATION ${CYNG_LIBRARY}/cyng_core
		PUBLIC_HEADER ${CYNG_INCLUDE})


set (crypto_hash
	src/hash/base64.cpp
	src/hash/md5.cpp
	src/hash/sha1.cpp
	src/hash/sha256.cpp
	src/hash/sha512.cpp
	include/crypto/hash/base64.h
	include/crypto/hash/md5.h
	include/crypto/hash/sha1.h
	include/crypto/hash/sha256.h
	include/crypto/hash/sha512.h
)

set (crypto_algorithm
	src/algorithm/none.cpp
	src/algorithm/hmacsha.cpp
	src/algorithm/rsa.cpp
	src/algorithm/ecdsa.cpp
	src/algorithm/pss.cpp
	include/crypto/algorithm/none.h
	include/crypto/algorithm/hmacsha.h
	include/crypto/algorithm/rsa.h
	include/crypto/algorithm/ecdsa.h
	include/crypto/algorithm/pss.h
)

source_group("hash" FILES ${crypto_hash})
source_group("algorithm" FILES ${crypto_algorithm})


#
#	define the crypto library
#
add_library(crypto ${GLOBAL_LIBRARY_TYPE} 
	include/crypto/crypto.h
	src/bio.cpp 
	src/factory.cpp 
	src/init.cpp 
	src/error.cpp 
	src/bignum.cpp 
	src/print.cpp 
	src/read.cpp 
	src/write.cpp 
	src/generate.cpp 
	src/aes.cpp
	src/jwt.cpp
	src/signatures.cpp
	${crypto_hash}
	${crypto_algorithm})
target_compile_features(crypto PRIVATE cxx_std_11)

target_include_directories(crypto
    PUBLIC 
        $<INSTALL_INTERFACE:include>    
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include;${OPENSSL_INCLUDE_DIR}>"
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
		${CYNG_INCLUDE}
)

target_link_libraries(crypto
    PUBLIC
        ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} 
    PRIVATE
        ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY}
)

set_target_properties(crypto 
	PROPERTIES PUBLIC_HEADER 
		"include/crypto/crypto.h;include/crypto/aes.h;include/crypto/bignum.h;include/crypto/bio.h;include/crypto/crypto.h;include/crypto/digest.h;include/crypto/error.h;include/crypto/factory.h;include/crypto/generate.h;include/crypto/init.h;include/crypto/jwt.h;include/crypto/print.h;include/crypto/read.h;include/crypto/signatures.h;include/crypto/write.h;include/crypto/algorithm/ecdsa.h;include/crypto/algorithm/hmacsha.h;include/crypto/algorithm/none.h;include/crypto/algorithm/pss.h;include/crypto/algorithm/rsa.h;include/crypto/hash/base64.h;include/crypto/hash/md5.h;include/crypto/hash/sha1.h;include/crypto/hash/sha256.h;include/crypto/hash/sha512.h")

include(GNUInstallDirs)
install(TARGETS crypto
	LIBRARY DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	INCLUDES DESTINATION 
        ${CMAKE_INSTALL_INCLUDEDIR}/crypto
	PUBLIC_HEADER DESTINATION 
	${CMAKE_INSTALL_INCLUDEDIR}/crypto)

include(GNUInstallDirs)
install(TARGETS crypto
	LIBRARY DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	INCLUDES DESTINATION 
        ${CMAKE_INSTALL_INCLUDEDIR}/crypto)


#
# manage unit test: CRYPT_BUILD_TEST
# default is OFF
#
if(NOT DEFINED ${PROJECT_NAME}_BUILD_TEST)
	set(${PROJECT_NAME}_BUILD_TEST OFF CACHE BOOL "build unit test")
endif()

#
#	Boost is only required to build the unit test
#
if(${PROJECT_NAME}_BUILD_TEST)

	find_package(Boost 1.70 REQUIRED COMPONENTS unit_test_framework)
	if(Boost_FOUND)
		include (test/unit-test.cmake)
		add_executable(unit_test ${unit_test})

		set_property(
			TARGET unit_test
			PROPERTY COMPILE_DEFINITIONS BOOST_TEST_DYN_LINK)

		target_include_directories(unit_test
			PRIVATE
				$<INSTALL_INTERFACE:include>    
				${CYNG_INCLUDE}
				"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include;${Boost_INCLUDE_DIRS};${OPENSSL_INCLUDE_DIR}>"
				${CMAKE_CURRENT_SOURCE_DIR}/src
		)

		target_link_libraries(unit_test
			PRIVATE
				crypto 
				"$<$<PLATFORM_ID:Linux>:${CYNG_LIBRARY}/cyng_core.so>"
				"$<$<PLATFORM_ID:Windows>:${CYNG_LIBRARY}/Debug/cyng_core.lib>"
				${OPENSSL_CRYPTO_LIBRARY} 
				${OPENSSL_SSL_LIBRARY} 
				${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} 
		)
	endif(Boost_FOUND)
endif()
