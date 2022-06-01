cmake_minimum_required (VERSION 3.10)
cmake_policy(SET CMP0074 NEW)


#
# set project name/properties
#
project(crypt
	VERSION 0.0.2
	LANGUAGES CXX C
	DESCRIPTION "C++ wrapper for OpenSLL - companion of CYNG library")


#                                                                                            
#        *******         *****   **    **        ***** **                                    
#      *       ***    ******  ***** *****     ******  **** *                                 
#     *         **   **   *  *  ***** *****  **   *  *  ***                                  
#     **        *   *    *  *   * **  * **  *    *  *    *                                   
#      ***              *  *    *     *         *  *            ****                         
#     ** ***           ** **    *     *        ** **           * **** *    ***       ****    
#      *** ***         ** **    *     *        ** **          **  ****    * ***     * ***  * 
#        *** ***       ** **    *     *        ** ******     ****        *   ***   *   ****  
#          *** ***     ** **    *     *        ** *****        ***      **    *** **         
#            ** ***    ** **    *     **       ** **             ***    ********  **         
#             ** **    *  **    *     **       *  **               ***  *******   **         
#              * *        *     *      **         *           ****  **  **        **         
#    ***        *     ****      *      **     *****          * **** *   ****    * ***     *  
#   *  *********     *  *****           **   *  *****           ****     *******   *******   
#  *     *****      *     **                *    ***                      *****     *****    
#  *                *                       *                                                
#   **               **                      **                                              
#                                                                                            
#                                                                                            
#                                                                                            
																					  

message(STATUS "**  ")                                                                                          
message(STATUS "**        *******         *****   **    **        ***** **                                    ")
message(STATUS "**      *       ***    ******  ***** *****     ******  **** *                                 ")
message(STATUS "**     *         **   **   *  *  ***** *****  **   *  *  ***                                  ")
message(STATUS "**     **        *   *    *  *   * **  * **  *    *  *    *                                   ")
message(STATUS "**      ***              *  *    *     *         *  *            ****                         ")
message(STATUS "**     ** ***           ** **    *     *        ** **           * **** *    ***       ****    ")
message(STATUS "**      *** ***         ** **    *     *        ** **          **  ****    * ***     * ***  * ")
message(STATUS "**        *** ***       ** **    *     *        ** ******     ****        *   ***   *   ****  ")
message(STATUS "**          *** ***     ** **    *     *        ** *****        ***      **    *** **         ")
message(STATUS "**            ** ***    ** **    *     **       ** **             ***    ********  **         ")
message(STATUS "**             ** **    *  **    *     **       *  **               ***  *******   **         ")
message(STATUS "**              * *        *     *      **         *           ****  **  **        **         ")
message(STATUS "**    ***        *     ****      *      **     *****          * **** *   ****    * ***     *  ")
message(STATUS "**   *  *********     *  *****           **   *  *****           ****     *******   *******   ")
message(STATUS "**  *     *****      *     **                *    ***                      *****     *****    ")
message(STATUS "**  *                *                       *                                                ")
message(STATUS "**   **               **                      **                                              ")
message(STATUS "**                                                                                            ")
#                                                                                            
#                                                                                            

# Only do these if this is the main project, and not if it is included through add_subdirectory
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)

	#
	# guard against in-source builds and bad build-type strings
	#
	include(cmake/safeguards.cmake)

    message(STATUS "** CMake              : ${CMAKE_VERSION}")
	message(STATUS "** Compiler           : ${CMAKE_CXX_COMPILER_ID} v${CMAKE_CXX_COMPILER_VERSION}")

    if (NOT WIN32) 
        # Alpine Linux v3.16/alpine
        cmake_host_system_information(RESULT CRYPTO_HOST_PRETTY_NAME QUERY DISTRIB_PRETTY_NAME)
        cmake_host_system_information(RESULT CRYPTO_HOST_ID_NAME QUERY DISTRIB_ID)
        message(STATUS "** Host System        : ${CRYPTO_HOST_PRETTY_NAME}/${CRYPTO_HOST_ID_NAME} - (${CMAKE_SYSTEM_NAME})")
    else()
        message(STATUS "** Host System        : ${CMAKE_SYSTEM_NAME}")
    endif()

    # Let's ensure -std=c++xx instead of -std=g++xx
    set(CMAKE_CXX_EXTENSIONS OFF)

	if (CMAKE_COMPILER_IS_GNUCXX)
		set(GLOBAL_LIBRARY_TYPE SHARED)
	elseif(MSVC)
		set(GLOBAL_LIBRARY_TYPE STATIC)
	    add_compile_definitions(_WIN32_WINNT=0x0A00 _SCL_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
        add_compile_options(/bigobj)
        add_compile_options(/MP)
	endif(CMAKE_COMPILER_IS_GNUCXX)

endif()

#
# place binaries and libraries according to GNU standards
#
include(GNUInstallDirs)

#
#	OpenSSL
#
find_package(OpenSSL 1.1.1 REQUIRED)
if(OPENSSL_FOUND)
	message(STATUS "** openSSL Include       : ${OPENSSL_INCLUDE_DIR}")
	message(STATUS "** openSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")
	message(STATUS "** openSSL SSL library   : ${OPENSSL_SSL_LIBRARY}")
	message(STATUS "** openSSL Libraries     : ${OPENSSL_LIBRARIES}")

#    include_directories(${OPENSSL_INCLUDE_DIR})
#    link_directories(${OPENSSL_LIBRARIES})

endif(OPENSSL_FOUND)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

#
# find cyng library
# CYNG_INCLUDE_DIRS CYNG_LIBRARIES
#
find_package(CYNG REQUIRED)
if (CYNG_FOUND)
    message(STATUS "** CYNG_INCLUDE_DIRS        : ${CYNG_INCLUDE_DIRS}")
    message(STATUS "** CYNG_LIBRARIES           : ${CYNG_LIBRARIES}")
    message(STATUS "** cyng_db                  : ${cyng_db}")
    message(STATUS "** cyng_io                  : ${cyng_io}")
    message(STATUS "** cyng_log                 : ${cyng_log}")
    message(STATUS "** cyng_obj                 : ${cyng_obj}")
    message(STATUS "** cyng_parse               : ${cyng_parse}")
    message(STATUS "** cyng_rnd                 : ${cyng_rnd}")
    message(STATUS "** cyng_sql                 : ${cyng_sql}")
    message(STATUS "** cyng_store               : ${cyng_store}")
    message(STATUS "** cyng_sys                 : ${cyng_sys}")
    message(STATUS "** cyng_task                : ${cyng_task}")
    message(STATUS "** cyng_vm                  : ${cyng_vm}")
else()
    message(FATAL_ERROR "** cyng library not found")
	set(CYNG_INCLUDE_DIR_SRC "not-found" CACHE PATH "specify path to CYNG include directory")
	set(CYNG_INCLUDE_DIR_BUILD "not-found" CACHE PATH "specify path to CYNG build directory")
endif()

#add_library(cyng_core SHARED IMPORTED)
#set_property(TARGET cyng_core 
#	PROPERTY 
#		IMPORTED_LOCATION ${CYNG_LIBRARY}/cyng_core
#		PUBLIC_HEADER ${CYNG_INCLUDE})


set (smfsec_hash
	src/hash/base64.cpp
	src/hash/md5.cpp
	src/hash/sha1.cpp
	src/hash/sha256.cpp
	src/hash/sha512.cpp
	include/smfsec/hash/base64.h
	include/smfsec/hash/md5.h
	include/smfsec/hash/sha1.h
	include/smfsec/hash/sha256.h
	include/smfsec/hash/sha512.h
)

set (smfsec_algorithm
	src/algorithm/none.cpp
	src/algorithm/hmacsha.cpp
	src/algorithm/rsa.cpp
	src/algorithm/ecdsa.cpp
	src/algorithm/pss.cpp
	include/smfsec/algorithm/none.h
	include/smfsec/algorithm/hmacsha.h
	include/smfsec/algorithm/rsa.h
	include/smfsec/algorithm/ecdsa.h
	include/smfsec/algorithm/pss.h
)

source_group("hash" FILES ${smfsec_hash})
source_group("algorithm" FILES ${smfsec_algorithm})


#
#	define the crypto library
#

add_library(smfsec ${GLOBAL_LIBRARY_TYPE} 
	include/smfsec/crypto.h
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
	${smfsec_hash}
	${smfsec_algorithm})
target_compile_features(smfsec PRIVATE cxx_std_11)

target_include_directories(smfsec
    PUBLIC 
        $<INSTALL_INTERFACE:include>    
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include;${OPENSSL_INCLUDE_DIR}>"
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
		${CYNG_INCLUDE_DIRS}
)

target_link_libraries(smfsec
    PUBLIC
        ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} 
    PRIVATE
        ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY}
)

set_target_properties(smfsec 
	PROPERTIES PUBLIC_HEADER 
		"${crypto_headers};${crypto_headers_algo};${crypto_headers_hash}")

include(GNUInstallDirs)
install(TARGETS smfsec
	LIBRARY DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	INCLUDES DESTINATION 
        ${CMAKE_INSTALL_INCLUDEDIR}/smfsec
	PUBLIC_HEADER DESTINATION 
		${CMAKE_INSTALL_INCLUDEDIR}/smfsec)
#	PUBLIC_HEADER_ALGO DESTINATION
#	${CMAKE_INSTALL_INCLUDEDIR}/crypto/algorithm)

#	- include files

install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/smfsec" # source directory
        DESTINATION "include" # target directory
        FILES_MATCHING # install only matched files
        PATTERN "*.h" # select header files
)

#
#	FixMe: INSTALL TARGETS - target crypto has PUBLIC_HEADER files but no PUBLIC_HEADER DESTINATION
#
include(GNUInstallDirs)
install(TARGETS smfsec
	LIBRARY DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION 
        ${CMAKE_INSTALL_LIBDIR}
	INCLUDES DESTINATION 
        ${CMAKE_INSTALL_INCLUDEDIR}/smfsec
	PUBLIC_HEADER DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}/smfsec
)


#
# call CMake with -DCRYPT_UNIT_TEST:BOOL=TRUE to generate unit tests 
# default is OFF
#
if(NOT DEFINED ${PROJECT_NAME}_UNIT_TEST)
	set(${PROJECT_NAME}_UNIT_TEST OFF CACHE BOOL "build unit test")
endif()

#
#	Boost is only required to build the unit test
#
if(${PROJECT_NAME}_UNIT_TEST)

	find_package(Boost 1.75 REQUIRED COMPONENTS unit_test_framework)
	if(Boost_FOUND)
		include (test/unit-test.cmake)
		add_executable(unit_test ${unit_test})

		set_property(
			TARGET unit_test
			PROPERTY COMPILE_DEFINITIONS BOOST_TEST_DYN_LINK)

		target_include_directories(unit_test
			PRIVATE
				$<INSTALL_INTERFACE:include>    
				${CYNG_INCLUDE_DIRS}
				"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include;${Boost_INCLUDE_DIRS};${OPENSSL_INCLUDE_DIR}>"
				${CMAKE_CURRENT_SOURCE_DIR}/src
		)

		target_link_libraries(unit_test
			PRIVATE
				smfsec 
				${cyng_obj}
#				"$<$<PLATFORM_ID:Linux>:${CYNG_LIBRARY}/cyng_core.so>"
#				"$<$<PLATFORM_ID:Windows>:${CYNG_LIBRARY}/Debug/cyng_core.lib>"
				${OPENSSL_CRYPTO_LIBRARY} 
				${OPENSSL_SSL_LIBRARY} 
				${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} 
		)
	endif(Boost_FOUND)
endif()

#
# CPack configuration
#

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_RELEASE "Nuakschott")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_NAME} - crypto support for SMF")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_VERSION_TWEAK ${PROJECT_VERSION_TWEAK})
set(CPACK_PACKAGE_CONTACT "info@solostec.ch")
set(CPACK_PACKAGE_VENDOR "solosTec")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PROJECT_NAME}-${CPACK_PROJECT_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RPM_PACKAGE_DESCRIPTION "SMFSec library")
set(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)

if(WIN32)

	set(CPACK_GENERATOR "NSIS64")
	set(CPACK_NSIS_MUI_ICON ${PROJECT_SOURCE_DIR}/src/assets/logo.ico)
	set(CPACK_NSIS_MUI_UNIICON ${PROJECT_SOURCE_DIR}/src/assets/logo.ico)
	#set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait '\\\"$INSTDIR\\\\vcredist_x86.exe\\\" /q:a'")
	set(CPACK_NSIS_MODIFY_PATH ON)
	set(CPACK_NSIS_URL_INFO_ABOUT "http:\\\\\\\\www.solostec.com")

else()

    set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

    if (${CRYPTO_HOST_ID_NAME} STREQUAL "openSUSE")
        set(CPACK_GENERATOR "RPM")
    else()    

        #   architecture: amd64
        message(STATUS "** architecture                 : ${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")  
        set(CPACK_DEBIAN_PACKAGE_SECTION "devel")
	    set(CPACK_GENERATOR "DEB")
    endif()
endif()

include(CPack)
