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


find_package(OpenSSL 1.0.2 REQUIRED)
if(OPENSSL_FOUND)
	message(STATUS "** openSSL Include       : ${OPENSSL_INCLUDE_DIR}")
	message(STATUS "** openSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")
	message(STATUS "** openSSL SSL library   : ${OPENSSL_SSL_LIBRARY}")
	message(STATUS "** openSSL Libraries     : ${OPENSSL_LIBRARIES}")

#    include_directories(${OPENSSL_INCLUDE_DIR})
#    link_directories(${OPENSSL_LIBRARIES})

endif(OPENSSL_FOUND)

#
#	define the crypto library
#
add_library(crypto src/bio.cpp src/factory.cpp src/init.cpp src/print.cpp src/read.cpp src/write.cpp src/generate.cpp)
target_compile_features(crypto PRIVATE cxx_std_11)

target_include_directories(crypto
    PUBLIC 
        $<INSTALL_INTERFACE:include>    
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include;${OPENSSL_INCLUDE_DIR}>"
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(crypto
    PUBLIC
        ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} 
#cyng::bio
    PRIVATE
        ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY}
)

include(GNUInstallDirs)
install(TARGETS crypto
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cyng)