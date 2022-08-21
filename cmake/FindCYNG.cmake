# FindCYNG.cmake
#
# Finds the CYNG library
#
# This will define the following variables
#
#   CYNG_FOUND          - system has cyng
#   CYNG_INCLUDE_DIRS	- the cyng include directories
#   CYNG_LIBRARIES      - cyng libraries directories
#	<NAME>_LIBRARY			- individual variable for each library found
#
# and the following imported targets
#
#     CYNG::CYNG
#

# clear the variables, in case they were set somewhere elese
if(CYNG_LIBRARIES)
	unset(CYNG_LIBRARIES)
	unset(CYNG_LIBRARIES CACHE)
	unset(CYNG_LIBRARIES PARENT_SCOPE)
endif()

if(CYNG_INCLUDE_DIRS)
	unset(CYNG_INCLUDE_DIRS)
	unset(CYNG_INCLUDE_DIRS CACHE)
	unset(CYNG_INCLUDE_DIRS PARENT_SCOPE)
endif()

#
#	try PkgConfig
#
find_package(PkgConfig)
pkg_check_modules(PC_CYNG QUIET CYNG)

if(PC_CYNG_FOUND)
    set(CYNG_VERSION ${PC_CYNG_VERSION})
    set(CYNG_INCLUDE_DIRS ${PC_CYNG_INCLUDE_DIRS})
    set(CYNG_LIBRARIES ${PC_CYNG_LIBRARIES})

	if(NOT PC_CYNGQUIETLY)
		message(STATUS "** PC_CYNG_FOUND: BEGIN")
		message(STATUS "** CYNG_VERSION: ${CYNG_VERSION}")
		message(STATUS "** CYNG_INCLUDE_DIRS: ${CYNG_INCLUDE_DIRS}")
		message(STATUS "** CYNG_LIBRARIES: ${CYNG_LIBRARIES}")
		message(STATUS "** PC_CYNG_FOUND: END")
	endif(NOT PC_CYNG_QUIETLY)

else(PC_CYNG_FOUND)

	#
	#	cyng header files
	#
	file(GLOB CYNG_SEARCH_PATH 
		"${CMAKE_PREFIX_PATH}/cyng*" 
		"${PROJECT_SOURCE_DIR}/../cyng*" 
		"${PROJECT_SOURCE_DIR}/../../sysroot-target" 
        "${PROJECT_SOURCE_DIR}/../../packages/cyng*"
		"${PROJECT_SOURCE_DIR}/../../root")

	#
	#	cyng header files, which are included in the form cyng/xx.h
	#
    find_path(CYNG_INCLUDE_DIR_SRC
        NAMES 
			cyng/meta.hpp 
            cyng/obj/object.h
		PATH_SUFFIXES
			include
        PATHS
			${CYNG_SEARCH_PATH}
        DOC 
            "CYNG headers"
		NO_CMAKE_FIND_ROOT_PATH
    )

	#
	#	cyng generated header files
	#
    find_path(CYNG_INCLUDE_DIR_BUILD
        NAMES 
            cyng.h
        PATH_SUFFIXES
			"include"
			"${SMFSEC_BUILD_TREE_STEM}/include"
			"build/include"
        PATHS
			${CYNG_SEARCH_PATH}
        DOC 
            "CYNG headers"
		NO_CMAKE_FIND_ROOT_PATH
    )	


    list(APPEND CYNG_INCLUDE_DIRS ${CYNG_INCLUDE_DIR_SRC})
    list(APPEND CYNG_INCLUDE_DIRS ${CYNG_INCLUDE_DIR_BUILD})

    #
	#	search cyng libraries on linux
	#
	set(FIND_LIBS "cyng_db;cyng_io;cyng_log;cyng_obj;cyng_parse;cyng_rnd;cyng_sql;cyng_store;cyng_sys;cyng_task;cyng_vm;cyng_net;cyng_sqlite3")

	if(WIN32)
        list(APPEND FIND_LIBS "cyng_scm")
    endif(WIN32)

	foreach(__LIB ${FIND_LIBS})
		find_library("${__LIB}" ${__LIB}
			PATHS
				${CYNG_SEARCH_PATH}
			PATH_SUFFIXES
				usr/lib
				lib
				build
				"${SMFSEC_BUILD_TREE_STEM}"
				"${SMFSEC_BUILD_TREE_STEM}/src/${__LIB}"
                "${SMFSEC_BUILD_TREE_STEM}/src/${__LIB}/Debug"
                "${SMFSEC_BUILD_TREE_STEM}/src/${__LIB}/Release"
				"${SMFSEC_BUILD_TREE_STEM}/Debug"
				"${SMFSEC_BUILD_TREE_STEM}/Release"
				"build/Debug"
				"build/Release"
			DOC 
				"CYNG libraries"
            NO_CMAKE_FIND_ROOT_PATH
		)
		
		# append the found library to the list of all libraries
		list(APPEND CYNG_LIBRARIES ${${__LIB}})

		# this creates a variable with the name of the searched library, so that it can be included more easily
		unset(__LIB_UPPERCASE_NAME)
		string(TOUPPER ${__LIB} __LIB_UPPERCASE_NAME)
		set(${__LIB_UPPERCASE_NAME}_LIBRARY ${${__LIB}})
	endforeach()

endif(PC_CYNG_FOUND)

# check if both the header and the libraries have been found
if (CYNG_INCLUDE_DIRS AND CYNG_LIBRARIES)
	set(CYNG_FOUND ON)
	unset(CYNG_INCLUDE_DIR_SRC CACHE)
	unset(CYNG_INCLUDE_DIR_BUILD CACHE)
	if(NOT CYNG_FIND_QUIETLY)
		message(STATUS "** CYNG_LIBRARIES    : ${CYNG_LIBRARIES}")
		message(STATUS "** CYNG_INCLUDE_DIRS : ${CYNG_INCLUDE_DIRS}")
	endif(NOT CYNG_FIND_QUIETLY)
endif(CYNG_INCLUDE_DIRS AND CYNG_LIBRARIES)

mark_as_advanced(CYNG_FOUND CYNG_INCLUDE_DIRS CYNG_LIBRARIES)

if(UNIX)
	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(CYNG
		REQUIRED_VARS 
			CYNG_INCLUDE_DIRS
			CYNG_LIBRARIES
		VERSION_VAR 
			CYNG_VERSION
		FAIL_MESSAGE
			"Cannot provide CYNG library"
	)
endif(UNIX)

if(CYNG_FOUND AND NOT TARGET CYNG::CYNG)

    add_library(CYNG::CYNG INTERFACE IMPORTED)

#	define a target
   	set_target_properties(CYNG::CYNG 
		PROPERTIES
			INTERFACE_INCLUDE_DIRECTORIES 
				"${CYNG_INCLUDE_DIRS}"
			INTERFACE_LINK_LIBRARIES 
				"${CYNG_LIBRARIES}"
    )

endif()

