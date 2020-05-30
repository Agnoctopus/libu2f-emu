# CMake minimal required version
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

# Project general informations
project(libu2f-emu VERSION 1.0.0 LANGUAGES C CXX
    DESCRIPTION "Universal 2nd Factor (U2F) Emulation C Library")

# Gnu install dirs
include(GNUInstallDirs)

# Openssl
find_package(OpenSSL REQUIRED)

# Doxygen
find_package(Doxygen)

# Dot
find_program(DOT dot)
if(DOT)
    set (HAVE_DOT YES)
else()
    set (HAVE_DOT NO)
    message("Dot not found: for pretty documentation")
endif()

# Doc
if(DOXYGEN_FOUND)
    set (VERSION ${PROJECT_VERSION})
    set (top_srcdir ${CMAKE_SOURCE_DIR})

    configure_file(
        ${CMAKE_SOURCE_DIR}/Doxyfile.in
        ${CMAKE_SOURCE_DIR}/Doxyfile)

    add_custom_target(doc
        COMMAND doxygen
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
else()
    message("Doxygen not found: continuing without Doxygen support")
endif()

# Add sources subdirectory
add_subdirectory(src)

# Add examples subdirectory
add_subdirectory(examples)

# Tests
enable_testing()
add_subdirectory(tests)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)
