# CMake minimal required version
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

# Project general informations
project(libu2f-emu VERSION 1.0.0 LANGUAGES C
    DESCRIPTION "Universal 2nd Factor (U2F) Emulation C Library")

# Gnu install dirs
include(GNUInstallDirs)

# Add sources subdirectory
add_subdirectory(src)