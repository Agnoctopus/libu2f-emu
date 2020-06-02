# Check if GTest is installed
find_package(GTest)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)

if(GTest_FOUND)
    set(CMAKE_CXX_STANDARD 17)
    include(GoogleTest)

    add_executable(sanity-check EXCLUDE_FROM_ALL)
    target_sources(sanity-check PRIVATE sanity.cc)
    target_include_directories(sanity-check PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(sanity-check PRIVATE gtest gtest_main ${EXTRA_LIBS})
    set_target_properties(sanity-check PROPERTIES FOLDER tests)
    target_compile_options(sanity-check PRIVATE -Wall -Werror -Wextra -pedantic ${EXTRA_FLAGS})
    add_test(sanity-check sanity-check)

    add_executable(basic EXCLUDE_FROM_ALL)
    target_sources(basic PRIVATE basic.cc)
    target_include_directories(basic PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(basic PRIVATE gtest gtest_main u2f-emu ${EXTRA_LIBS})
    target_compile_options(basic PRIVATE -Wall -Werror -Wextra -pedantic ${EXTRA_FLAGS})
    set_target_properties(basic PROPERTIES FOLDER tests)
    add_test(basic basic)

    add_executable(payload EXCLUDE_FROM_ALL)
    target_sources(payload PRIVATE payload.cc)
    target_include_directories(payload PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(payload PRIVATE gtest gtest_main u2f-emu ${EXTRA_LIBS})
    target_compile_options(payload PRIVATE -Wall -Werror -Wextra -pedantic ${EXTRA_FLAGS})
    set_target_properties(payload PROPERTIES FOLDER tests)
    add_test(payload payload)

    add_custom_command(OUTPUT SETUP_DIR
        COMMAND rm -rf .u2f.tmp
        COMMAND ${CMAKE_SOURCE_DIR}/setup.sh .u2f.tmp)
    add_custom_target(setup_dir DEPENDS SETUP_DIR)

    add_dependencies(check setup_dir sanity-check basic payload)

    add_subdirectory(usb)
endif()
