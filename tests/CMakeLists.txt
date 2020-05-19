# Check if GTest is installed
find_package(GTest)

if(GTest_FOUND)
    set(CMAKE_CXX_STANDARD 17)
    include(GoogleTest)

    add_executable(sanity-check)
    target_sources(sanity-check PRIVATE sanity.cc)
    target_link_libraries(sanity-check PRIVATE gtest gtest_main)
    set_target_properties(sanity-check PROPERTIES FOLDER tests)
    target_compile_options(sanity-check PRIVATE -Wall -Werror -Wextra)
    add_test(sanity-check sanity-check)
endif()
