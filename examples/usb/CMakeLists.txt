# Sources
set (SRC
    main.c
    uhid-dev.c
    u2f-dev.c)

# Add executable
add_executable(u2f-emu-usb EXCLUDE_FROM_ALL)
target_sources(u2f-emu-usb PRIVATE ${SRC})
target_include_directories(u2f-emu-usb PRIVATE .)
target_include_directories(u2f-emu-usb PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_options(u2f-emu-usb PRIVATE -Wall -Werror -Wextra -std=c99 -pedantic ${EXTRA_FLAGS})
target_compile_options(u2f-emu-usb PRIVATE -D_GNU_SOURCE)
target_link_libraries(u2f-emu-usb PRIVATE u2f-emu ${EXTRA_LIBS})
