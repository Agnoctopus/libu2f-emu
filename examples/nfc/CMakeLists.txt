# Sources
set (SRC
    main.c)

# Add executable
add_executable(u2f-emu-nfc EXCLUDE_FROM_ALL)
target_sources(u2f-emu-nfc PRIVATE ${SRC})
target_include_directories(u2f-emu-nfc PRIVATE .)
target_compile_options(u2f-emu-nfc PRIVATE -Wall -Werror -Wextra -std=c99 -pedantic ${EXTRA_FLAGS})
target_link_libraries(u2f-emu-nfc PRIVATE u2f-emu ${EXTRA_LBIS})
