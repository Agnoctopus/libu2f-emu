# Sources
set (SRC
    main.c)

# Add executable
add_executable(u2f-emu-nfc EXCLUDE_FROM_ALL)
target_sources(u2f-emu-nfc PRIVATE ${SRC})
target_include_directories(u2f-emu PRIVATE .)
target_link_libraries(u2f-emu-nfc u2f-emu)
