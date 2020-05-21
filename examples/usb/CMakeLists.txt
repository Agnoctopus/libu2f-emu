# Sources
set (SRC
    main.c
    uhid-dev.c)

# Add executable
add_executable(u2f-emu-usb EXCLUDE_FROM_ALL)
target_sources(u2f-emu-usb PRIVATE ${SRC})
target_include_directories(u2f-emu PRIVATE .)
target_link_libraries(u2f-emu-usb u2f-emu)
