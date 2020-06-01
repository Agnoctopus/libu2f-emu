# Sources
set (SRC
    main.c)

# Add executable
add_executable(u2f-emu-bluetooth EXCLUDE_FROM_ALL)
target_sources(u2f-emu-bluetooth PRIVATE ${SRC})
target_include_directories(u2f-emu-bluetooth PRIVATE .)
target_compile_options(u2f-emu-bluetooth PRIVATE ${EXTRA_FLAGS})
target_link_libraries(u2f-emu-bluetooth PRIVATE u2f-emu ${EXTRA_LIBS})
