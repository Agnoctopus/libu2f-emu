# Versions
set (SO_VERSION ${PROJECT_VERSION})

# Default Release
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

# Sources
set (SRC
    counter.c
    crypto.c
    error.c
    payload.c
    transport.c
    u2f-emu.c
    usb/cmd.c
    usb/message.c
    usb/packet.c
    usb/transaction.c
    usb/usb.c
    raw/authenticate.c
    raw/raw.c
    raw/register.c
    )

# Headers
set (HEADERS
    u2f-emu.h
    u2f-emu-types.h)

# Library U2F-Emu
add_library(u2f-emu SHARED)
target_sources(u2f-emu PRIVATE ${SRC})
target_include_directories(u2f-emu PRIVATE .)
set_target_properties(u2f-emu PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(u2f-emu PROPERTIES SOVERSION ${SO_VERSION})
set_target_properties(u2f-emu PROPERTIES PUBLIC_HEADER "${HEADERS}")
target_compile_options(u2f-emu PRIVATE -Wall -Wextra -Werror -pedantic -std=c99 ${EXTRA_FLAGS})
target_compile_options(u2f-emu PRIVATE -D_GNU_SOURCE)
target_link_libraries(u2f-emu OpenSSL::SSL gcov)
install(TARGETS u2f-emu LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/u2f-emu)

# Pkgconfig
set (version ${SO_VERSION})
set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix \${prefix})
set (libdir \${exec_prefix}/lib)
set (includedir \${prefix}/include)
configure_file(u2f-emu.pc.in u2f-emu.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/src/u2f-emu.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
