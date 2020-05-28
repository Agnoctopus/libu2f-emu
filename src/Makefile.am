MY_WARN_CFLAGS = -fno-strict-aliasing -Wnested-externs -Wmissing-prototypes -Wstrict-prototypes -Wimplicit-function-declaration -Wold-style-definition -Wjump-misses-init -Wall -Wextra -Wundef -Wwrite-strings -Wpointer-arith -Wmissing-declarations -Wredundant-decls -Wno-unused-parameter -Wno-missing-field-initializers -Wformat=2 -Wcast-align -Wformat-nonliteral -Wformat-security -Wsign-compare -Wstrict-aliasing -Wshadow -Winline -Wpacked -Wmissing-format-attribute -Wmissing-noreturn -Winit-self -Wmissing-include-dirs -Wunused-but-set-variable -Warray-bounds -Wreturn-type -Wswitch-enum -Wswitch-default -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wrestrict -Wnull-dereference -Wdouble-promotion -Werror -Wno-suggest-attribute=format -Wno-error=unused-parameter -Wno-error=missing-field-initializers

AM_CFLAGS = $(MY_WARN_CFLAGS) -I${top_srcdir}/src

lib_LTLIBRARIES = libu2f-emu.la
u2f_emu_includedir=$(includedir)/u2f-emu
u2f_emu_include_HEADERS = u2f-emu.h u2f-emu-types.h

# General
libu2f_emu_la_SOURCES = u2f-emu.h u2f-emu-types.h
libu2f_emu_la_SOURCES += raw-message.h
libu2f_emu_la_SOURCES += u2f-emu.c error.c raw-message.c
# USB
libu2f_emu_la_SOURCES += usb/usb.c usb/usb.h
libu2f_emu_la_SOURCES += usb/transaction.c usb/transaction.h
libu2f_emu_la_SOURCES += usb/message.c usb/message.h
libu2f_emu_la_SOURCES += usb/cmd.c usb/cmd.h
libu2f_emu_la_SOURCES += usb/packet.c usb/packet.h
# MISC
libu2f_emu_la_SOURCES += u2f-emu.pc.in

libu2f_emu_la_LDFLAGS = -version-info $(SO_VERSION)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = u2f-emu.pc
