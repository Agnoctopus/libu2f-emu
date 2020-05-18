AM_CFLAGS = $(WARN_CFLAGS) -I${top_srcdir}/src

lib_LTLIBRARIES = libu2f-emu.la
u2f_emu_includedir=$(includedir)/u2f-emu
u2f_emu_include_HEADERS = u2f-emu.h u2f-emu-types.h

libu2f_emu_la_SOURCES = u2f-emu.h u2f-emu-types.h
libu2f_emu_la_SOURCES += raw-message.h
libu2f_emu_la_SOURCES += u2f-emu.c error.c raw-message.c
libu2f_emu_la_SOURCES += u2f-emu.pc.in

libu2f_emu_la_LDFLAGS = -version-info $(SO_VERSION)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = u2f-emu.pc