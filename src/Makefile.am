AM_CFLAGS = $(WARN_CFLAGS) -I${top_srcdir}/src

lib_LTLIBRARIES = libu2f-emu.la
u2f_emu_includedir=$(includedir)/u2f-emu
u2f_emu_include_HEADERS = hello.h

libu2f_emu_la_SOURCES = hello.h
libu2f_emu_la_SOURCES += hello.c
libu2f_emu_la_SOURCES += u2f-emu.pc.in

libu2f_emu_la_LDFLAGS = -version-info $(SO_VERSION)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = u2f-emu.pc