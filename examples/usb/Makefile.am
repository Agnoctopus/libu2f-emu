AM_CFLAGS = -Wall -Wextra -Werror -D_GNU_SOURCE
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/examples/usb

noinst_PROGRAMS = u2f-emu-usb

u2f_emu_usb_SOURCES = main.c uhid-dev.c u2f-dev.c
u2f_emu_usb_LDADD = $(top_srcdir)/src/libu2f-emu.la