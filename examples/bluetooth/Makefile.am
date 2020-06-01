AM_CFLAGS = -Wall -Wextra -Werror -D_GNU_SOURCE
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/examples/bluetooth

noinst_PROGRAMS = u2f-emu-bluetooth

u2f_emu_bluetooth_SOURCES = main.c
u2f_emu_bluetooth_LDADD = $(top_srcdir)/src/libu2f-emu.la

clean-local:
	rm -f *.gcno
	rm -f *.gcda
