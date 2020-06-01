AM_CFLAGS = -Wall -Wextra -Werror -D_GNU_SOURCE
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/examples/nfc

noinst_PROGRAMS = u2f-emu-nfc

u2f_emu_nfc_SOURCES = main.c
u2f_emu_nfc_LDADD = $(top_srcdir)/src/libu2f-emu.la

clean-local:
	rm -f *.gcno
	rm -f *.gcda
