# Subdirs
SUBDIRS = src tests

# Flags
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

# Extra dist
EXTRA_DIST = autogen.sh

# Docs
if HAVE_DOXYGEN
doc:
	$(DOXYGEN) Doxyfile

endif

examples: all
	$(MAKE) $(AM_MAKEFLAGS) -C examples

coverage: check
	mkdir -p ${top_srcdir}/coverage
	gcovr -r ${top_srcdir}/src --html --html-details --html-title 'Libu2f-emu coverage' -o ${top_srcdir}/coverage/index.html -j2

clean-local:
	$(MAKE) $(AM_MAKEFLAGS) -C examples clean
	rm -rf ${top_srcdir}/doc
	rm -rf ${top_srcdir}/coverage

.PHONY: examples doc