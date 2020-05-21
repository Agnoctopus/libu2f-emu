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

clean-local:
	$(MAKE) $(AM_MAKEFLAGS) -C examples clean

.PHONY: examples doc