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

clean-local:
	rm -rf $(top_srcdir)/doc

.PHONY: doc
endif
