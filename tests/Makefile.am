if HAVE_PTHREAD
    GTEST_CPPFLAGS += -DGTEST_HAS_PTHREAD=1
    GTEST_CFLAGS += $(PTHREAD_CFLAGS)
    GTEST_LIBS += $(PTHREAD_LIBS)
else
    GTEST_CPPFLAGS += "-DGTEST_HAS_PTHREAD=0"
endif

AM_CXXFLAGS = $(WARN_CXXFLAGS) -I${top_srcdir}/src  $(GTEST_CFLAGS)
AM_CPPFLAGS = $(WARN_CXXFLAGS) -I${top_srcdir}/src $(GTEST_CPPFLAGS)
AM_LDFLAGS = $(GTEST_LDFLAGS) $(GTEST_LIBS)

clean-local:
	rm -f *.gcno
	rm -f *.gcda

pre-check:
	make post-check
	${top_srcdir}/setup.sh ${top_srcdir}/tests/.u2f.tmp

post-check:
	rm -rf ${top_srcdir}/tests/.u2f.tmp

check: pre-check
	make post-check

# TESTS -- Programs run automatically by "make check"
# check_PROGRAMS -- Programs built by "make check" but not necessarily run
TESTS = sanity-check basic
check_PROGRAMS = $(TESTS)

sanity_check_SOURCES = sanity.cc

basic_SOURCES = basic.cc
basic_LDADD = $(top_srcdir)/src/libu2f-emu.la
