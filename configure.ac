AC_PREREQ([2.69])
AC_INIT([libu2f-emu],
        [1.0.0],
        [cesar.belley@lse.epita.fr],
        [libu2f-emu],
        [https://github.com/MattGorko/libu2f-emu])

# Config
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

# Subst
AC_SUBST([SO_VERSION], [1:0:0])
AC_SUBST([version], [1.0.0])

# Automake
AM_INIT_AUTOMAKE([
        -Wall -Werror
        foreign
        subdir-objects
        silent-rules
])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
AM_PROG_AR
AC_PROG_INSTALL

# Doxygen
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN"; then
        AC_MSG_WARN([Doxygen not found: continuing without Doxygen support])
fi

# Dot
AC_CHECK_PROGS([DOT], [dot])
if test -z "$DOT"; then
        AC_MSG_WARN([Dot not found: for pretty documentation])
fi

# Compiler flags
AX_COMPILER_FLAGS
AX_CHECK_COMPILE_FLAG([-std=c99],
                      [CFLAGS+=" -std=c99"])
AX_CHECK_COMPILE_FLAG([-pedantic],
                      [CFLAGS+=" -pedantic"])

# Libtool configs
LT_PREREQ([2.4.6])
LT_INIT([
        shared
        disable-static
        pic-only
])

# Checks for libraries.
ACX_PTHREAD([HAVE_PTHREAD=1], [HAVE_PTHREAD=0])
AM_CONDITIONAL([HAVE_PTHREAD], [test -n "$HAVE_PTHREAD"])

PKG_CHECK_MODULES([OPENSSL], [libssl, libcrypto], [HAVE_SSL=1], [HAVE_SSL=0])
AM_CONDITIONAL([HAVE_SSL], [test -n "$HAVE_SSL"])
AM_COND_IF([HAVE_SSL],
        AC_SUBST([OPENSSL_LIBS])
)

PKG_CHECK_MODULES([GTEST], [gtest, gtest_main], [HAVE_GTEST=1], [HAVE_GTEST=0])
AM_CONDITIONAL([HAVE_GTEST], [test -n "$HAVE_GTEST"])
AM_COND_IF([HAVE_GTEST],
        AC_SUBST([GTEST_CFLAGS])
        AC_SUBST([GTEST_LIBS])
        AC_SUBST([GTEST_CPPFLAGS])
)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stddef.h stdint.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

# Docs
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AM_CONDITIONAL([HAVE_DOT], [test -n "$DOT"])
AM_COND_IF([HAVE_DOT],
        AC_SUBST([HAVE_DOT], [YES]),
        AC_SUBST([HAVE_DOT], [NO]))
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([Doxyfile])])

# Configs
AC_CONFIG_FILES([
        Makefile
        src/Makefile
        src/u2f-emu.pc
        tests/Makefile
        examples/Makefile
        examples/usb/Makefile
        examples/nfc/Makefile
        examples/bluetooth/Makefile
])

# Output
AC_OUTPUT