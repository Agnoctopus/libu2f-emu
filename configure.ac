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
AM_PROG_AR
AC_PROG_INSTALL

# Compiler flags
AX_CHECK_COMPILE_FLAG([-pedantic],
                      [AM_CFLAGS="$AM_CFLAGS -pedantic"])
AX_COMPILER_FLAGS

# Libtool configs
LT_PREREQ([2.4.6])
LT_INIT([
        shared
        disable-static
        pic-only
])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC

# Configs
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/u2f-emu.pc
])

# Output
AC_OUTPUT