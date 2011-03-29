#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(gridsupervisor-utils, 0.1, TO-TS-PS-STSO-ST1@mail.mm.atosorigin.com)
AC_CONFIG_AUX_DIR(autotools)
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_YACC
AM_PROG_LEX

case "$host_os" in
linux*)
  AC_DEFINE([LINUX], 1, [Define for the Linux operating system.])
  ;;
solaris*)
  AC_DEFINE([SOLARIS], 1, [Define for the Solaris operating system.])
  ;;
*)
  AC_MSG_ERROR([Non supprted operating system: $host_os. exiting.])
  ;;
esac

# Set default lib path to permit use of lib64
case "$build" in
x86_64*)
  LD_LIBDIR=lib64
  #AC_CHECK_LIB([sysmm64], [spoolmess], [LSYSMM=-lsysmm64])
  LSYSMM=-lsysmm64
  ;;
*)
  LD_LIBDIR=lib
  AC_CHECK_LIB([sysmm], [spoolmess], [LSYSMM=-lsysmm])
  LSYSMM=-lsysmm
  ;;
esac

AM_CONDITIONAL([COND_SYSMM], [test -n "$LSYSMM"])
AC_SUBST(LSYSMM)

AC_ARG_WITH([ld-libdir],
  AS_HELP_STRING([--with-ld-libdir=DIR],
    [SSL install directory (default: $LD_LIBDIR)]),
  [LD_LIBDIR=$withval]
)
AC_SUBST(LD_LIBDIR)

# 
AC_ARG_WITH([libevent],
  AS_HELP_STRING([--with-libevent=DIR],
  	[libevent installation directory (default: PREFIX)]),
  [LIBEVENT_DIR=$withval],
  [LIBEVENT_DIR=/usr/local]
)
AC_ARG_WITH([libevent-lib],
  AS_HELP_STRING([--with-libevent-lib=DIR],
  	[libevent library directory (default: PREFIX/lib)]),
  [LIBEVENT_LIBDIR=$withval],
  [LIBEVENT_LIBDIR=/$LIBEVENT_DIR/$LD_LIBDIR]
)
AC_CHECK_FILE([$LIBEVENT_DIR/include/event.h],,[AC_MSG_ERROR([not found])])
AC_SUBST(LIBEVENT_DIR)
AC_SUBST(LIBEVENT_LIBDIR)

LIBEVENT_LIBS=`pkg-config --libs libevent`
AC_SUBST(LIBEVENT_LIBS)
LIBEVENT_CFLAGS=`pkg-config --cflags libevent`
AC_SUBST(LIBEVENT_CFLAGS)

# Check grid metautils
AC_ARG_WITH([metautils],
  AS_HELP_STRING([--with-metautils=DIR],
    [Grid metautils install directory (default: /usr/local)]),
  [METAUTILS_DIR=$withval],
  [METAUTILS_DIR=/usr/local]
)
AC_SUBST(METAUTILS_DIR)

# Toggle specific modules
AC_ARG_ENABLE([spoolmess],
  AS_HELP_STRING([--enable-spoolmess=DIR],
    [Builds the alert_module based on spoolmess]),
  [
	SYSMM_DEFINE=[-DSPOOLMESS=1]
	AC_SUBST(SYSMM_DEFINE)

	AC_DEFINE([HAVE_SYSMM], 1, [NetApp support has been trigerred])
	AC_SUBST(SYSMM_DEFINE)

	SYSMM_LIBS="$LSYSMM"
	AC_SUBST(SYSMM_LIBS)

	sysmm_enabled=true

	AC_CHECK_FILE([$METAUTILS_DIR/include/metautils.h],, [AC_MSG_ERROR([not found])])
	AC_CHECK_FILE([$METAUTILS_DIR/include/metacomm.h],, [AC_MSG_ERROR([not found])])
	AC_CHECK_FILE([$METAUTILS_DIR/include/metatypes.h],, [AC_MSG_ERROR([not found])])
  ]
)
AM_CONDITIONAL([SYSMM_ENABLED], [test x$sysmm_enabled = xtrue])

# Checks for libraries.
AM_PATH_LOG4C
AM_PATH_GLIB_2_0(2.18.0,,AC_MSG_ERROR(glib version >= 2.18 required),[gmodule gthread])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stddef.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_REPLACE_FNMATCH
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([memset mkdir regcomp strchr strdup strerror])

AC_CONFIG_FILES([Makefile
		 lib/Makefile
		 alert_spoolmess/Makefile
		 main/Makefile])
AC_OUTPUT


