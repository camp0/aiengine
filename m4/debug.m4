dnl
dnl checking for debug build
dnl
AC_DEFUN([AC_CHECK_DEBUG], [
    AC_ARG_ENABLE([debug], 
                  AC_HELP_STRING([--enable-debug]
                                 [enable debugging]),
                  [enable_debug=yes], [enable_debug=no])

    if test x"$enable_debug" = xyes; then
        AC_DEFINE([DEBUG],,[Define this if you want to build a DEBUG version.])
    fi
])

