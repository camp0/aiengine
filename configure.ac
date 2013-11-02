AC_INIT([aiengine],[0.2],[luis.camp0.2009@gmail.com],[],[https://bitbucket.org/camp0/aiengine])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

AM_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
m4_include([m4/ax_python_devel.m4])
m4_include([m4/ax_boost_base.m4])
m4_include([m4/ax_boost_python.m4])
m4_include([m4/ax_boost_asio.m4])
m4_include([m4/ax_boost_filesystem.m4])
m4_include([m4/ax_boost_regex.m4])
m4_include([m4/ax_boost_system.m4])
m4_include([m4/ax_boost_unit_test_framework.m4])
m4_include([m4/ax_boost_program_options.m4])
m4_include([m4/ac_c++11.m4])

AC_PREREQ(2.59)

AC_PROG_INSTALL

AC_LANG([C++])
AC_PROG_CXX([g++ c++])
AC_PROG_MAKE_SET
AC_HEADER_STDC

AC_COMPILE_STDCXX_11([noext],[mandatory])

if test "$ac_cv_cxx_compile_cxx11_cxx" = no ||
    test "$ac_cv_cxx_compile_cxx11_gxx" = no; then
    AC_MSG_ERROR([C++11 support is an essential dependency for AIEngine, install it.])
else
    AM_CXXFLAGS="$AM_CXXFLAGS -std=c++11"
fi

AM_CXXFLAGS="$AM_CXXFLAGS -Wno-write-strings"
# Dont use it unless you know what you are doing
# CXXFLAGS="-std=c++11"
# CXXFLAGS="-std=c++0x"

##########################################################################
# Pcap support
##########################################################################
#AC_CHECK_HEADER([pcap.h])
#AC_CHECK_LIB(pcap,main,,AC_MSG_ERROR([Pcap support is an essential dependency for AIEngine, install it.]))
AC_CHECK_HEADER(pcap.h,
      AC_CHECK_LIB(pcap, main,
      [have_libpcap=yes LIBS="-lpcap $LIBS"]))

##########################################################################
# Boost support
##########################################################################

AX_BOOST_BASE([1.48.0])
AX_BOOST_ASIO
AX_BOOST_SYSTEM
AX_BOOST_REGEX
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS

AX_PYTHON_DEVEL([>= 2.7])
AX_BOOST_PYTHON

##########################################################################
# Log4cxx support 
##########################################################################
AC_CHECK_HEADER([log4cxx/logger.h])
AC_CHECK_LIB([log4cxx],[main],,have_log4cxx=no)

AM_CONDITIONAL(SUPPORT_LOG4CXX, test "$have_log4cxx" = yes)

##########################################################################
# Debug compilation support
##########################################################################

AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug data generation (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])

if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
    AM_CXXFLAGS="$AM_CXXFLAGS -g -Wall -Werror -Wno-uninitialized -O0"
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    AM_CXXFLAGS="$AM_CXXFLAGS -O0"
fi

CXXFLAGS=$AM_CXXFLAGS

##########################################################################

AC_CONFIG_FILES([
Makefile
test/Makefile
man/Makefile
pcapfiles/Makefile
src/Makefile
src/ethernet/Makefile
src/vlan/Makefile
src/mpls/Makefile
src/ip/Makefile
src/ip6/Makefile
src/gprs/Makefile
src/icmp/Makefile
src/udp/Makefile
src/tcp/Makefile
src/flow/Makefile
src/http/Makefile
src/ssl/Makefile
src/dns/Makefile
src/tcpgeneric/Makefile
src/udpgeneric/Makefile
src/regex/Makefile
src/user/Makefile
src/frequency/Makefile
src/learner/Makefile
src/names/Makefile
])


AC_OUTPUT

echo "
  aiengine 
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Prefix..............: $prefix
  Debug Build.........: $debugit
  C++ Compiler........: $CXX $AM_CXXFLAGS $CPPFLAGS 
  C++11 support.......: $ac_cv_cxx_compile_cxx11_cxx
  Linker..............: $LD $LDFLAGS $LIBS
  Boost include.......: $BOOST_CPPFLAGS/boost
  Boost...............: $boost_lib_version_req
  Python..............: $PYTHON_VERSION $ax_python_bin 
  Python include path.: $python_path
  Log4cxx.............: $ac_cv_lib_log4cxx_main
  Libpcap.............: $ac_cv_lib_pcap_main
"

