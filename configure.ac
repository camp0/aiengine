AC_INIT([aiengine],[0.1])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

AM_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
m4_include([m4/ax_python_devel.m4])
m4_include([m4/ax_boost_base.m4])
m4_include([m4/ax_boost_python.m4])
m4_include([m4/debug.m4])
m4_include([m4/ac_c++11.m4])

AC_PREREQ(2.59)

AC_PROG_INSTALL

AC_LANG([C++])
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_HEADER_STDC

CXXFLAGS="-O0 -g -std=c++11 -Wno-write-strings"
AC_COMPILE_STDCXX_11

# CXXFLAGS="-std=c++11"
# CXXFLAGS="-std=c++0x"

dnl BOOST
AX_BOOST_BASE([1.49.0])

AX_PYTHON_DEVEL([>= 2.7])
AX_BOOST_PYTHON

# Log4cxx header must exist and library must exist
AC_CHECK_HEADER([log4cxx/logger.h],,
  AC_MSG_ERROR([log4cxx/logger.h not found.  Exiting.]))
AC_CHECK_LIB([log4cxx], [main],,
  AC_MSG_ERROR([log4cxx library not found.  Exiting.]))

AC_CHECK_DEBUG

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
src/signatures/Makefile
src/user/Makefile
src/frequency/Makefile
src/learner/Makefile
src/names/Makefile
])


AC_OUTPUT

echo "
  aiengine 
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
  Boost..........: $boost_lib_version_req
  Python.........: $ax_python_bin
"

