AC_INIT([aiengine],[1.0],[luis.camp0.2009@gmail.com],[],[https://bitbucket.org/camp0/aiengine])
AM_INIT_AUTOMAKE([subdir-objects])
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

AC_CANONICAL_HOST
AM_CONDITIONAL([__OPENBSD__],false)
AM_CONDITIONAL([__FREEBSD__],false)
AM_CONDITIONAL([__LINUX__],false)
case $host in
    *free*)    
    	AC_DEFINE([__FREEBSD__],[1],[FreeBSD Host])
    	AM_CONDITIONAL([__FREEBSD__],true)
# The macro ax_boost_python is not working properly on freebsd
# in order to fix the problem I just updated the BOOST_PYTHON_LIB
# and if something is wrong will explode later :D
	BOOST_PYTHON_LIB="boost_python"
    ;;
    *openbsd*)    
    	AC_DEFINE([__OPENBSD__],[1],[OpenBSD Host])
    	AM_CONDITIONAL([__OPENBSD__],true)
    ;;
    *linux*)
	AC_DEFINE([__LINUX__],[1],[Linux Host])
    	AM_CONDITIONAL([__LINUX__],true)
    ;;
esac

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

AC_SUBST([cxx_version],[$( $CXX --version|head -n 1 )])

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

AX_BOOST_BASE([1.49.0])
AX_BOOST_ASIO
AX_BOOST_SYSTEM
AX_BOOST_REGEX
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS

AC_MSG_CHECKING([whether to build with unit tests.])
AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--enable-tests],
        [enable tests generation (def=no)])],
    [unittestsit="$enableval"],
    [unittestsit=no])

if test x"$unittestsit" = x"yes"; then
    AX_BOOST_UNIT_TEST_FRAMEWORK
fi

AM_PATH_PYTHON

# If want a specific python version change the value
# but allways with the commas!!!
AX_PYTHON_DEVEL([>= '2.7'])
AX_BOOST_PYTHON

##########################################################################
# Log4cxx support 
##########################################################################
AC_CHECK_HEADER([log4cxx/logger.h])
AC_CHECK_LIB([log4cxx],[main],have_log4cxx=yes,have_log4cxx=no)

AM_CONDITIONAL(SUPPORT_LOG4CXX, [test "$have_log4cxx" = yes])

##########################################################################
# Pcre++ support 
##########################################################################

AC_MSG_CHECKING(for perl regular expressions support)
AC_ARG_WITH(pcre, AC_HELP_STRING([--with-pcre],[Enable pcre support (default yes)]),
    [WITH_PCRE=$withval],[WITH_PCRE=yes])
AC_MSG_RESULT([$WITH_PCRE])

if test "$WITH_PCRE" != "no"; then
  AC_PATH_PROG(PCRECONFIG, pcre-config)

  if test x"$PCRECONFIG" != x; then
    PCRE_LIB=`$PCRECONFIG --libs`
    CPPFLAGS="$CPPFLAGS `$PCRECONFIG --cflags`"
    AC_DEFINE([HAVE_LIBPCRE], [1], [libpcre])
    AC_DEFINE([HAVE_PCRE_H], [1], [pcre.h])
  else
     AC_MSG_ERROR([pcre-config not found, install the pcre-devel package or build with --without-pcre])
  fi
fi

AC_SUBST(PCRE_LIB)
    AC_MSG_CHECKING(for PCRE JIT support)
    AC_TRY_COMPILE([ #include <pcre.h> ],
        [
        int jit = 0;
        pcre_config(PCRE_CONFIG_JIT, &jit);
        ],
        [ pcre_jit_available=yes ], [ pcre_jit_available=no ]
        )

    if test "x$pcre_jit_available" = "xyes"; then
       AC_MSG_RESULT(yes)
       AC_DEFINE([PCRE_HAVE_JIT], [1], [Pcre with JIT compiler support enabled])

       AC_MSG_CHECKING(for PCRE JIT support usability)
       AC_TRY_COMPILE([ #include <pcre.h> ],
           [
           const char* regexstr = "(a|b|c|d)";
           pcre *re;
           const char *error;
           pcre_extra *extra;
           int err_offset;
           re = pcre_compile(regexstr,0, &error, &err_offset,NULL);
           extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
           if (extra == NULL)
               exit(EXIT_FAILURE);
           int jit = 0;
           int ret = pcre_fullinfo(re, extra, PCRE_INFO_JIT, &jit);
           if (ret != 0 || jit != 1)
               exit(EXIT_FAILURE);
           exit(EXIT_SUCCESS);
           ],
           [ pcre_jit_works=yes ], [:]
       )
       if test "x$pcre_jit_works" != "xyes"; then
           AC_MSG_RESULT(no)
           echo
           echo "   PCRE JIT support detection worked but testing it failed"
           echo "   something odd is going on, please file a bug report."
           echo
           exit 1
       else
           AC_MSG_RESULT(yes)
       fi
    fi

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
    AM_CXXFLAGS="-O0 $AM_CXXFLAGS -g -Wall -Werror -Wno-uninitialized "
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    AM_CXXFLAGS="-O3 $AM_CXXFLAGS "
fi


##########################################################################
# database adaptor support
##########################################################################

AC_MSG_CHECKING([whether to build database adaptors on python])
AC_ARG_ENABLE([adaptor],
    [AS_HELP_STRING([--enable-adaptor],
        [enable python database adaptor support (def=no)])],
    [adaptor_support=yes],
    [adaptor_support=no])
AC_MSG_RESULT([$adaptor_support])

if test x"$adaptor_support" = x"yes"; then
    AC_DEFINE([HAVE_ADAPTOR],[1],[Database adaptor python support])
else
    AC_DEFINE([HAVE_ADAPTOR],[0],[No database adaptor python support])
fi

##########################################################################
# bloom filter support
##########################################################################

AC_MSG_CHECKING([whether to build bloom filters])
AC_ARG_ENABLE([bloomfilter],
    [AS_HELP_STRING([--enable-bloomfilter],
        [enable bloom filter support (def=no)])],
    [bloom_support=yes],
    [bloom_support=no])
AC_MSG_RESULT([$bloom_support])

if test x"$bloom_support" = x"yes"; then
    AC_CHECK_HEADER([boost/bloom_filter/basic_bloom_filter.hpp])
#    AC_CHECK_LIB([bf],[main],,have_bloom=no)
	AC_DEFINE([HAVE_BLOOMFILTER],[1],[Bloom filter support])
#else
#    	AC_DEFINE([HAVE_BLOOMFILTER],[0],[No bloom filter support])
fi

##########################################################################
# Flow serialization compression support
##########################################################################

AC_MSG_CHECKING([whether to build flow serialization compression support])
AC_ARG_ENABLE([fscompress],
    [AS_HELP_STRING([--enable-fscompress],
        [enable flow serialization compression support (def=no)])],
    [fscompress_support=yes],
    [fscompress_support=no])
AC_MSG_RESULT([$fscompress_support])

if test x"$fscompress_support" = x"yes"; then
    AC_DEFINE([HAVE_FLOW_SERIALIZATION_COMPRESSION],[1],[Flow serialization compression support])
#else
#    AC_DEFINE([HAVE_FLOW_SERIALIZATION_COMPRESSION],[0],[Flow serialization compression support])
fi

##########################################################################

CXXFLAGS=$AM_CXXFLAGS

##########################################################################

AC_CONFIG_FILES([
Makefile
test/Makefile
man/Makefile
utils/Makefile
examples/Makefile
pcapfiles/Makefile
src/Makefile
src/ethernet/Makefile
src/vlan/Makefile
src/mpls/Makefile
src/ip/Makefile
src/ip6/Makefile
src/ipset/Makefile
src/gprs/Makefile
src/vxlan/Makefile
src/gre/Makefile
src/icmp/Makefile
src/icmp6/Makefile
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
  Host................: $host 
  Prefix..............: $prefix
  Debug Build.........: $debugit
  C++ version.........: $cxx_version 
  C++ compiler........: $CXX $AM_CXXFLAGS $CPPFLAGS 
  C++11 support.......: $ac_cv_cxx_compile_cxx11_cxx
  Linker..............: $LD $LDFLAGS $LIBS
  Boost include.......: $BOOST_CPPFLAGS/boost
  Boost...............: $boost_lib_version_req
  Boost unit tests....: $unittestsit
  Boost python lib....: $BOOST_PYTHON_LIB
  Python..............: $PYTHON_VERSION $ax_python_bin 
  Python include path.: $python_path
  Log4cxx.............: $ac_cv_lib_log4cxx_main
  Libpcap.............: $ac_cv_lib_pcap_main
  Pcre................: $WITH_PCRE
  Pcre JIT............: $pcre_jit_works
  Database support....: $adaptor_support
  Bloom filter support: $bloom_support
  Flow sc support.....: $fscompress_support
"

