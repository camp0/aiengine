AUTOMAKE_OPTIONS = gnu

TEST = test_regex

check_PROGRAMS = test_regex

noinst_HEADERS =	Regex.h RegexManager.h 

test_regex_SOURCES =		Regex.cc RegexManager.cc \
				test_regex.cc

test_regex_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_regex_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework -lboost_regex $(PCRE_LIB) 

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

