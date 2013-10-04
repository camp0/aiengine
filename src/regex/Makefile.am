AUTOMAKE_OPTIONS = gnu

TEST = test_regex

check_PROGRAMS = test_regex

test_regex_SOURCES =		Regex.cc RegexManager.cc \
				test_regex.cc

test_regex_CPPFLAGS = -DSTAND_ALONE
test_regex_LDADD   = -lboost_unit_test_framework -lboost_regex

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

