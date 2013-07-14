AUTOMAKE_OPTIONS = gnu

TEST = test_signatures

check_PROGRAMS = test_signatures

test_signatures_SOURCES =	Signature.cc SignatureManager.cc \
				test_signatures.cc

test_signatures_LDADD   = -lboost_unit_test_framework -lboost_regex

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

