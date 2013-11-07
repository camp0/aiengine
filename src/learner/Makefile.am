AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_learner.h

TEST = test_learner

check_PROGRAMS = test_learner

test_learner_SOURCES = 	LearnerEngine.cc \
			test_learner.cc

test_learner_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_learner_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

