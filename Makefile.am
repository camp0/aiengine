AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = 	src \
		test \
		pcapfiles \
		src/ethernet \
		src/vlan \
		src/ip \
		src/ip6 \
		src/gprs \
		src/icmp \
		src/udp \
		src/tcp \
		src/flow 

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = README AUTHORS NEWS INSTALL

MAINTAINERCLEANFILES = config.h.in Makefile.in configure stamp-h1 config.log py-compile \
        ltmain.sh missing install-sh depcomp config.sub config.guess aclocal.m4 config.h.in~

