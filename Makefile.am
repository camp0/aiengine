AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = 	src \
		test \
		pcapfiles \
		src/ethernet \
		src/vlan \
		src/mpls \
		src/ip \
		src/ip6 \
		src/gprs \
		src/icmp \
		src/udp \
		src/tcp \
		src/http \
		src/ssl \
		src/dns \
		src/flow \
		src/tcpgeneric \
		src/udpgeneric \
		src/signatures \
		src/user \
		src/frequency  

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = README AUTHORS NEWS INSTALL

MAINTAINERCLEANFILES = config.h.in Makefile.in configure stamp-h1 config.log py-compile \
        ltmain.sh missing install-sh depcomp config.sub config.guess aclocal.m4 config.h.in~

