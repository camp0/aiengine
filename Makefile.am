AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = 	src \
		test \
		man \
		utils \
		examples \
		pcapfiles \
		src/ethernet \
		src/vlan \
		src/mpls \
		src/ip \
		src/ip6 \
		src/ipset \
		src/gprs \
		src/vxlan \
		src/icmp \
		src/udp \
		src/tcp \
		src/http \
		src/ssl \
		src/dns \
		src/flow \
		src/tcpgeneric \
		src/udpgeneric \
		src/regex \
		src/user \
		src/frequency \
		src/learner \
		src/names 

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = README AUTHORS NEWS INSTALL README.md

MAINTAINERCLEANFILES = config.h.in Makefile.in configure stamp-h1 config.log py-compile \
        ltmain.sh missing install-sh depcomp config.sub config.guess aclocal.m4 config.h.in~

