## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib \
	   @ISIS_TOPOLOGY_INCLUDES@ -I/usr/local/include/
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600
LIBS = @LIBS@ @ISIS_LIBS@ -L/usr/local/lib/


AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS)

noinst_LIBRARIES = libisis.a
sbin_PROGRAMS = @ISIS_TARGETS@ 
SUBDIRS = topology
EXTRA_PROGRAMS = isisd trilld

libisis_a_SOURCES = \
	isis_adjacency.c isis_lsp.c dict.c isis_circuit.c isis_pdu.c \
	isis_tlv.c isisd.c isis_misc.c isis_zebra.c isis_dr.c \
	isis_flags.c isis_dynhn.c iso_checksum.c isis_csm.c isis_events.c \
	isis_spf.c isis_route.c isis_routemap.c 


noinst_HEADERS = \
	isisd.h isis_pdu.h isis_tlv.h isis_adjacency.h isis_constants.h \
	isis_lsp.h dict.h isis_circuit.h isis_misc.h isis_network.h \
	isis_zebra.h isis_dr.h isis_flags.h isis_dynhn.h isis_common.h \
	iso_checksum.h isis_csm.h isis_events.h isis_spf.h isis_route.h \
	include-netbsd/clnp.h include-netbsd/esis.h include-netbsd/iso.h \
	bool.h netlink_socket.h isis_vlans.h isis_trill.h

isisd_SOURCES = \
	isis_main.c $(libisis_a_SOURCES) isis_trilldummy.c\
	isis_bpf.c isis_dlpi.c isis_pfpacket.c

isisd_LDADD = @ISIS_TOPOLOGY_LIB@ ../lib/libzebra.la @LIBCAP@ @LIBM@

trilld_SOURCES = \
	isis_main.c $(libisis_a_SOURCES) isis_trill.c isis_trillio.c \
	isis_trillvlans.c isis_trillbpdu.c netlink_socket.c

trilld_LDADD = @ISIS_TOPOLOGY_LIB@ ../lib/libzebra.la /usr/local/lib/libbridge.a \
			/usr/local/lib/libmnl.la @LIBCAP@ @LIBM@ 
			

examplesdir = $(exampledir)
dist_examples_DATA = isisd.conf.sample
