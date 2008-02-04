INCLUDES		= $(XML_CFLAGS) $(XML_CPPFLAGS) $(OPENSSL_CFLAGS)

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= anon
noinst_PROGRAMS		= pcap_anon anon_test_key

anon_SOURCES		= anon.c
anon_LDADD		= libanon.la $(OPENSSL_LIBS)

pcap_anon_SOURCES	= pcap_anon.c
pcap_anon_LDADD		= libanon.la $(OPENSSL_LIBS) -lpcap

anon_test_key_SOURCES		= anon_test_key.c
anon_test_key_LDADD		= libanon.la $(OPENSSL_LIBS)

man_MANS		= anon.1 anon-ip.3 anon-mac.3

include_HEADERS		= libanon.h
lib_LTLIBRARIES		= libanon.la
libanon_la_SOURCES	= anon-ip.c anon-ipv6.c anon-mac.c anon-int64.c anon-uint64.c anon-octs.c anon-key.c
libanon_la_LDFLAGS	= -version-info @VERSION_LIBTOOL@ $(OPENSSL_LIBS)
