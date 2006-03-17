INCLUDES		= $(XML_CFLAGS) $(XML_CPPFLAGS) $(OPENSSL_CFLAGS)

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= anon

anon_SOURCES		= anon.c
anon_LDADD		= libanon.la $(OPENSSL_LIBS)

man_MANS		= anon.1 anon-ip.3 anon-mac.3

include_HEADERS		= libanon.h
lib_LTLIBRARIES		= libanon.la
libanon_la_SOURCES	= anon-ip.c anon-ipv6.c anon-mac.c anon-int64.c anon-uint64.c anon-octet-string.c
libanon_la_LDFLAGS	= -version-info @VERSION_LIBTOOL@
