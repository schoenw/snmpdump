# New ports collection makefile for:   snmpdump
# Date created:                18 February 2006
# Whom:                        Matus Harvan <m.harvan@iu-bremen.de>
# 
# not working yet !!!
#
# $FreeBSD$

PORTNAME=      snmpdump
PORTVERSION=   0.1
CATEGORIES=    net-mgmt
MASTER_SITES= 
MASTER_SITE_SUBDIR=

MAINTAINER=    m.harvan@iu-bremen.de
COMMENT=       convert pcap SNMP traces into xml format, aonymize and analyze them

#DISTNAME=	snmpdump
FETCH_DEPENDS= svn:${PORTSDIR}/devel/subversion

do-fetch:
		mkdir -p work/snmpdump
		svn co https://svn.eecs.iu-bremen.de/svn/schoenw/src/snmpdump/trunk work/snmpdump

#EXTRACT_DEPENDS= svn:${PORTSDIR}/devel/subversion
NO_EXTRACT=	yes
RUN_DEPENDS=   
# we need to find a suitable check for libnids
#DEPENDS=	lib/libnids.a:${PORTSDIR}/net/libnids 
LIB_DEPENDS=   smi:${PORTSDIR}/net-mgmt/libsmi \
	xml2:${PORTSDIR}/textproc/libxml2
#	nids:${PORTSDIR}/net/libnids 

DISTFILES=
#FETCH_CMD=	svn co snmpdump

#[If it extracts to a directory other than ${DISTNAME}...]
WRKSRC=                ${WRKDIR}/snmpdump

USE_AUTOTOOLS=	libtool:15 autoconf:259 aclocal:19 
ACLOCAL_ARGS=	-I /usr/local/share/aclocal
# we need to pass these flags to ./configure
#GNU_CONFIGURE= yes
#CONFIGURE_ENV+= --enable-shared --with-libnids=/usr/local/
#CONFIGURE_ARGS+= --enable-shared --with-libnids=/usr/local/

#USE_GMAKE=     yes

NO_INSTALL=	yes

.include <bsd.port.mk>
