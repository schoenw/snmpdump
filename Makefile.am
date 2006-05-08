#
# Makefile.am --
#
#      Template to generate the toplevel Makefile.in using automake.
#
# Copyright (c) 2004 Juergen Schoenwaelder, International University Bremen.
#
# See the file "COPYING" for information on usage and redistribution
# of this file, and for a DISCLAIMER OF ALL WARRANTIES.
#
# @(#) $Id$
#

AUTOMAKE_OPTIONS        = no-dependencies foreign

EXTRA_DIST		= libanon.pc

SUBDIRS			= libanon src scripts doc test

pkgconfigdir		= $(libdir)/pkgconfig
pkgconfig_DATA		= libanon.pc
$(pkgconfig_DATA):	config.status
