# ARP/NDP Logging OPNsense plugin
#
# Standalone build using OPNsense's official plugin build framework,
# vendored in Mk/, Scripts/ and Templates/ (from github.com/opnsense/plugins,
# BSD-2-Clause, Copyright (c) Franco Fichtner). Unlike a plugin living inside
# the official opnsense/plugins monorepo (category/name/), this Makefile
# lives at the repo root together with src/, so PLUGINSDIR is pointed here
# explicitly instead of relying on the "two directories up" default.
#
# Usage (run on a FreeBSD/OPNsense host with the pkg tools available):
#   make package                          Build ./work/pkg/*.pkg
#   make PLUGIN_VERSION=1.2.3 package     Build a specific version
#   make clean                            Reset src/ and remove work/

PLUGINSDIR=		${.CURDIR}

PLUGIN_NAME=		arp-ndp-logging
PLUGIN_VERSION?=	0.0.4
PLUGIN_COMMENT=		ARP/NDP change logging (arpwatch alternative)
PLUGIN_MAINTAINER=	github.com/mr-manuel
PLUGIN_WWW=		https://github.com/mr-manuel/opnsense_arp-ndp-logging
PLUGIN_LICENSE=		BSD2CLAUSE

# Plugin ships only PHP/Python/shell, no compiled binaries, so it isn't tied
# to the FreeBSD ABI of whichever release built it (e.g. the CI VM's 14.2
# vs. a firewall running a FreeBSD 15-based OPNsense) -- tag it ABI-agnostic
# so it installs across FreeBSD majors instead of pkg rejecting it as a
# mismatch.
PLUGIN_NO_ABI=		yes

.include "Mk/plugins.mk"
