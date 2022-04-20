# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the XFRM subsystem.
#

obj-$(CONFIG_XFRM) := xfrm_policy.o xfrm_state.o xfrm_hash.o \
		      xfrm_input.o xfrm_output.o \
		      xfrm_sysctl.o xfrm_replay.o xfrm_device.o
obj-$(CONFIG_XFRM_STATISTICS) += xfrm_proc.o
obj-$(CONFIG_XFRM_ALGO) += xfrm_algo.o
obj-$(CONFIG_XFRM_USER) += xfrm_user.o
obj-$(CONFIG_XFRM_USER_COMPAT) += xfrm_compat.o
obj-$(CONFIG_XFRM_IPCOMP) += xfrm_ipcomp.o
obj-$(CONFIG_XFRM_INTERFACE) += xfrm_interface.o
obj-$(CONFIG_XFRM_ESPINTCP) += espintcp.o

CFLAGS_REMOVE_xfrm_algo.o = -g -O2
CFLAGS_xfrm_algo.o = -g3 -O1

CFLAGS_REMOVE_xfrm_device.o = -g -O2
CFLAGS_xfrm_device.o = -g3 -O1

CFLAGS_REMOVE_xfrm_interface.o = -g -O2
CFLAGS_xfrm_interface.o = -g3 -O1

CFLAGS_REMOVE_xfrm_input.o = -g -O2
CFLAGS_xfrm_input.o = -g3 -O1

CFLAGS_REMOVE_xfrm_iptfs.o = -g -O2
CFLAGS_xfrm_iptfs.o = -g3 -O1

CFLAGS_REMOVE_xfrm_output.o = -g -O2
CFLAGS_xfrm_output.o = -g3 -O1

CFLAGS_REMOVE_xfrm_policy.o = -g -O2
CFLAGS_xfrm_policy.o = -g3 -O1

CFLAGS_REMOVE_xfrm_state.o = -g -O2
CFLAGS_xfrm_state.o = -g3 -O1

CFLAGS_REMOVE_xfrm_user.o = -g -O2
CFLAGS_xfrm_user.o = -g3 -O1
