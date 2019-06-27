# Author: Dimitrios Skarlatos
# Contact: skarlat2@illinois.edu - http://skarlat2.web.engr.illinois.edu/
# MicroScope Kernel Module Makefile

obj-m += microscope_mod.o
nuke-objs := microscope_mod.o util.o
CFLAGS_nuke.o := -O0
CFLAGS_nuke_mod.o := -O0

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Some tutorials use M= instead of SUBDIRS= You may need to be root to
# compile the module. You must be root to insert it.
default:
	$(MAKE) V=1 -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
