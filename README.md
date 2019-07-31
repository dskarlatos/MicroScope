# MicroScope
This repository contains the MicroScope framework used to perform microarchitectural replay attacks.

Please check our paper for details:


MicroScope: Enabling Microarchitectural Replay Attacks. Dimitrios Skarlatos, Mengjia Yan, Bhargava Gopireddy, Read Sprabery, Josep Torrellas, and Christopher W. Fletcher. Proceedings of the 46th Intl. Symposium on Computer Architecture (ISCA), Phoenix, USA, June 2019.

```
@inproceedings{Skarlatos:Microscope:ISCA19,
 author = {Skarlatos, Dimitrios and Yan, Mengjia and Gopireddy, Bhargava and Sprabery, Read and Torrellas, Josep and Fletcher, Christopher W.},
 title = {MicroScope: Enabling Microarchitectural Replay Attacks},
 booktitle = {Proceedings of the 46th International Symposium on Computer Architecture},
 series = {ISCA '19},
 year = {2019},
 location = {Phoenix, Arizona},
 pages = {318--331},
 numpages = {14},
 publisher = {ACM},
}
```

[You can find the MicroScope paper here!](http://skarlat2.web.engr.illinois.edu)

The current release includes the MicroScope kernel module that can be used to perform
microarchitectural replay attacks through page faults. The release includes the
utility functions for many different attack scenarios as well as a skeleton kernel module
with page fault replay capabilities.

## Details on Kernel Source:
A kernel patch against ubuntu-4.4.0-101.124 can be found under the kernel_patch directory.
For convenience [here you can find a precompiled kernel that already exposes some functions
to the MicroScope kernel module.](https://drive.google.com/open?id=1433kWpnafmffyDPmW_HZSZlbbOPlwKyU)
A pre-compiled kernel is in compiled_deb.zip that contains the .deb files.

## Kernel install steps:
1) sudo dpkg -i linux*.deb
2) reboot the machine and select the newly installed kernel
3) login
4) run uname -a which should return
5) Output should be: Linux USERNAME 4.4.0-101-generic #124+attack SMP Tue Mar 6 14:26:05 CST 2018 x86_64 x86_64 x86_64 GNU/Linux

## MicroScope usage steps:

Run only once:
1) change DEVICE_FILE_NAME_PATH in microscope_mod.h
2) sudo mknod nuke_channel c 1313 0 // this creates a char device

Build and Install:
1) make
2) install the module with insmod microscope_mod.ko
3) dmesg will print a welcome message from microscope
4) remove the module with rmmod microscope
