# januscape-livepatch

Use at your own risks.


Fixes bugs used on januscape public exploit poc in __link_shadow_page and kvm_mmu_get_child_sp. Writeup mentions only 81ccda30b4e8 as fixes, but it also use use-after-free path which was fixed on 0cb2af2ea66ad

__link_shadow_pages fixes bug on pte_list_remove and kvm_mmu_get_child_sp fixes gfn mismatch.

Tested on ubuntu kernel 6.2+

Requires linux-source-<your kernel version>

Requires linux-headers-$(uname -r)


Fixes the makefile with your source path for the current kernel, requires it because of include spte.h and mmu_internal.h

Load livepatch
```
make && insmod ./januscape-livepatch.ko
```
Remove livepatch:
```
echo 0 > /sys/kernel/livepatch/januscape_livepatch/enabled
```