obj-m += januscape-livepatch.o
KDIR = /lib/modules/$(shell uname -r)/build
ccflags-y += -I./arch/x86/kvm
ccflags-y += -I./arch/x86/kvm/mmu
all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean
