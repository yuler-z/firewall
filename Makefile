#KERN_DIR = /usr/src/kernels/2.6.18-53.el5-i686
#KERN_DIR = /usr/src/$(shell uname -r)
CONFIG_MODULE_SIG=n
KERN_DIR = /lib/modules/$(shell uname -r)/build
fw-objs := firewall.o #file2.o file3.o
obj-m += fw.o

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   
clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f *.symvers
