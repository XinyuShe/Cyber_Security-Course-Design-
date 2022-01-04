#KERN_DIR = /usr/src/$(shell uname -r)
KERN_DIR = /lib/modules/$(shell uname -r)/build
myfw-objs := my_firewall.o hashmap.o
obj-m += myfw.o

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   
clean:                                  
	rm -r *.order
	rm -f *.symvers
	rm -f *.o
	rm -f *.ko
	rm -f *.mod.c
