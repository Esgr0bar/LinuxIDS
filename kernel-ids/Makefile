obj-m += ids_module.o
ids_module-objs := ids_module.o buffer_overflow.o rootkit_detection.o unauthorized_access.o ebpf_programs.o pf_ring_module.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
