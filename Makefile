NETWORK_DEVICE=lo

KERNEL_SOURCES=kern.c
USER_SOURCES=user.c
CALCULATE_SOURCES=calculate.c
KERN_OUT=build/kern.o
CC=clang

all:
	$(CC) -O3 -g -Wall -target bpf -c $(KERNEL_SOURCES) -o $(KERN_OUT) 
	$(CC) -O2 -g -Wall $(USER_SOURCES) -lbpf -lxdp -o build/user
	$(CC) -O2 -g -Wall $(CALCULATE_SOURCES) -o build/calc

load:
	-sudo xdp-loader unload -a $(NETWORK_DEVICE)
	sudo ./build/user
