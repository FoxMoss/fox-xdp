NETWORK_DEVICE=wlan0

KERNEL_SOURCES=kern.c
USER_SOURCES=user.c
KERN_OUT=build/kern.o
CC=clang

all:
	$(CC) -O2 -g -Wall -target bpf -c $(KERNEL_SOURCES) -o $(KERN_OUT)
	$(CC) -O2 -g -Wall $(USER_SOURCES) -lbpf -lxdp -o build/user

load:
	-sudo xdp-loader unload -a wlan0
	sudo ./build/user
