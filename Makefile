NETWORK_DEVICE=lo

KERNEL_SOURCES=kern.c
USER_SOURCES=user.c
CALCULATE_SOURCES=calculate.c
CC=clang

all:
	$(CC) -O3 -g -Wall -target bpf -c $(KERNEL_SOURCES) -o build/fox.bpf
	$(CC) -O2 -g -Wall $(USER_SOURCES) -lbpf -lxdp -o build/fox-filter
	$(CC) -O2 -g -Wall $(CALCULATE_SOURCES) -o build/generate-config

release:
	$(CC) -O3 -g -Wall -target bpf -c $(KERNEL_SOURCES) -DRELEASE -o build/fox.bpf
	$(CC) --static -O2 -Wall $(USER_SOURCES) -lxdp -lbpf -lelf -lz -lzstd -o build/fox-filter
	$(CC) --static -O2 -Wall $(CALCULATE_SOURCES) -o build/generate-config
	-rm build/x86_64-linux-musl.zip
	cp -r signatures build
	cd build && zip -r x86_64-linux-musl.zip fox.bpf fox-filter generate-config signatures

