BPF_CLANG = clang
BPF_STRIP = llvm-strip
CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

all: dist/ebpf.bpf.o

dist/ebpf.bpf.o: src/ebpf.c include/vmlinux.h include/common.h
	mkdir -p dist
	$(BPF_CLANG) $(CFLAGS) -Iinclude -c $< -o $@
	$(BPF_STRIP) -g $@

clean:
	rm -rf dist
