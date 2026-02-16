# Makefile for SCX FIFO Project

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# File names
APP = scx_fifo
BPF_OBJ = ${APP}.bpf.o
USER_APP = ${APP}

# Compiler flags
CFLAGS = -g -O2 -Wall
LDFLAGS = -lbpf -lelf

all: $(USER_APP)

# 1. Generate vmlinux.h (Kernel types definitions)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile BPF code to Object file
$(BPF_OBJ): $(APP).bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $(APP).bpf.c -o $(BPF_OBJ)

# 3. Generate BPF Skeleton (Linker between C and BPF)
$(APP).bpf.skel.h: $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(APP).bpf.skel.h

# 4. Compile User-space Loader
$(USER_APP): main.c $(APP).bpf.skel.h
	$(CC) $(CFLAGS) main.c -o $(USER_APP) $(LDFLAGS)

clean:
	rm -f $(USER_APP) $(BPF_OBJ) $(APP).bpf.skel.h vmlinux.h *.o
