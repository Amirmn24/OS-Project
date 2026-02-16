# Makefile for SCX FIFO Project

CLANG ?= clang
BPFTOOL ?= /usr/lib/linux-tools/6.8.0-90-generic/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# File names
APP = scx_fifo
BPF_OBJ = ${APP}.bpf.o
USER_APP = ${APP}

SCX_REPO = ./scx
INCLUDES = -I. -I$(SCX_REPO)/scheds/include

# Compiler flags
CFLAGS = -g -O2 -Wall
LDFLAGS = -lbpf -lelf

all: $(USER_APP)

# 1. Generate vmlinux.h (Only if it doesn't exist)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile BPF code to Object file (Added INCLUDES)
$(BPF_OBJ): $(APP).bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(APP).bpf.c -o $(BPF_OBJ)

# 3. Generate BPF Skeleton
$(APP).bpf.skel.h: $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(APP).bpf.skel.h

# 4. Compile User-space Loader (Added INCLUDES)
$(USER_APP): main.c $(APP).bpf.skel.h
	$(CC) $(CFLAGS) $(INCLUDES) main.c -o $(USER_APP) $(LDFLAGS)

clean:
	rm -f $(USER_APP) $(BPF_OBJ) $(APP).bpf.skel.h *.o
