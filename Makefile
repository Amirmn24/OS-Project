APP=scx_fifo

all: $(APP)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# compile to bpf o
scx_fifo.bpf.o: scx_fifo.bpf.c vmlinux.h
	clang -g -O2 -target bpf -c scx_fifo.bpf.c -o scx_fifo.bpf.o

# generate header
scx_fifo.bpf.skel.h: scx_fifo.bpf.o
	bpftool gen skeleton scx_fifo.bpf.o > scx_fifo.bpf.skel.h

# compile and link
$(APP): main.c scx_fifo.bpf.skel.h
	gcc -g -O2 main.c -o $(APP) -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.h $(APP)
