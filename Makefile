.PHONY: all clean run

all: onexit_test_bpf.o onexit_test_bpf.skel.h onexit_test_user

clean:
        rm -f *.o *.skel.h onexit_test_user

run: all
        sudo bash -c "ulimit -l unlimited && exec ./onexit_test_user"

vmlinux.h:
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

onexit_test_bpf.o: onexit_test_bpf.c vmlinux.h
        clang -target bpf -O2 -g -c $< -o $@ -I.

onexit_test_bpf.skel.h: onexit_test_bpf.o
        bpftool gen skeleton $< > $@

onexit_test_user: onexit_test_user.c onexit_test_bpf.o onexit_test_bpf.skel.h
        ../openwrt/staging_dir/toolchain-aarch64_cortex-a53_gcc-13.3.0_musl/bin/aarch64-openwrt-linux-gcc -Wall -g $< -o $@ -lbpf
