package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I../../bpf/headers" gpuActivity ../../bpf/gpu_activity.bpf.c
