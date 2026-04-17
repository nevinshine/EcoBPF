package collector

// bpf2go generate directives for type-safe eBPF program loading.
// These directives invoke cilium/ebpf/cmd/bpf2go to auto-generate Go
// structs that mirror the C ring buffer event and map value types,
// guaranteeing correct memory layout alignment.
//
// Run with: go generate ./internal/collector/...

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I../../bpf/headers" cpuSched ../../bpf/cpu_sched.bpf.c
