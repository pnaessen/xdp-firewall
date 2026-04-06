package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Bpf xdp_filter.c -- -I./headers -I/usr/include/x86_64-linux-gnu
