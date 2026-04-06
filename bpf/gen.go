package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_filter.c -- -I./headers
