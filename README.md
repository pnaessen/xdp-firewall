# xdp-firewall

> A high-performance packet filter using eBPF/XDP in kernel space (C) and a Go user-space loader/monitor.

## Overview

This project implements an ultra-low-latency XDP firewall that drops ICMP packets before they reach the Linux network stack.

The eBPF program is attached at the XDP hook and keeps counters per source IP in a PERCPU map. The Go daemon loads the program, attaches it to a network interface, and periodically prints aggregated drop statistics.

## Architecture and Features

* **XDP packet filtering**: Drops ICMP packets (`XDP_DROP`) at driver level.
* **PERCPU counters**: Uses a `BPF_MAP_TYPE_PERCPU_HASH` map (`icmp_stats`) keyed by source IPv4 address.
* **Low-contention stats path**: Per-CPU counters reduce write contention inside the kernel.
* **Go integration with bpf2go**: Uses Cilium `bpf2go` to compile the eBPF program and generate typed Go bindings.
* **Periodic monitoring**: User space iterates over the map every second, sums per-CPU values, and prints delta + total drops per IP.
* **Graceful shutdown**: Handles `SIGINT` and `SIGTERM` and detaches the XDP program cleanly.

## Prerequisites

* Linux kernel with eBPF/XDP support
* `clang` and `llvm`
* `golang` (1.21+)
* `libbpf-dev` and Linux headers

## Build and Run

```bash
# 1) Generate eBPF objects and Go bindings
go generate ./...

# 2) Build user-space binary
go build -o xdp-firewall

# 3) Run (root required to attach XDP)
sudo ./xdp-firewall
```

## Runtime Behavior

* Every inbound ICMP packet is dropped.
* `icmp_stats` tracks drops per source IP.
* The Go daemon prints incremental and cumulative counts once per second.

## Configuration

* The target interface is currently hardcoded in `main.go` as `ifaceName := "enp0s3"`.
* Change it to match your host interface (for example `eth0`, `ens33`, `enp0s3`).
