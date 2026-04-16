# xdp-firewall

> A high-performance network packet filter demonstrating Kernel Bypass capabilities using eBPF/XDP, written in C (Kernel Space) and Go (User Space).

## 📖 Overview

This project implements an ultra-low latency network firewall. By attaching an **eBPF (extended Berkeley Packet Filter)** program directly to the **XDP (eXpress Data Path)** hook in the network interface card (NIC) driver, it drops malicious packets (currently filtering ICMP/Ping) *before* the Linux kernel network stack even allocates an `sk_buff`.

This hybrid architecture leverages C for raw memory manipulation in the kernel and Go for asynchronous event monitoring in user space.

## 🏗️ Architecture & Features

* **Kernel Bypass (XDP)**: Intercepts raw Ethernet/IPv4 frames directly from DMA memory, achieving near-zero latency packet filtering.
* **Hybrid C/Go Toolchain**: Uses Cilium's `bpf2go` to compile the C kernel code via LLVM/Clang and automatically generate seamless Go bindings.
* **Lockless Communication**: Implements an eBPF `BPF_MAP_TYPE_RINGBUF` (Ring Buffer) for highly efficient, lockless event streaming (blocked IP addresses) from the kernel to the user space daemon.
* **Asynchronous Go Daemon**: A concurrent user-space application that loads the eBPF bytecode, manages the network interface attachment, and listens to the Ring Buffer via non-blocking Goroutines.
* **Graceful Shutdown**: Strict POSIX signal handling in Go (`SIGINT`, `SIGTERM`) to ensure safe memory cleanup and proper detachment of the eBPF program from the NIC.

## ⚙️ Prerequisites

To compile and run this project, your Linux environment needs the following toolchain:
* Linux Kernel 5.8+ (for Ring Buffer support)
* `clang` and `llvm` (to target the `bpf` virtual architecture)
* `golang` (1.21+)
* `libbpf-dev` and `linux-headers`

## 🚀 Build and Usage

```bash
# 1. Compile the C code (eBPF) and generate the Go stubs
go generate ./...

# 2. Compile the Go user-space daemon
go build -o xdp-firewall

# 3. Run the firewall (requires root privileges to attach to the network interface)
# Note: Ensure the target interface (e.g., eth0, enp0s3) is correctly set in main.go
sudo ./xdp-firewall
