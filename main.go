package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/pnaessen/xdp-firewall/bpf"
)

// XDP firewall entry point: orchestrates eBPF program lifecycle (load, attach, monitor, cleanup).
func main() {
	// Target network interface
	ifaceName := "enp0s3"

	// Load compiled eBPF bytecode into kernel memory
	var objs bpf.BpfObjects
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", ifaceName, err)
	}

	// Attach eBPF program to XDP hook
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropIcmp,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf(" XDP firewall active on %s. Aggregation mode.\n", ifaceName)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			var key [4]byte
			var cpuValues []uint64

			iterator := objs.IcmpStats.Iterate()

			for iterator.Next(&key, &cpuValues) {
				var totalPackets uint64 = 0
				for _, val := range cpuValues {
					totalPackets += val
				}

				ip := net.IPv4(key[0], key[1], key[2], key[3])

				if totalPackets > 0 {
					fmt.Printf(" Stats: %d pings blocked from IP %s\n", totalPackets, ip.String())
				}
			}

			if err := iterator.Err(); err != nil {
				log.Printf("Error iterating map: %v", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit

	fmt.Println("\n Signal received. Stopping firewall and cleaning up kernel...")
}
