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
	ifaceName := "eth0"

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

		previousStats := make(map[string]uint64)

		for range ticker.C {

			seenIPs := make(map[string]bool)
			var key [4]byte
			var cpuValues []uint64

			iterator := objs.IcmpStats.Iterate()

			for iterator.Next(&key, &cpuValues) {
				var currentTotal uint64 = 0

				for _, val := range cpuValues {
					currentTotal += val
				}

				ip := net.IPv4(key[0], key[1], key[2], key[3]).String()
				prevTotal := previousStats[ip]
				delta := currentTotal - prevTotal

				if delta > 0 {
					fmt.Printf("XDP drop: %d ping block from ip %s (Total ping block: %d)\n", delta, ip, currentTotal)
					previousStats[ip] = currentTotal
				}
				seenIPs[ip] = true
			}
			if err := iterator.Err(); err != nil {
				log.Printf("Erreur lors de la lecture de la map: %v\n", err)
			}

			for ip := range previousStats {
				if !seenIPs[ip] {
					delete(previousStats, ip)
				}
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit

	fmt.Println("\n Signal received. Stopping firewall and cleaning up kernel...")
}
