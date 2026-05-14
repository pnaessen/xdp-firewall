package main

import (
	"flag"
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
	ifaceName := flag.String("iface", "eth0", "Network interface to attach XDP program")
	flag.Parse()

	// Load compiled eBPF bytecode into kernel memory
	var objs bpf.BpfObjects
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", *ifaceName, err)
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

	fmt.Printf("XDP firewall active on %s. Aggregation mode.\n", *ifaceName)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go monitorStats(quit, ticker, &objs)

	<-quit
	fmt.Println("\nSignal received. Stopping firewall and cleaning up kernel...")
}

func monitorStats(quit <-chan os.Signal, ticker *time.Ticker, objs *bpf.BpfObjects) {
	previousStats := make(map[string]uint64)

	for {
		select {
		case <-ticker.C:
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
					fmt.Printf("XDP drop: %d ping block from ip %s (Total: %d)\n", delta, ip, currentTotal)
					previousStats[ip] = currentTotal
				}
				seenIPs[ip] = true
			}
			if err := iterator.Err(); err != nil {
				log.Printf("Error reading eBPF map: %v\n", err)
			}

			for ip := range previousStats {
				if !seenIPs[ip] {
					delete(previousStats, ip)
				}
			}

		case <-quit:
			return
		}
	}
}
