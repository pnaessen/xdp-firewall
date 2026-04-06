package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/pnaessen/xdp-firewall/bpf"
)

func main() {
	ifaceName := "enp0s3"

	var objs bpf.BpfObjects
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropIcmp,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf(" XDP firewall active on %s. Ready to block.\n", ifaceName)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open Ring Buffer: %v", err)
	}
	defer rd.Close()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				break
			}

			if len(record.RawSample) >= 4 {
				ip := net.IPv4(
					record.RawSample[0],
					record.RawSample[1],
					record.RawSample[2],
					record.RawSample[3],
				)
				fmt.Printf(" XDP DROP: Ping packet blocked from IP %s\n", ip.String())
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit

	fmt.Println("\n Signal received. Stopping firewall and cleaning up kernel...")
}
