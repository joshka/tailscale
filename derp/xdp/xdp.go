package main

import (
	"errors"
	"flag"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type config bpf xdp.c -- -I headers

var (
	flagDevice  = flag.String("device", "", "target device name")
	flagPort    = flag.Int("dport", 0, "destination UDP port to serve")
	flagVerbose = flag.Bool("verbose", false, "verbose output including verifier errors")
)

func main() {
	flag.Parse()
	if len(*flagDevice) < 1 {
		log.Fatal("device flag is unset")
	}
	if *flagPort < 1 || *flagPort > math.MaxUint16 {
		log.Fatal("dport flag is invalid")
	}
	iface, err := net.InterfaceByName(*flagDevice)
	if err != nil {
		log.Panic(err)
	}

	objs := bpfObjects{}
	err = loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 10,
		},
	})
	if err != nil {
		if *flagVerbose {
			ve := &ebpf.VerifierError{}
			if errors.As(err, &ve) {
				log.Panicf("%+v", ve)
			}
		}
		log.Panic(err)
	}
	defer objs.Close()

	var key uint32
	config := bpfConfig{
		DstPort: uint16(*flagPort),
	}
	err = objs.ConfigMap.Put(key, &config)
	if err != nil {
		log.Panic(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Panic(err)
	}
	defer l.Close()

	log.Println("XDP program loaded")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
