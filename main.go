package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang Qdisc bpf/qdisc_full.c -- -I../ -Ibpf/

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	objs := QdiscObjects{}
	if err := LoadQdiscObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tpDequeue, err := link.Kprobe("sch_direct_xmit", objs.KprobeSchDirectXmit, nil)
	if err != nil {
		log.Fatal(err)
	}

	defer tpDequeue.Close()
	// tpDequeue, err := link.Tracepoint("qdisc", "qdisc_dequeue", objs.QdiscDequeue, nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer tpDequeue.Close()

	// Do something with the attached program
	fmt.Println("Attached program, waiting for Ctrl+C...")
	go func() {
		<-stopper

		fmt.Println("Detaching program")
	}()
	select {
	case <-stopper:
		fmt.Println("Detaching program")
	}

}
