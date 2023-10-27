package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang Pfifo bpf/pfifo.c -- -I../ -Ibpf/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang Htb bpf/htb.c -- -I../ -Ibpf/

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	// pfifoObjs := PfifoObjects{}
	// if err := LoadPfifoObjects(&pfifoObjs, nil); err != nil {
	// 	log.Fatalf("loading objects: %v", err)
	// }
	// defer pfifoObjs.Close()

	// pfifoEnqueue, err := link.Kprobe("pfifo_enqueue", pfifoObjs.KprobePfifoEnqueue, nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// defer pfifoEnqueue.Close()

	htbObjs := HtbObjects{}
	if err := LoadHtbObjects(&htbObjs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer htbObjs.Close()

	htbEnqueue, err := link.Kprobe("htb_enqueue", htbObjs.KprobeHtbEnqueue, nil)
	if err != nil {
		log.Fatal(err)
	}

	defer htbEnqueue.Close()

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
