package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpconn ./ebpf/tcp-connecting.c -- -D__TARGET_ARCH_x86 -Iebpf/headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang fentryFexit ./ebpf/fentry_fexit.c -- -D__TARGET_ARCH_x86 -Iebpf/headers -Wall

func main() {
	var noTrace bool
	flag.BoolVar(&noTrace, "no-trace", false, "disable bpf-tailcall-trace")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var obj tcpconnObjects
	if err := loadTcpconnObjects(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}
	defer obj.Close()

	// prepare programs for bpf_tail_call()
	prog := obj.tcpconnPrograms.HandleNewConnection
	for key := uint32(0); key < obj.Progs.MaxEntries(); key++ {
		key := key
		if err := obj.Progs.Update(key, prog, ebpf.UpdateAny); err != nil {
			log.Printf("Failed to prepare tailcall(handle_new_connection): %v", err)
			return
		}
		defer func() {
			if err := obj.Progs.Delete(key); err != nil {
				log.Printf("Failed to delete tailcall(handle_new_connection): %v", err)
			}
		}()
	}

	mapInfo, err := obj.Progs.Info()
	if err != nil {
		log.Printf("Failed to get map info: %v", err)
		return
	}
	mapID, ok := mapInfo.ID()
	if !ok {
		log.Printf("Failed to get map id")
		return
	}

	spec, err := loadFentryFexit()
	if err != nil {
		log.Printf("Failed to load bpf obj: %v", err)
		return
	}

	var ffObj fentryFexitObjects
	if err := spec.LoadAndAssign(&ffObj, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"socks":  obj.Socks,
			"events": obj.Events,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}
	defer ffObj.Close()

	if !noTrace {
		progInfo, err := ffObj.FentryTailcall.Info()
		if err != nil {
			log.Printf("Failed to get prog info: %v", err)
			return
		}

		progID, ok := progInfo.ID()
		if !ok {
			log.Printf("Failed to get prog id")
			return
		}

		if out, err := exec.Command("insmod",
			"./kernel/bpf-tailcall-trace.ko",
			fmt.Sprintf("bpf_prog_id=%d", progID),
			fmt.Sprintf("bpf_map_id=%d", mapID),
		).CombinedOutput(); err != nil {
			log.Printf("Failed to load bpf-tailcall-trace.ko: %v\n%s", err, out)
			return
		}
		defer func() {
			if out, err := exec.Command("rmmod", "bpf-tailcall-trace").CombinedOutput(); err != nil {
				log.Printf("Failed to unload bpf-tailcall-trace.ko: %v\n%s", err, out)
			}
		}()
	}

	if kp, err := link.Kprobe("tcp_connect", obj.K_tcpConnect, nil); err != nil {
		log.Printf("Failed to attach kprobe(tcp_connect): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(tcp_connect)")
	}

	if kp, err := link.Kprobe("inet_csk_complete_hashdance", obj.K_icskCompleteHashdance, nil); err != nil {
		log.Printf("Failed to attach kprobe(inet_csk_complete_hashdance): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(inet_csk_complete_hashdance)")
	}

	go handlePerfEvent(ctx, obj.Events)

	<-ctx.Done()
}

func handlePerfEvent(ctx context.Context, events *ebpf.Map) {
	eventReader, err := perf.NewReader(events, 4096)
	if err != nil {
		log.Printf("Failed to create perf-event reader: %v", err)
		return
	}

	log.Printf("Listening events...")

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev struct {
		Saddr, Daddr [4]byte
		Sport, Dport uint16
		ProbeType    uint8
		Retval       uint8
		Pad          uint16
	}
	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			log.Printf("Reading perf-event: %v", err)
		}

		if event.LostSamples != 0 {
			log.Printf("Lost %d events", event.LostSamples)
		}

		binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev)

		switch ev.ProbeType {
		case 0:
			log.Printf("new tcp connection: %s:%d -> %s:%d (kprobe)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport)
		case 1:
			log.Printf("new tcp connection: %s:%d -> %s:%d (fentry on index: %d)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport, ev.Retval)
		case 2:
			log.Printf("new tcp connection: %s:%d -> %s:%d (fexit on index: %d)",
				netip.AddrFrom4(ev.Saddr), ev.Sport,
				netip.AddrFrom4(ev.Daddr), ev.Dport, ev.Retval)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
