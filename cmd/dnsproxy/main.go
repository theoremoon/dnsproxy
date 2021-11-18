package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/theoremoon/dnsproxy/internal/redirector"
	"github.com/theoremoon/dnsproxy/internal/resolver"
	"golang.org/x/xerrors"
)

func getPort() uint16 {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func run() error {
	resolv := resolver.New()
	port := getPort()
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-h" {
			fmt.Printf("%s [-h] [-p port] <hostname=A|CNAME>...\n", os.Args[0])
			return nil
		}

		if os.Args[i] == "-p" {
			p, err := strconv.ParseUint(os.Args[i+1], 10, 16)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			port = uint16(p)
			i++
			continue
		}

		// hostname=valueを分割してhandlerに登録
		parts := strings.SplitN(os.Args[i], "=", 2)
		hostname, record := parts[0], parts[1]
		var rrstr string
		if net.ParseIP(record) == nil {
			rrstr = fmt.Sprintf("%s CNAME %s", hostname, record)
		} else {
			rrstr = fmt.Sprintf("%s A %s", hostname, record)
		}
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		resolv.Handler(hostname, rr)
	}

	// redirectorを動かす
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	r, err := redirector.New(addr)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	// DNS Serverを建てる
	rr, err := dns.NewRR("local. A 10.0.0.0")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	resolv.Handler("local", rr)

	// 片付け準備
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// run
	err = r.Start()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	resolv.Serve(ctx, addr)

	<-ctx.Done()
	log.Println("Remove nft chain...")
	if err := r.Close(); err != nil {
		log.Printf("%+v\n", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v\n", err)
	}
}
