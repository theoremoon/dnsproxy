package resolver

import (
	"context"
	"log"
	"net"

	"github.com/miekg/dns"
)

type Resolver interface {
	Handler(domain string, rr dns.RR)
	Serve(ctx context.Context, addr string) error
}

type resolver struct {
	mux *dns.ServeMux
}

func New() Resolver {
	mux := dns.NewServeMux()

	// fallback to default DNS Resolver
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		c := &dns.Client{
			Net: "tcp-tls",
		}

		m, _, err := c.Exchange(r, net.JoinHostPort("1.1.1.1", "853"))
		if err != nil {
			log.Printf("%+v\n", err)
			return
		}
		w.WriteMsg(m)
	})

	return &resolver{
		mux: mux,
	}
}

func (r *resolver) Handler(domain string, rr dns.RR) {
	r.mux.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Compress = false

		// 割とめちゃくちゃをやっていて、どんなクエリにも決まったレコードを返している
		// 本来はクエリのタイプで分岐したりする
		m.Answer = append(m.Answer, rr)

		w.WriteMsg(m)
	})
}

func (r *resolver) Serve(ctx context.Context, addr string) error {
	tcpDNS := &dns.Server{Addr: addr, Net: "tcp", Handler: r.mux}
	udpDNS := &dns.Server{Addr: addr, Net: "udp", Handler: r.mux}

	errChan := make(chan error)
	go func() {
		err := tcpDNS.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()
	go func() {
		err := udpDNS.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		err1 := tcpDNS.Shutdown()
		if err1 != nil {
			log.Printf("%+v\n", err1)
		}

		err2 := udpDNS.Shutdown()
		if err2 != nil {
			log.Printf("%+v\n", err2)
		}
		return nil
	case err := <-errChan:
		return err
	}
}
