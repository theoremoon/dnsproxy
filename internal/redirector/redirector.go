/// DNS requestを特定のポートにリダイレクトするくん
package redirector

import (
	"net"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const (
	DNSPort   = 53
	ChainName = "dnsproxy"
)

type Redirector interface {
	Start() error
	Close() error
}

type redirector struct {
	RedirectToHost net.IP
	RedirectToPort uint16
}

func New(addr string) (Redirector, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &redirector{
		RedirectToHost: net.ParseIP(host).To4(),
		RedirectToPort: uint16(p),
	}, nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func (r *redirector) Start() error {
	c := &nftables.Conn{} // global namespaceを設定していく

	t := c.AddTable(&nftables.Table{
		Name:   "nat",
		Family: nftables.TableFamilyIPv4,
	})
	chain := c.AddChain(&nftables.Chain{
		Name:     ChainName,
		Table:    t,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: 0,
	})

	c.AddRule(&nftables.Rule{
		Table: t,
		Chain: chain,
		Exprs: []expr.Any{
			// L4のprotocol
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},

			// tcp
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// destination portを見る
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // tcp headerでdst portのoffsetは2
				Len:          2, // 長さは2
			},

			// destination portがDNSPortの値に等しいとき
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(DNSPort),
			},

			// リダイレクト先のホストの値を準備しておく
			&expr.Immediate{
				Register: 1,
				Data:     r.RedirectToHost,
			},

			// リダイレクト先のポートの値を準備しておく
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(r.RedirectToPort),
			},

			// DNATでリダイレクトする
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: t,
		Chain: chain,
		Exprs: []expr.Any{
			// L4のprotocol
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},

			// udp
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},

			// destination portを見る
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // udp headerでdst portのoffsetは2
				Len:          2, // 長さは2
			},

			// destination portがDNSPortの値に等しいとき
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(DNSPort),
			},

			// リダイレクト先のホストの値を準備しておく
			&expr.Immediate{
				Register: 1,
				Data:     r.RedirectToHost,
			},

			// リダイレクト先のポートの値を準備しておく
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(r.RedirectToPort),
			},

			// DNATでリダイレクトする
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	})

	// 反映
	if err := c.Flush(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (r *redirector) Close() error {
	c := &nftables.Conn{} // global namespaceを設定していく

	chain := &nftables.Chain{
		Name: ChainName,
	}
	chain.Table = &nftables.Table{
		Name:   "nat",
		Family: nftables.TableFamilyIPv4,
	}
	c.DelChain(chain)

	if err := c.Flush(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}
