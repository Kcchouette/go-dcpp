package hubtest

import "net"

func newPipe(i int) (net.Conn, net.Conn) {
	hc, cc := net.Pipe()
	localhost := net.ParseIP("127.0.0.1")
	ha := &net.TCPAddr{
		IP:   localhost,
		Port: 411,
	}
	ca := &net.TCPAddr{
		IP:   localhost,
		Port: 1000 + i,
	}
	return addrOverride{
			Conn:   hc,
			local:  ha,
			remote: ca,
		}, addrOverride{
			Conn:   cc,
			local:  ca,
			remote: ha,
		}
}

type addrOverride struct {
	net.Conn
	local, remote net.Addr
}

func (c addrOverride) LocalAddr() net.Addr {
	return c.local
}

func (c addrOverride) RemoteAddr() net.Addr {
	return c.remote
}
