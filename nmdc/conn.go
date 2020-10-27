package nmdc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync/atomic"

	"golang.org/x/text/encoding"

	"github.com/direct-connect/go-dc/keyprint"
	"github.com/direct-connect/go-dc/keyprint/tlskp"
	"github.com/direct-connect/go-dc/lineproto"
	"github.com/direct-connect/go-dc/nmdc"
)

var (
	Debug bool

	DefaultFallbackEncoding encoding.Encoding
)

const writeBuffer = 0

var dialer = net.Dialer{}

// Dial connects to a specified address.
func Dial(addr string, opts ...DialOption) (*Conn, error) {
	return DialContext(context.Background(), addr, opts...)
}

type dialConfig struct {
	ExpectKPs []string
	ConnOpts  []nmdc.ConnOption
}

type DialOption interface {
	apply(c *dialConfig)
}
type dialOptionFunc func(c *dialConfig)

func (f dialOptionFunc) apply(c *dialConfig) {
	f(c)
}

func WithExpectedKPs(kps ...string) DialOption {
	return dialOptionFunc(func(c *dialConfig) {
		c.ExpectKPs = append(c.ExpectKPs, kps...)
	})
}

func WithConnOpts(opts ...nmdc.ConnOption) DialOption {
	return dialOptionFunc(func(c *dialConfig) {
		c.ConnOpts = append(c.ConnOpts, opts...)
	})
}

// DialContext connects to a specified address.
func DialContext(ctx context.Context, addr string, opts ...DialOption) (*Conn, error) {
	var conf dialConfig
	for _, opt := range opts {
		opt.apply(&conf)
	}
	u, err := nmdc.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	secure := false
	switch u.Scheme {
	case nmdc.SchemeNMDC:
		// continue
	case nmdc.SchemeNMDCS:
		secure = true
	default:
		return nil, fmt.Errorf("unsupported protocol: %q", u.Scheme)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		var err2 error
		host, port, err2 = net.SplitHostPort(u.Host + ":" + strconv.Itoa(nmdc.DefaultPort))
		if err2 != nil {
			return nil, err
		}
	}
	u.Host = net.JoinHostPort(host, port)

	conn, err := dialer.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	var kps []string
	if secure {
		sconn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err = sconn.Handshake(); err != nil {
			_ = sconn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %v", err)
		}
		conn = sconn
		// verify keyprint if it's set in the URL
		if exp := keyprint.FromURL(u); exp != "" {
			conf.ExpectKPs = append(conf.ExpectKPs, exp)
		}
		if len(conf.ExpectKPs) != 0 {
			var last error
			for _, exp := range conf.ExpectKPs {
				if kps, err = tlskp.VerifyKeyPrint(sconn, exp); err != nil {
					last = err
				} else {
					last = nil
					break
				}
			}
			if last != nil {
				_ = sconn.Close()
				return nil, last
			}
		} else {
			kps = tlskp.GetKeyPrints(sconn)
		}
	}
	c := NewConn(conn)
	c.kps = kps
	return c, nil
}

var nmdcLineOpts = []lineproto.ConnOption{
	lineproto.WithWriteBuffer(writeBuffer),
}

var nmdcConnID uint64

// NewConn runs an NMDC protocol over a specified connection.
func NewConn(conn net.Conn, opts ...nmdc.ConnOption) *Conn {
	nopt := []nmdc.ConnOption{
		nmdc.WithLineOpts(nmdcLineOpts...),
	}
	if DefaultFallbackEncoding != nil {
		nopt = append(nopt, nmdc.WithTextEncoding(DefaultFallbackEncoding))
	}
	nopt = append(nopt, opts...)
	c := nmdc.NewConn(conn, nopt...)
	if Debug {
		id := atomic.AddUint64(&nmdcConnID, 1)
		c.OnLineR(func(line []byte) (bool, error) {
			log.Printf("-> (%d) %q", id, string(line))
			return true, nil
		})
		c.OnLineW(func(line []byte) (bool, error) {
			log.Printf("(%d) <- %q", id, string(line))
			return true, nil
		})
	}
	return &Conn{Conn: c}
}

// Conn is a NMDC protocol connection.
type Conn struct {
	*nmdc.Conn
	kps []string // keyprints, set by TLS
}

// GetKeyPrints returns keyprints set by TLS, if any.
func (c *Conn) GetKeyPrints() []string {
	return c.kps
}
